import { SEVERITY, type Finding, type Scanner, type ScanResult } from "../types";
import type { PluginConfig } from "./types";
import { commandExists, generateFindingId, runCommand } from "../utils";
import { parseSarif } from "./parsers/sarif";
import { logger } from "../logger";

/**
 * Generic CLI scanner that wraps any command-line security tool
 */
export class CliScanner implements Scanner {
  name: string;
  private config: PluginConfig;

  constructor(config: PluginConfig) {
    this.name = config.name;
    this.config = config;
  }

  async isAvailable(): Promise<boolean> {
    const cmd = this.config.checkCommand ?? this.config.command.split(" ")[0];

    if (!cmd) {
      throw new Error("Invalid command: empty string");
    }

    return commandExists(cmd);
  }

  async scan(target: string): Promise<ScanResult> {
    const start = Date.now();

    try {
      // Replace {{target}} placeholder in command and args
      const args = (this.config.args ?? []).map((arg) => arg.replace("{{target}}", target));

      // Add target to args if not already present via placeholder
      if (!this.config.args?.some((a) => a.includes("{{target}}"))) {
        args.push(target);
      }

      const result = await runCommand(this.config.command, args, {
        cwd: target,
        timeout: this.config.timeout ?? 300_000,
        env: this.config.env,
      });

      const findings = this.parseOutput(result.stdout, result.stderr, target);

      return {
        scanner: this.name,
        success: true,
        findings,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      return {
        scanner: this.name,
        success: false,
        findings: [],
        error: err instanceof Error ? err.message : String(err),
        durationMs: Date.now() - start,
      };
    }
  }

  private parseOutput(stdout: string, stderr: string, target: string): Finding[] {
    const output = stdout || stderr;
    if (!output.trim()) return [];

    switch (this.config.outputFormat) {
      case "sarif":
        return parseSarif(output, this.name, this.config.category);

      case "json":
        return this.parseJson(output, target);

      case "lines":
        return this.parseLines(output, target);

      default:
        return [];
    }
  }

  private parseJson(output: string, target: string): Finding[] {
    const parser = this.config.parser;
    if (!parser) {
      logger.warn(`No parser config for ${this.name}, returning empty findings`);
      return [];
    }

    try {
      const data = JSON.parse(output);
      const results = this.getNestedValue(data, parser.resultsPath);

      if (!Array.isArray(results)) {
        return [];
      }

      return results.map((item: Record<string, unknown>, idx: number) => {
        const severityField = parser.fieldMapping.severity;
        const severity = this.mapSeverity(
          String(this.getNestedValue(item, severityField) ?? "medium"),
          parser.severityMapping
        );

        const filePathField = parser.fieldMapping.filePath;
        const filePath = String(this.getNestedValue(item, filePathField) ?? target);
        const startLineField = parser.fieldMapping.startLine;
        const startLine = startLineField
          ? Number(this.getNestedValue(item, startLineField)) || undefined
          : undefined;
        const idField = parser.fieldMapping.id;
        const id = idField
          ? String(this.getNestedValue(item, idField) ?? `${this.name}-${idx}`)
          : `${this.name}-${idx}`;

        const titleField = parser.fieldMapping.title;
        const descField = parser.fieldMapping.description;
        const endLineField = parser.fieldMapping.endLine;
        const recField = parser.fieldMapping.recommendation;

        return {
          id: generateFindingId(this.name, filePath, startLine ?? 0, id),
          scanner: this.name,
          category: this.config.category,
          severity,
          title: String(this.getNestedValue(item, titleField) ?? "Unknown"),
          description: String(this.getNestedValue(item, descField) ?? ""),
          filePath,
          startLine,
          endLine: endLineField
            ? Number(this.getNestedValue(item, endLineField)) || undefined
            : undefined,
          cweId: parser.fieldMapping.cweId
            ? String(this.getNestedValue(item, parser.fieldMapping.cweId) ?? "")
            : undefined,
          cveId: parser.fieldMapping.cveId
            ? String(this.getNestedValue(item, parser.fieldMapping.cveId) ?? "")
            : undefined,
          recommendation: recField
            ? String(this.getNestedValue(item, recField) ?? "Review and fix this issue")
            : "Review and fix this issue",
          snippet: parser.fieldMapping.snippet
            ? String(this.getNestedValue(item, parser.fieldMapping.snippet) ?? "")
            : undefined,
        };
      });
    } catch (err) {
      logger.error(`Failed to parse JSON output from ${this.name}`, err);
      return [];
    }
  }

  private parseLines(output: string, _target: string): Finding[] {
    // Simple line-based parser for tools that output one finding per line
    // Format expected: severity:file:line:message
    const findings: Finding[] = [];
    const lines = output.split("\n").filter((l) => l.trim());

    for (const line of lines) {
      const match = line.match(/^(critical|high|medium|low|info):([^:]+):(\d+)?:(.+)$/i);
      if (match) {
        const [, severity = SEVERITY.MEDIUM, file = "", lineNum, message = ""] = match;
        findings.push({
          id: generateFindingId(this.name, file, Number(lineNum) || 0, message),
          scanner: this.name,
          category: this.config.category,
          severity: (severity.toLowerCase() as Finding["severity"]) || "medium",
          title: message.slice(0, 100),
          description: message,
          filePath: file,
          startLine: lineNum ? Number(lineNum) : undefined,
          recommendation: "Review and fix this issue",
        });
      }
    }

    return findings;
  }

  /**
   * Get nested value from object using dot notation
   * Supports array access like "items[0].value"
   */
  private getNestedValue(obj: unknown, path: string): unknown {
    if (!path) return undefined;

    const parts = path.split(/[.[\]]/).filter(Boolean);
    let current: unknown = obj;

    for (const part of parts) {
      if (current === null || current === undefined) return undefined;
      if (typeof current !== "object") return undefined;
      current = (current as Record<string, unknown>)[part];
    }

    return current;
  }

  private mapSeverity(
    value: string,
    mapping?: Record<string, Finding["severity"]>
  ): Finding["severity"] {
    if (mapping?.[value]) {
      return mapping[value];
    }

    // Default mapping
    const lower = value.toLowerCase();
    if (lower.includes("critical")) return "critical";
    if (lower.includes("high")) return "high";
    if (lower.includes("medium") || lower.includes("moderate")) return "medium";
    if (lower.includes("low")) return "low";
    return "info";
  }
}
