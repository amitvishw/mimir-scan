import type { Finding, Scanner, ScanResult, Severity } from "../types";
import { CATEGORY } from "../types";
import { commandExists, generateFindingId, runCommand } from "../utils";

interface SemgrepResult {
  results?: {
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message: string;
      severity: string;
      metadata?: {
        cwe?: string[];
        owasp?: string[];
        confidence?: string;
      };
      lines?: string;
    };
  }[];
  errors?: { message: string }[];
}

function mapSeverity(semgrepSeverity: string): Severity {
  switch (semgrepSeverity.toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "info";
    default:
      return "medium";
  }
}

export class SemgrepScanner implements Scanner {
  name = "semgrep";

  async isAvailable(): Promise<boolean> {
    return commandExists("semgrep");
  }

  async scan(target: string): Promise<ScanResult> {
    const start = Date.now();
    const makeResult = (partial: Omit<ScanResult, "scanner" | "durationMs">): ScanResult => ({
      scanner: this.name,
      durationMs: Date.now() - start,
      ...partial,
    });

    let result;
    try {
      result = await runCommand(
        "semgrep",
        [
          "scan",
          "--json",
          "--config",
          process.env["SEMGREP_RULES_DIR"] ?? "auto",
          "--no-git-ignore",
          target,
        ],
        { cwd: target, timeout: 300_000 }
      );
    } catch (err) {
      return makeResult({
        success: false,
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      });
    }

    if (!result.stdout) {
      return makeResult({ success: true, findings: [] });
    }

    let parsed: SemgrepResult;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return makeResult({
        success: false,
        findings: [],
        error: `Failed to parse semgrep output: ${result.stderr || result.stdout.slice(0, 500)}`,
      });
    }

    const findings = this.parseResults(parsed);
    return makeResult({ success: true, findings });
  }

  private parseResults(parsed: SemgrepResult): Finding[] {
    return (parsed.results ?? []).map((r) => {
      const cweIds = r.extra.metadata?.cwe ?? [];
      return {
        id: generateFindingId(this.name, r.path, r.start.line, r.check_id),
        scanner: this.name,
        category: CATEGORY.SAST,
        severity: mapSeverity(r.extra.severity),
        title: r.check_id.split(".").pop() ?? r.check_id,
        description: r.extra.message,
        filePath: r.path,
        startLine: r.start.line,
        endLine: r.end.line,
        cweId: cweIds[0],
        recommendation: `Fix the issue identified by rule: ${r.check_id}. ${r.extra.message}`,
        snippet: r.extra.lines,
        metadata: {
          ruleId: r.check_id,
          owasp: r.extra.metadata?.owasp,
          confidence: r.extra.metadata?.confidence,
        },
      };
    });
  }
}
