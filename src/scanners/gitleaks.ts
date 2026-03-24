import type { Finding, Scanner, ScanResult } from "../types";
import { CATEGORY, SEVERITY } from "../types";
import { commandExists, generateFindingId, runCommand } from "../utils";

interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  File: string;
  RuleID: string;
  Entropy: number;
  Match?: string;
}

export class GitleaksScanner implements Scanner {
  name = "gitleaks";

  async isAvailable(): Promise<boolean> {
    return commandExists("gitleaks");
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
        "gitleaks",
        [
          "detect",
          "--source",
          target,
          "--report-format",
          "json",
          "--report-path",
          "/dev/stdout",
          "--no-git",
        ],
        { cwd: target, timeout: 120_000 }
      );
    } catch (err) {
      return makeResult({
        success: false,
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      });
    }

    // Gitleaks exits 1 when leaks are found - check for JSON array
    if (!result.stdout?.trim().startsWith("[")) {
      return makeResult({ success: true, findings: [] });
    }

    let parsed: GitleaksResult[];
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return makeResult({
        success: false,
        findings: [],
        error: `Failed to parse gitleaks output: ${result.stderr || result.stdout.slice(0, 500)}`,
      });
    }

    const findings = this.parseResults(parsed);
    return makeResult({ success: true, findings });
  }

  private parseResults(parsed: GitleaksResult[]): Finding[] {
    return parsed.map((leak) => ({
      id: generateFindingId(this.name, leak.File, leak.StartLine, leak.RuleID),
      scanner: this.name,
      category: CATEGORY.SECRETS,
      severity: SEVERITY.CRITICAL,
      title: `Hardcoded secret: ${leak.RuleID}`,
      description: leak.Description,
      filePath: leak.File,
      startLine: leak.StartLine,
      endLine: leak.EndLine,
      recommendation: `Remove the hardcoded secret (${leak.RuleID}) from ${leak.File}:${leak.StartLine}. Use environment variables or a secrets manager instead.`,
      snippet: leak.Match ? "[REDACTED — secret detected]" : undefined,
      metadata: {
        ruleId: leak.RuleID,
        entropy: leak.Entropy,
      },
    }));
  }
}
