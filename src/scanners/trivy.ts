import type { Finding, Scanner, ScanResult, Severity } from "../types";
import { CATEGORY } from "../types";
import { commandExists, generateFindingId, runCommand } from "../utils";

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}

interface TrivyResult {
  Results?: {
    Target: string;
    Type: string;
    Vulnerabilities?: TrivyVulnerability[];
    Misconfigurations?: {
      ID: string;
      Title: string;
      Description: string;
      Severity: string;
      Resolution: string;
      CauseMetadata?: {
        StartLine?: number;
        EndLine?: number;
      };
    }[];
  }[];
}

function mapSeverity(trivySeverity: string): Severity {
  switch (trivySeverity.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

export class TrivyScanner implements Scanner {
  name = "trivy";

  async isAvailable(): Promise<boolean> {
    return commandExists("trivy");
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
        "trivy",
        ["fs", "--format", "json", "--scanners", "vuln,misconfig", "--skip-db-update", target],
        { cwd: target, timeout: 300_000 }
      );
      if (result.stderr?.includes("--skip-db-update cannot be specified on the first run")) {
        result = await runCommand(
          "trivy",
          ["fs", "--format", "json", "--scanners", "vuln,misconfig", target],
          { cwd: target, timeout: 300_000 }
        );
      }
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

    let parsed: TrivyResult;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return makeResult({
        success: false,
        findings: [],
        error: `Failed to parse trivy output: ${result.stderr || result.stdout.slice(0, 500)}`,
      });
    }

    const findings = this.parseResults(parsed);
    return makeResult({ success: true, findings });
  }

  private parseResults(parsed: TrivyResult): Finding[] {
    return (parsed.Results ?? []).flatMap((res) => [
      ...this.parseVulnerabilities(res.Target, res.Vulnerabilities ?? []),
      ...this.parseMisconfigurations(res.Target, res.Misconfigurations ?? []),
    ]);
  }

  private parseVulnerabilities(target: string, vulns: TrivyVulnerability[]): Finding[] {
    return vulns.map((vuln) => ({
      id: generateFindingId(this.name, target, undefined, vuln.VulnerabilityID),
      scanner: this.name,
      category: CATEGORY.SCA,
      severity: mapSeverity(vuln.Severity),
      title: `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
      description:
        vuln.Description ??
        vuln.Title ??
        `Vulnerability in ${vuln.PkgName}@${vuln.InstalledVersion}`,
      filePath: target,
      cveId: vuln.VulnerabilityID,
      recommendation: vuln.FixedVersion
        ? `Upgrade ${vuln.PkgName} from ${vuln.InstalledVersion} to ${vuln.FixedVersion}`
        : `No fix available yet for ${vuln.PkgName}@${vuln.InstalledVersion}. Consider replacing the package.`,
      metadata: {
        pkgName: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion,
        url: vuln.PrimaryURL,
      },
    }));
  }

  private parseMisconfigurations(
    target: string,
    misconfigs: NonNullable<TrivyResult["Results"]>[number]["Misconfigurations"]
  ): Finding[] {
    return (misconfigs ?? []).map((m) => ({
      id: generateFindingId(this.name, target, m.CauseMetadata?.StartLine, m.ID),
      scanner: this.name,
      category: CATEGORY.IAC,
      severity: mapSeverity(m.Severity),
      title: m.Title,
      description: m.Description,
      filePath: target,
      startLine: m.CauseMetadata?.StartLine,
      endLine: m.CauseMetadata?.EndLine,
      recommendation: m.Resolution,
    }));
  }
}
