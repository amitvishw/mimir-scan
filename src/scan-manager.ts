import type {
  Finding,
  Scanner,
  ScanResult,
  Severity,
  MimirConfig,
  SarifReport,
  SarifRule,
  SarifResult,
  SecurityGrade,
  AutoFixAction,
  AutoFixResult,
} from "./types";
import { SEVERITY_ORDER, SARIF_SEVERITY_MAP, FIX_TYPE, CATEGORY } from "./types";
import {
  SemgrepScanner,
  TrivyScanner,
  GitleaksScanner,
  PromptInjectionScanner,
} from "./scanners/index";
import { getGitChangedFiles, runCommand } from "./utils";
import { loadPluginConfig, createPluginScanners } from "./plugins/index";
import { logger } from "./logger";

/** Manages all scanners and stores findings */
export class ScanManager {
  private scanners: Scanner[] = [];
  private findings: Finding[] = [];
  private config: MimirConfig;

  constructor(config: MimirConfig) {
    this.config = config;
    this.initScanners();
  }

  private initScanners() {
    // Built-in scanners
    const builtInScanners: Scanner[] = [
      new SemgrepScanner(),
      new TrivyScanner(),
      new GitleaksScanner(),
      new PromptInjectionScanner(),
    ];

    // Load custom plugin scanners from config
    const pluginConfig = loadPluginConfig(this.config.targetDir);
    const pluginScanners = pluginConfig ? createPluginScanners(pluginConfig) : [];

    if (pluginScanners.length > 0) {
      logger.debug(
        `Loaded ${pluginScanners.length} custom scanner(s)`,
        pluginScanners.map((s) => s.name)
      );
    }

    const allScanners = [...builtInScanners, ...pluginScanners];
    this.scanners = allScanners.filter((s) => this.config.enabledScanners.includes(s.name));
    logger.debug(`Enabled scanners: ${this.scanners.map((s) => s.name).join(", ")}`);
  }

  /** Register a custom scanner at runtime */
  registerScanner(scanner: Scanner): void {
    this.scanners.push(scanner);
  }

  /** Get list of all registered scanner names */
  getScannerNames(): string[] {
    return this.scanners.map((s) => s.name);
  }

  /** Check which scanners are installed */
  async getAvailability(): Promise<Record<string, boolean>> {
    const result: Record<string, boolean> = {};
    for (const scanner of this.scanners) {
      result[scanner.name] = await scanner.isAvailable();
    }
    return result;
  }

  /** Run all enabled+available scanners */
  async runScan(target?: string): Promise<{
    results: ScanResult[];
    findings: Finding[];
    summary: string;
  }> {
    const scanTarget = target ?? this.config.targetDir;
    const results: ScanResult[] = [];
    const newFindings: Finding[] = [];

    logger.info(`Starting scan on ${scanTarget}`);
    const scanStart = Date.now();

    for (const scanner of this.scanners) {
      const available = await scanner.isAvailable();
      if (!available) {
        logger.debug(`Scanner ${scanner.name} not available, skipping`);
        results.push({
          scanner: scanner.name,
          success: false,
          findings: [],
          error: `${scanner.name} is not installed. Install it to enable scanning.`,
          durationMs: 0,
        });
        continue;
      }

      logger.debug(`Running scanner: ${scanner.name}`);
      const result = await scanner.scan(scanTarget);
      logger.debug(`Scanner ${scanner.name} completed`, {
        findings: result.findings.length,
        durationMs: result.durationMs,
      });
      results.push(result);
      newFindings.push(...result.findings);
    }

    // Filter by minimum severity
    const minOrder = SEVERITY_ORDER[this.config.minSeverity];
    const filtered = newFindings.filter((f) => SEVERITY_ORDER[f.severity] >= minOrder);

    this.findings = filtered;

    const totalDuration = Date.now() - scanStart;
    logger.info(`Scan complete`, { findings: filtered.length, durationMs: totalDuration });

    const summary = this.buildSummary(results, filtered);
    return { results, findings: filtered, summary };
  }

  /** Run scan only on git-changed files */
  async runDiffScan(base?: string): Promise<{
    results: ScanResult[];
    findings: Finding[];
    summary: string;
    changedFiles: string[];
  }> {
    const { files, error } = await getGitChangedFiles(this.config.targetDir, base);

    if (error) {
      return {
        results: [],
        findings: [],
        summary: `Git diff scan failed: ${error}`,
        changedFiles: [],
      };
    }

    if (files.length === 0) {
      return {
        results: [],
        findings: [],
        summary: "No changed files detected. Working directory is clean.",
        changedFiles: [],
      };
    }

    // Run full scan
    const { results, findings } = await this.runScan();

    // Filter findings to only include changed files
    const changedSet = new Set(files.map((f) => f.toLowerCase()));
    const filteredFindings = findings.filter((f) => {
      const normalizedPath = f.filePath.toLowerCase();
      return Array.from(changedSet).some(
        (changed) => normalizedPath.includes(changed) || changed.includes(normalizedPath)
      );
    });

    this.findings = filteredFindings;

    const grade = this.calculateGrade(filteredFindings);
    const summary = [
      `Mimir Diff Scan Complete — Grade: ${grade}`,
      `  Changed files: ${files.length}`,
      `  Findings in changed files: ${filteredFindings.length}`,
      `  Files scanned: ${files.slice(0, 5).join(", ")}${files.length > 5 ? ` (+${files.length - 5} more)` : ""}`,
    ].join("\n");

    return {
      results,
      findings: filteredFindings,
      summary,
      changedFiles: files,
    };
  }

  /** Get stored findings, optionally filtered */
  getFindings(opts?: { severity?: Severity; category?: string; filePath?: string }): Finding[] {
    let result = [...this.findings];

    if (opts?.severity) {
      const minOrder = SEVERITY_ORDER[opts.severity];
      result = result.filter((f) => SEVERITY_ORDER[f.severity] >= minOrder);
    }
    if (opts?.category) {
      result = result.filter((f) => f.category === opts.category);
    }
    if (opts?.filePath) {
      const pathFilter = opts.filePath;
      result = result.filter((f) => f.filePath.includes(pathFilter));
    }

    return result;
  }

  /** Generate a fix prompt for the AI agent */
  generateFixPrompt(findingId?: string): string {
    const targets = findingId ? this.findings.filter((f) => f.id === findingId) : this.findings;

    if (targets.length === 0) {
      return "No findings to fix. Run a scan first.";
    }

    const lines: string[] = [
      "# Security Findings — Fix Required\n",
      "The following security vulnerabilities were detected. Please fix each one:\n",
    ];

    // Group by file
    const byFile = new Map<string, Finding[]>();
    for (const f of targets) {
      const existing = byFile.get(f.filePath) ?? [];
      existing.push(f);
      byFile.set(f.filePath, existing);
    }

    for (const [filePath, fileFindings] of byFile) {
      lines.push(`## File: ${filePath}\n`);

      for (const f of fileFindings) {
        lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
        if (f.startLine)
          lines.push(`- **Location**: Line ${f.startLine}${f.endLine ? `-${f.endLine}` : ""}`);
        if (f.cweId) lines.push(`- **CWE**: ${f.cweId}`);
        if (f.cveId) lines.push(`- **CVE**: ${f.cveId}`);
        lines.push(`- **Description**: ${f.description}`);
        lines.push(`- **Recommendation**: ${f.recommendation}`);
        if (f.snippet) {
          lines.push(`- **Code snippet**:\n\`\`\`\n${f.snippet}\n\`\`\``);
        }
        lines.push("");
      }
    }

    lines.push("\n---");
    lines.push("After fixing, run the scan again to verify all issues are resolved.");

    return lines.join("\n");
  }

  /** Generate auto-fix actions for findings */
  generateAutoFixes(findingId?: string): AutoFixAction[] {
    const targets = findingId ? this.findings.filter((f) => f.id === findingId) : this.findings;

    const fixes: AutoFixAction[] = [];

    for (const finding of targets) {
      const fix = this.createAutoFix(finding);
      if (fix) {
        fixes.push(fix);
      }
    }

    return fixes;
  }

  /** Create an auto-fix action for a specific finding */
  private createAutoFix(finding: Finding): AutoFixAction | null {
    // SCA (dependency) fixes - most automatable
    if (finding.category === "sca" && finding.metadata) {
      const meta = finding.metadata as {
        pkgName?: string;
        installedVersion?: string;
        fixedVersion?: string;
      };

      if (meta.fixedVersion && meta.pkgName) {
        return {
          findingId: finding.id,
          type: FIX_TYPE.DEPENDENCY_UPGRADE,
          description: `Upgrade ${meta.pkgName} from ${meta.installedVersion} to ${meta.fixedVersion}`,
          commands: this.getDependencyUpgradeCommands(
            finding.filePath,
            meta.pkgName,
            meta.fixedVersion
          ),
          safe: true,
          autoApply: true,
        };
      }
    }

    // Secrets fixes
    if (finding.category === CATEGORY.SECRETS) {
      return {
        findingId: finding.id,
        type: FIX_TYPE.CODE_CHANGE,
        description: `Remove hardcoded secret and use environment variable`,
        filePath: finding.filePath,
        startLine: finding.startLine,
        endLine: finding.endLine,
        suggestedChange: `Replace hardcoded value with: process.env["${this.envVarName(finding.title)}"]`,
        safe: false,
        autoApply: false,
      };
    }

    // SAST fixes - provide guidance
    if (finding.category === CATEGORY.SAST) {
      return {
        findingId: finding.id,
        type: FIX_TYPE.CODE_CHANGE,
        description: finding.recommendation,
        filePath: finding.filePath,
        startLine: finding.startLine,
        endLine: finding.endLine,
        safe: false,
        autoApply: false,
      };
    }

    // Default manual fix
    return {
      findingId: finding.id,
      type: FIX_TYPE.MANUAL,
      description: finding.recommendation,
      safe: false,
      autoApply: false,
    };
  }

  /** Get commands to upgrade a dependency based on package manager */
  private getDependencyUpgradeCommands(
    filePath: string,
    pkgName: string,
    version: string
  ): string[] {
    const file = filePath.toLowerCase();

    if (file.includes("package.json") || file.includes("package-lock.json")) {
      return [
        `npm install ${pkgName}@${version}`,
        `# or: yarn upgrade ${pkgName}@${version}`,
        `# or: bun add ${pkgName}@${version}`,
      ];
    }

    if (file.includes("requirements.txt") || file.includes("pyproject.toml")) {
      return [`pip install ${pkgName}==${version}`, `# Then update requirements.txt`];
    }

    if (file.includes("gemfile")) {
      return [`bundle update ${pkgName} --conservative`];
    }

    if (file.includes("go.mod")) {
      return [`go get ${pkgName}@v${version}`];
    }

    if (file.includes("cargo.toml")) {
      return [`cargo update -p ${pkgName}`];
    }

    return [`# Upgrade ${pkgName} to version ${version} using your package manager`];
  }

  /** Generate env var name from finding title */
  private envVarName(title: string): string {
    return title
      .replace(/^Hardcoded secret:\s*/i, "")
      .replace(/[^a-zA-Z0-9]/g, "_")
      .toUpperCase();
  }

  /** Apply safe auto-fixes (dependency upgrades only) */
  async applyAutoFixes(fixes?: AutoFixAction[]): Promise<AutoFixResult[]> {
    const toApply = (fixes ?? this.generateAutoFixes()).filter(
      (f) => f.autoApply && f.safe && f.type === "dependency_upgrade"
    );

    const results: AutoFixResult[] = [];

    for (const fix of toApply) {
      if (!fix.commands || fix.commands.length === 0) {
        results.push({
          findingId: fix.findingId,
          success: false,
          message: "No commands to execute",
        });
        continue;
      }

      // Only execute the first command (the primary one)
      const cmd = fix.commands[0] ?? "";
      if (!cmd || cmd.startsWith("#")) {
        results.push({
          findingId: fix.findingId,
          success: false,
          message: cmd ? "Command is a comment, skipping" : "No command available",
        });
        continue;
      }

      try {
        const parts = cmd.split(" ");
        const binary = parts[0];
        if (!binary) {
          results.push({ findingId: fix.findingId, success: false, message: "Empty command" });
          continue;
        }
        const args = parts.slice(1);
        const result = await runCommand(binary, args, {
          cwd: this.config.targetDir,
          timeout: 120_000,
        });

        results.push({
          findingId: fix.findingId,
          success: result.exitCode === 0,
          message:
            result.exitCode === 0 ? `Applied: ${cmd}` : `Failed: ${result.stderr || result.stdout}`,
          command: cmd,
        });
      } catch (err) {
        results.push({
          findingId: fix.findingId,
          success: false,
          message: err instanceof Error ? err.message : String(err),
          command: cmd,
        });
      }
    }

    return results;
  }

  private buildSummary(results: ScanResult[], findings: Finding[]): string {
    const bySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    }

    const grade = this.calculateGrade(findings);
    const scannerStatus = results
      .map(
        (r) =>
          `${r.scanner}: ${r.success ? `✓ (${r.findings.length} findings, ${r.durationMs}ms)` : `✗ ${r.error}`}`
      )
      .join("\n  ");

    return [
      `Mimir Scan Complete — Grade: ${grade}`,
      `  Total findings: ${findings.length}`,
      `  Critical: ${bySeverity["critical"]}, High: ${bySeverity["high"]}, Medium: ${bySeverity["medium"]}, Low: ${bySeverity["low"]}, Info: ${bySeverity["info"]}`,
      `  Scanners:`,
      `  ${scannerStatus}`,
    ].join("\n");
  }

  /** Calculate security grade based on findings */
  calculateGrade(findings?: Finding[]): SecurityGrade {
    const f = findings ?? this.findings;
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const finding of f) {
      if (finding.severity in counts) {
        counts[finding.severity as keyof typeof counts]++;
      }
    }

    // Grading criteria:
    // A: No critical or high, <= 2 medium
    // B: No critical, <= 2 high, <= 5 medium
    // C: No critical, <= 5 high, <= 10 medium
    // D: <= 2 critical, <= 10 high
    // F: > 2 critical or > 10 high
    if (counts.critical === 0 && counts.high === 0 && counts.medium <= 2) {
      return "A";
    }
    if (counts.critical === 0 && counts.high <= 2 && counts.medium <= 5) {
      return "B";
    }
    if (counts.critical === 0 && counts.high <= 5 && counts.medium <= 10) {
      return "C";
    }
    if (counts.critical <= 2 && counts.high <= 10) {
      return "D";
    }
    return "F";
  }

  /** Export findings in SARIF format */
  toSarif(findings?: Finding[]): SarifReport {
    const f = findings ?? this.findings;

    // Collect unique rules
    const rulesMap = new Map<string, SarifRule>();
    const results: SarifResult[] = [];

    for (const finding of f) {
      const ruleId = `${finding.scanner}/${finding.category}/${finding.title.replace(/[^a-zA-Z0-9-_]/g, "-")}`;

      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: finding.title,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          properties: {
            category: finding.category,
            "security-severity": this.severityToScore(finding.severity),
          },
        });
      }

      results.push({
        ruleId,
        level: SARIF_SEVERITY_MAP[finding.severity],
        message: { text: finding.description },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: finding.filePath },
              region: finding.startLine
                ? {
                    startLine: finding.startLine,
                    endLine: finding.endLine ?? finding.startLine,
                  }
                : undefined,
            },
          },
        ],
        fingerprints: {
          "mimir/v1": finding.id,
        },
      });
    }

    return {
      $schema:
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "mimir-scan",
              version: "0.1.0",
              informationUri: "https://github.com/amitvishw/mimir-scan",
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
        },
      ],
    };
  }

  /** Convert severity to CVSS-like score for SARIF */
  private severityToScore(severity: Severity): string {
    const scores: Record<Severity, string> = {
      critical: "9.0",
      high: "7.0",
      medium: "4.0",
      low: "2.0",
      info: "0.0",
    };
    return scores[severity];
  }
}
