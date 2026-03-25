import { describe, test, expect, beforeEach } from "bun:test";
import { ScanManager } from "./scan-manager";
import type { AutoFixAction, Finding, Scanner, ScanResult, MimirConfig } from "./types";

/** Helper to inject findings for testing (bypasses private access) */
function setFindings(manager: ScanManager, findings: Finding[]): void {
  (manager as unknown as { findings: Finding[] }).findings = findings;
}

// Mock findings for testing
const mockFindings: Finding[] = [
  {
    id: "test:file1.js:10:sql-injection",
    scanner: "semgrep",
    category: "sast",
    severity: "critical",
    title: "SQL Injection",
    description: "User input directly in SQL query",
    filePath: "src/file1.js",
    startLine: 10,
    recommendation: "Use parameterized queries",
  },
  {
    id: "test:file2.js:20:xss",
    scanner: "semgrep",
    category: "sast",
    severity: "high",
    title: "XSS Vulnerability",
    description: "Unescaped output to HTML",
    filePath: "src/file2.js",
    startLine: 20,
    recommendation: "Escape HTML output",
  },
  {
    id: "test:package.json:0:CVE-2023-1234",
    scanner: "trivy",
    category: "sca",
    severity: "high",
    title: "CVE-2023-1234 in lodash",
    description: "Prototype pollution vulnerability",
    filePath: "package.json",
    cveId: "CVE-2023-1234",
    recommendation: "Upgrade lodash from 4.17.20 to 4.17.21",
    metadata: {
      pkgName: "lodash",
      installedVersion: "4.17.20",
      fixedVersion: "4.17.21",
    },
  },
  {
    id: "test:config.js:5:hardcoded-secret",
    scanner: "gitleaks",
    category: "secrets",
    severity: "critical",
    title: "Hardcoded API Key",
    description: "API key found in source code",
    filePath: "src/config.js",
    startLine: 5,
    recommendation: "Use environment variables",
  },
  {
    id: "test:main.tf:15:s3-public",
    scanner: "trivy",
    category: "iac",
    severity: "medium",
    title: "S3 Bucket Public Access",
    description: "S3 bucket allows public access",
    filePath: "infra/main.tf",
    startLine: 15,
    recommendation: "Disable public access",
  },
  {
    id: "test:file3.js:30:info-log",
    scanner: "semgrep",
    category: "sast",
    severity: "info",
    title: "Console Log Statement",
    description: "Debug logging in production code",
    filePath: "src/file3.js",
    startLine: 30,
    recommendation: "Remove console.log statements",
  },
];

describe("ScanManager", () => {
  let manager: ScanManager;
  const config: MimirConfig = {
    targetDir: "/tmp/test",
    enabledScanners: ["semgrep", "trivy", "gitleaks"],
    minSeverity: "low",
  };

  beforeEach(() => {
    manager = new ScanManager(config);
    setFindings(manager, [...mockFindings]);
  });

  describe("calculateGrade", () => {
    test("returns A for no high-severity findings", () => {
      setFindings(manager, [{ ...mockFindings[4]!, severity: "low" }]);
      expect(manager.calculateGrade()).toBe("A");
    });

    test("returns A for empty findings", () => {
      setFindings(manager, []);
      expect(manager.calculateGrade()).toBe("A");
    });

    test("returns B for few high severity", () => {
      setFindings(manager, [{ ...mockFindings[1]! }, { ...mockFindings[4]! }]);
      expect(manager.calculateGrade()).toBe("B");
    });

    test("returns C for multiple high severity", () => {
      setFindings(manager, [
        { ...mockFindings[1]!, severity: "high" },
        { ...mockFindings[2]!, severity: "high" },
        { ...mockFindings[3]!, severity: "high" },
        { ...mockFindings[4]!, severity: "medium" },
        { ...mockFindings[4]!, severity: "medium" },
        { ...mockFindings[4]!, severity: "medium" },
      ]);
      expect(manager.calculateGrade()).toBe("C");
    });

    test("returns D for some critical findings", () => {
      setFindings(manager, [
        { ...mockFindings[0]!, severity: "critical" },
        { ...mockFindings[3]!, severity: "critical" },
      ]);
      expect(manager.calculateGrade()).toBe("D");
    });

    test("returns F for many critical findings", () => {
      setFindings(manager, [
        { ...mockFindings[0]!, severity: "critical" },
        { ...mockFindings[1]!, severity: "critical" },
        { ...mockFindings[2]!, severity: "critical" },
      ]);
      expect(manager.calculateGrade()).toBe("F");
    });

    test("accepts custom findings array", () => {
      const baseFinding = mockFindings[5];
      const customFindings = baseFinding
        ? ([{ ...baseFinding, severity: "info" }] as Finding[])
        : [];
      expect(manager.calculateGrade(customFindings)).toBe("A");
    });
  });

  describe("toSarif", () => {
    test("generates valid SARIF structure", () => {
      const sarif = manager.toSarif();

      expect(sarif.$schema).toContain("sarif-schema-2.1.0");
      expect(sarif.version).toBe("2.1.0");
      expect(sarif.runs).toHaveLength(1);
      expect(sarif.runs[0]?.tool.driver.name).toBe("mimir-scan");
    });

    test("includes all findings as results", () => {
      const sarif = manager.toSarif();
      expect(sarif.runs[0]?.results).toHaveLength(mockFindings.length);
    });

    test("creates unique rules for each finding type", () => {
      const sarif = manager.toSarif();
      const rules = sarif.runs[0]?.tool.driver.rules ?? [];
      expect(rules.length).toBeGreaterThan(0);
      // Each unique finding type should have a rule
      const ruleIds = rules.map((r) => r.id);
      expect(new Set(ruleIds).size).toBe(ruleIds.length); // All unique
    });

    test("maps severity to SARIF levels correctly", () => {
      const sarif = manager.toSarif();
      const results = sarif.runs[0]?.results ?? [];

      const criticalResult = results.find((r) => r.ruleId.includes("SQL-Injection"));
      expect(criticalResult?.level).toBe("error");

      const infoResult = results.find((r) => r.ruleId.includes("Console-Log"));
      expect(infoResult?.level).toBe("note");
    });

    test("includes file locations", () => {
      const sarif = manager.toSarif();
      const result = sarif.runs[0]?.results[0];

      expect(result?.locations).toHaveLength(1);
      expect(result?.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe("src/file1.js");
      expect(result?.locations?.[0]?.physicalLocation.region?.startLine).toBe(10);
    });

    test("includes fingerprints for deduplication", () => {
      const sarif = manager.toSarif();
      const result = sarif.runs[0]?.results[0];

      expect(result?.fingerprints).toBeDefined();
      expect(result?.fingerprints?.["mimir/v1"]).toBeDefined();
    });

    test("accepts custom findings array", () => {
      const customFindings = mockFindings[0] ? [mockFindings[0]] : [];
      const sarif = manager.toSarif(customFindings);

      expect(sarif.runs[0]?.results).toHaveLength(1);
    });
  });

  describe("generateAutoFixes", () => {
    test("generates dependency upgrade fix for SCA findings", () => {
      const fixes = manager.generateAutoFixes();
      const scaFix = fixes.find((f) => f.findingId.includes("CVE-2023-1234"));

      expect(scaFix).toBeDefined();
      expect(scaFix?.type).toBe("dependency_upgrade");
      expect(scaFix?.safe).toBe(true);
      expect(scaFix?.autoApply).toBe(true);
      expect(scaFix?.commands).toBeDefined();
      expect(scaFix?.commands?.[0]).toContain("npm install lodash@4.17.21");
    });

    test("generates code change fix for secrets", () => {
      const fixes = manager.generateAutoFixes();
      const secretFix = fixes.find((f) => f.findingId.includes("hardcoded-secret"));

      expect(secretFix).toBeDefined();
      expect(secretFix?.type).toBe("code_change");
      expect(secretFix?.safe).toBe(false);
      expect(secretFix?.autoApply).toBe(false);
      expect(secretFix?.suggestedChange).toContain("process.env");
    });

    test("generates code change fix for SAST findings", () => {
      const fixes = manager.generateAutoFixes();
      const sastFix = fixes.find((f) => f.findingId.includes("sql-injection"));

      expect(sastFix).toBeDefined();
      expect(sastFix?.type).toBe("code_change");
      expect(sastFix?.filePath).toBe("src/file1.js");
      expect(sastFix?.startLine).toBe(10);
    });

    test("can filter by finding ID", () => {
      const fixes = manager.generateAutoFixes("test:package.json:0:CVE-2023-1234");

      expect(fixes).toHaveLength(1);
      expect(fixes).toEqual([
        expect.objectContaining({ findingId: expect.stringContaining("CVE-2023-1234") }),
      ]);
    });

    test("returns empty array for no findings", () => {
      setFindings(manager, []);
      const fixes = manager.generateAutoFixes();

      expect(fixes).toHaveLength(0);
    });
  });

  describe("generateAutoFixes - Package Manager Detection", () => {
    test("generates npm command for package.json", () => {
      const fixes = manager.generateAutoFixes();
      const fix = fixes.find((f) => f.findingId.includes("CVE-2023-1234"));

      expect(fix?.commands?.[0]).toContain("npm install");
    });

    test("generates pip command for requirements.txt", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          filePath: "requirements.txt",
          metadata: { pkgName: "requests", installedVersion: "2.25.0", fixedVersion: "2.26.0" },
        },
      ]);
      const fixes = manager.generateAutoFixes();

      expect(fixes).toHaveLength(1);
      expect(fixes[0]?.commands?.[0]).toContain("pip install requests==2.26.0");
    });

    test("generates go get command for go.mod", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          filePath: "go.mod",
          metadata: {
            pkgName: "github.com/pkg/errors",
            installedVersion: "0.9.0",
            fixedVersion: "0.9.1",
          },
        },
      ]);
      const fixes = manager.generateAutoFixes();

      expect(fixes).toHaveLength(1);
      expect(fixes[0]?.commands?.[0]).toContain("go get");
    });
  });

  describe("getFindings with filters", () => {
    test("filters by severity", () => {
      const critical = manager.getFindings({ severity: "critical" });
      expect(
        critical.every(
          (f) =>
            f.severity === "critical" ||
            f.severity === "high" ||
            f.severity === "medium" ||
            f.severity === "low"
        )
      ).toBe(true);
    });

    test("filters by category", () => {
      const sast = manager.getFindings({ category: "sast" });
      expect(sast.every((f) => f.category === "sast")).toBe(true);
      expect(sast.length).toBe(3);
    });

    test("filters by file path", () => {
      const file1 = manager.getFindings({ filePath: "file1" });
      expect(file1.every((f) => f.filePath.includes("file1"))).toBe(true);
    });

    test("combines multiple filters", () => {
      const results = manager.getFindings({ category: "sast", severity: "high" });
      expect(results.length).toBeGreaterThan(0);
      expect(results.every((f) => f.category === "sast")).toBe(true);
    });
  });

  describe("generateFixPrompt", () => {
    test("generates markdown fix prompt", () => {
      const prompt = manager.generateFixPrompt();

      expect(prompt).toContain("# Security Findings");
      expect(prompt).toContain("SQL Injection");
      expect(prompt).toContain("[CRITICAL]");
      expect(prompt).toContain("Line 10");
    });

    test("groups findings by file", () => {
      const prompt = manager.generateFixPrompt();

      expect(prompt).toContain("## File: src/file1.js");
      expect(prompt).toContain("## File: src/file2.js");
    });

    test("can generate for specific finding", () => {
      const prompt = manager.generateFixPrompt("test:file1.js:10:sql-injection");

      expect(prompt).toContain("SQL Injection");
      expect(prompt).not.toContain("XSS Vulnerability");
    });

    test("returns message when no findings", () => {
      setFindings(manager, []);
      const prompt = manager.generateFixPrompt();

      expect(prompt).toContain("No findings to fix");
    });
  });

  describe("getScannerNames", () => {
    test("returns enabled scanner names from config", () => {
      const names = manager.getScannerNames();
      // Should match the enabledScanners from config
      expect(names).toContain("semgrep");
      expect(names).toContain("trivy");
      expect(names).toContain("gitleaks");
      expect(names).toHaveLength(3);
    });

    test("includes prompt-injection when enabled", () => {
      const managerWithPromptInjection = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "low",
      });
      expect(managerWithPromptInjection.getScannerNames()).toContain("prompt-injection");
    });
  });

  describe("registerScanner", () => {
    test("adds custom scanner", () => {
      const initialCount = manager.getScannerNames().length;

      const mockScanner: Scanner = {
        name: "custom-scanner",
        isAvailable: async () => true,
        scan: async (): Promise<ScanResult> => ({
          scanner: "custom-scanner",
          success: true,
          findings: [],
          durationMs: 0,
        }),
      };

      manager.registerScanner(mockScanner);
      expect(manager.getScannerNames().length).toBe(initialCount + 1);
      expect(manager.getScannerNames()).toContain("custom-scanner");
    });
  });

  describe("getAvailability", () => {
    test("returns availability for all registered scanners", async () => {
      const availability = await manager.getAvailability();
      const scannerNames = manager.getScannerNames();

      // Should have entry for each scanner
      for (const name of scannerNames) {
        expect(name in availability).toBe(true);
      }
    });

    test("prompt-injection scanner is always available", async () => {
      const managerWithPromptInjection = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "low",
      });
      const availability = await managerWithPromptInjection.getAvailability();
      expect(availability["prompt-injection"]).toBe(true);
    });
  });

  describe("runScan", () => {
    test("returns scan results structure", async () => {
      // Create manager with only prompt-injection (always available)
      const testManager = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "low",
      });

      const { results, findings, summary } = await testManager.runScan("/tmp");

      expect(Array.isArray(results)).toBe(true);
      expect(Array.isArray(findings)).toBe(true);
      expect(typeof summary).toBe("string");
      expect(summary).toContain("Mimir Scan Complete");
    });

    test("filters findings by minSeverity", async () => {
      const highSeverityManager = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "high",
      });

      const { findings } = await highSeverityManager.runScan("/tmp");
      // All findings should be high or above
      for (const f of findings) {
        expect(["critical", "high"]).toContain(f.severity);
      }
    });

    test("includes scanner status in summary", async () => {
      const testManager = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "low",
      });

      const { summary } = await testManager.runScan("/tmp");
      expect(summary).toContain("prompt-injection");
    });
  });

  describe("generateAutoFixes - Edge Cases", () => {
    test("handles IaC findings with manual fix", () => {
      setFindings(manager, [mockFindings[4]!]);
      const fixes = manager.generateAutoFixes();

      expect(fixes).toHaveLength(1);
      expect(fixes).toEqual([expect.objectContaining({ type: "manual" })]);
    });

    test("handles SCA without fixed version", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          metadata: { pkgName: "lodash", installedVersion: "4.17.20" }, // No fixedVersion
        },
      ]);
      const fixes = manager.generateAutoFixes();

      expect(fixes).toHaveLength(1);
      expect(fixes).toEqual([expect.objectContaining({ type: "manual" })]);
    });
  });

  describe("generateAutoFixes - More Package Managers", () => {
    test("generates bundle command for Gemfile", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          filePath: "Gemfile",
          metadata: { pkgName: "rails", installedVersion: "6.0.0", fixedVersion: "6.1.0" },
        },
      ]);
      const fixes = manager.generateAutoFixes();
      expect(fixes).toHaveLength(1);
      expect(fixes[0]?.commands?.[0]).toContain("bundle update");
    });

    test("generates cargo command for Cargo.toml", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          filePath: "Cargo.toml",
          metadata: { pkgName: "serde", installedVersion: "1.0.0", fixedVersion: "1.0.1" },
        },
      ]);
      const fixes = manager.generateAutoFixes();
      expect(fixes).toHaveLength(1);
      expect(fixes[0]?.commands?.[0]).toContain("cargo update");
    });

    test("generates generic comment for unknown package manager", () => {
      setFindings(manager, [
        {
          ...mockFindings[2]!,
          filePath: "unknown-lock.file",
          metadata: { pkgName: "pkg", installedVersion: "1.0", fixedVersion: "2.0" },
        },
      ]);
      const fixes = manager.generateAutoFixes();
      expect(fixes).toHaveLength(1);
      expect(fixes[0]?.commands?.[0]).toContain("# Upgrade");
    });
  });

  describe("applyAutoFixes", () => {
    let fixManager: ScanManager;

    beforeEach(() => {
      // Use /tmp as targetDir since it exists
      fixManager = new ScanManager({
        targetDir: "/tmp",
        enabledScanners: ["prompt-injection"],
        minSeverity: "low",
      });
    });

    test("returns empty array when no safe fixes", async () => {
      setFindings(fixManager, [mockFindings[0]!]);
      const results = await fixManager.applyAutoFixes();
      expect(results).toEqual([]);
    });

    test("handles fix with no commands", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "test-1",
          type: "dependency_upgrade",
          description: "Test fix",
          safe: true,
          autoApply: true,
          commands: [],
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([
        expect.objectContaining({ success: false, message: "No commands to execute" }),
      ]);
    });

    test("skips comment commands", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "test-1",
          type: "dependency_upgrade",
          description: "Test fix",
          safe: true,
          autoApply: true,
          commands: ["# This is a comment"],
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([
        expect.objectContaining({ success: false, message: expect.stringContaining("comment") }),
      ]);
    });

    test("executes valid command successfully", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "test-1",
          type: "dependency_upgrade",
          description: "Test fix",
          safe: true,
          autoApply: true,
          commands: ["echo success"],
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([
        expect.objectContaining({ success: true, message: expect.stringContaining("Applied") }),
      ]);
    });

    test("handles command failure", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "test-1",
          type: "dependency_upgrade",
          description: "Test fix",
          safe: true,
          autoApply: true,
          commands: ["false"], // 'false' command always exits with 1
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([expect.objectContaining({ success: false })]);
    });

    test("handles non-existent command", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "test-1",
          type: "dependency_upgrade",
          description: "Test fix",
          safe: true,
          autoApply: true,
          commands: ["nonexistentcmd12345 arg1"],
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([expect.objectContaining({ success: false })]);
    });

    test("only applies safe dependency upgrades", async () => {
      const fixes: AutoFixAction[] = [
        {
          findingId: "safe-fix",
          type: "dependency_upgrade",
          description: "Safe",
          safe: true,
          autoApply: true,
          commands: ["echo safe"],
        },
        {
          findingId: "unsafe-fix",
          type: "code_change",
          description: "Unsafe",
          safe: false,
          autoApply: false,
          commands: ["echo unsafe"],
        },
      ];
      const results = await fixManager.applyAutoFixes(fixes);
      expect(results).toHaveLength(1);
      expect(results).toEqual([expect.objectContaining({ findingId: "safe-fix" })]);
    });
  });
});
