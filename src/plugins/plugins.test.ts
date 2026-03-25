import { describe, expect, it } from "bun:test";
import { CliScanner } from "./cli-scanner";
import { parseSarif } from "./parsers/sarif";
import { loadPluginConfig, createPluginScanners, getPreset, listPresets } from "./loader";
import { PARSER_PRESETS } from "./types";
import type { PluginConfig } from "./types";
import { join } from "path";

const FIXTURES_DIR = join(import.meta.dir, "../../fixtures");

describe("PARSER_PRESETS", () => {
  it("has snyk preset", () => {
    const preset = PARSER_PRESETS["snyk"];
    expect(preset).toBeDefined();
    expect(preset?.category).toBe("sca");
    expect(preset?.command).toBe("snyk");
  });

  it("has checkov preset", () => {
    const preset = PARSER_PRESETS["checkov"];
    expect(preset).toBeDefined();
    expect(preset?.category).toBe("iac");
  });

  it("has bandit preset", () => {
    const preset = PARSER_PRESETS["bandit"];
    expect(preset).toBeDefined();
    expect(preset?.category).toBe("sast");
  });

  it("has njsscan preset", () => {
    const preset = PARSER_PRESETS["njsscan"];
    expect(preset).toBeDefined();
    expect(preset?.category).toBe("sast");
  });
});

describe("loader functions", () => {
  it("getPreset returns preset for known tool", () => {
    const preset = getPreset("snyk");
    expect(preset).toBeDefined();
    expect(preset?.command).toBe("snyk");
  });

  it("getPreset returns undefined for unknown tool", () => {
    const preset = getPreset("unknown-tool");
    expect(preset).toBeUndefined();
  });

  it("listPresets returns all preset names", () => {
    const presets = listPresets();
    expect(presets).toContain("snyk");
    expect(presets).toContain("checkov");
    expect(presets).toContain("bandit");
    expect(presets).toContain("njsscan");
  });

  it("loadPluginConfig returns null for non-existent config", () => {
    const config = loadPluginConfig("/tmp/non-existent-dir-12345");
    expect(config).toBeNull();
  });

  it("createPluginScanners creates scanners from config", () => {
    const scanners = createPluginScanners({
      plugins: [
        {
          name: "test-scanner",
          category: "sast",
          command: "echo",
          args: ["test"],
          outputFormat: "lines",
        },
      ],
    });
    expect(scanners).toHaveLength(1);
    expect(scanners).toEqual([expect.objectContaining({ name: "test-scanner" })]);
  });

  it("merges preset with custom config", () => {
    const scanners = createPluginScanners({
      plugins: [
        {
          name: "snyk", // Known preset
          category: "sca",
          command: "snyk",
          args: ["test", "--severity-threshold=high"], // Custom args
          outputFormat: "json",
        },
      ],
    });
    expect(scanners).toHaveLength(1);
    expect(scanners).toEqual([expect.objectContaining({ name: "snyk" })]);
  });

  it("handles empty plugins array", () => {
    const scanners = createPluginScanners({ plugins: [] });
    expect(scanners).toHaveLength(0);
  });

  it("handles config without plugins key", () => {
    const scanners = createPluginScanners({});
    expect(scanners).toHaveLength(0);
  });
});

describe("CliScanner", () => {
  const testConfig: PluginConfig = {
    name: "test-cli",
    category: "sast",
    command: "echo",
    args: ["hello"],
    outputFormat: "lines",
  };

  it("creates scanner with correct name", () => {
    const scanner = new CliScanner(testConfig);
    expect(scanner.name).toBe("test-cli");
  });

  it("isAvailable returns true for existing command", async () => {
    const scanner = new CliScanner(testConfig);
    const available = await scanner.isAvailable();
    expect(available).toBe(true);
  });

  it("isAvailable returns false for non-existing command", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "non-existent-command-12345",
    });
    const available = await scanner.isAvailable();
    expect(available).toBe(false);
  });

  it("throws error for empty command", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "",
    });
    expect(scanner.isAvailable()).rejects.toThrow("Invalid command: empty string");
  });

  it("scan returns empty findings for empty output", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "true", // outputs nothing
    });
    const result = await scanner.scan("/tmp");
    expect(result.success).toBe(true);
    expect(result.findings).toHaveLength(0);
  });

  it("parses lines format correctly", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "echo",
      args: ["high:/path/to/file.js:42:SQL injection vulnerability"],
      outputFormat: "lines",
    });
    const result = await scanner.scan("/tmp");
    expect(result.success).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings).toEqual([
      expect.objectContaining({
        severity: "high",
        filePath: "/path/to/file.js",
        startLine: 42,
      }),
    ]);
  });

  it("parses lines with different severities", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "echo",
      args: ["critical:/file.js:1:Critical issue"],
      outputFormat: "lines",
    });
    const result = await scanner.scan("/tmp");
    expect(result.findings).toEqual([expect.objectContaining({ severity: "critical" })]);
  });

  it("parses lines without line number", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "echo",
      args: ["medium:/file.js::Missing line number"],
      outputFormat: "lines",
    });
    const result = await scanner.scan("/tmp");
    expect(result.findings).toEqual([expect.objectContaining({ startLine: undefined })]);
  });

  it("handles command failure gracefully", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "sh",
      args: ["-c", "exit 1"],
    });
    const result = await scanner.scan("/tmp");
    expect(result.success).toBe(true); // Command ran, just no output
  });

  it("uses checkCommand for availability when specified", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      checkCommand: "echo", // Check with echo instead of test-cli
    });
    const available = await scanner.isAvailable();
    expect(available).toBe(true);
  });

  it("handles JSON without parser config", async () => {
    const scanner = new CliScanner({
      name: "no-parser",
      category: "sast",
      command: "printf",
      args: ['{"results": []}'],
      outputFormat: "json",
      // No parser config
    });
    const result = await scanner.scan("/tmp");
    expect(result.findings).toHaveLength(0);
  });

  it("handles invalid JSON gracefully", async () => {
    const scanner = new CliScanner({
      name: "bad-json",
      category: "sast",
      command: "printf",
      args: ["not valid json"],
      outputFormat: "json",
      parser: {
        resultsPath: "results",
        fieldMapping: { severity: "sev", title: "t", description: "d", filePath: "f" },
      },
    });
    const result = await scanner.scan("/tmp");
    expect(result.findings).toHaveLength(0);
  });

  it("replaces {{target}} placeholder in args", async () => {
    const scanner = new CliScanner({
      ...testConfig,
      command: "echo",
      args: ["scanning:{{target}}:done"],
      outputFormat: "lines",
    });
    const result = await scanner.scan("/tmp");
    expect(result.success).toBe(true);
  });
});

describe("CliScanner JSON parsing with fixtures", () => {
  const SCANNER_OUTPUT_DIR = join(FIXTURES_DIR, "scanner-output");

  it("parses JSON with custom field mapping", async () => {
    const scanner = new CliScanner({
      name: "json-scanner",
      category: "sast",
      command: "cat",
      args: [join(SCANNER_OUTPUT_DIR, "simple.json")],
      outputFormat: "json",
      parser: {
        resultsPath: "issues",
        fieldMapping: {
          id: "rule_id",
          severity: "level",
          title: "msg",
          description: "details",
          filePath: "file",
          startLine: "line",
        },
        severityMapping: { HIGH: "high", MEDIUM: "medium", LOW: "low" },
      },
    });

    const result = await scanner.scan("/tmp");
    expect(result.success).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings).toEqual([
      expect.objectContaining({
        severity: "high",
        title: "Security issue",
        startLine: 25,
      }),
    ]);
  });

  it("parses nested JSON paths", async () => {
    const scanner = new CliScanner({
      name: "nested-scanner",
      category: "sast",
      command: "cat",
      args: [join(SCANNER_OUTPUT_DIR, "nested.json")],
      outputFormat: "json",
      parser: {
        resultsPath: "data.scan.vulnerabilities",
        fieldMapping: {
          severity: "sev",
          title: "name",
          description: "desc",
          filePath: "path",
        },
      },
    });

    const result = await scanner.scan("/tmp");
    expect(result.findings).toHaveLength(1);
    expect(result.findings).toEqual([
      expect.objectContaining({
        title: "Test",
        severity: "critical",
      }),
    ]);
  });

  it("handles all optional fields", async () => {
    const scanner = new CliScanner({
      name: "full-scanner",
      category: "sast",
      command: "cat",
      args: [join(SCANNER_OUTPUT_DIR, "full-fields.json")],
      outputFormat: "json",
      parser: {
        resultsPath: "results",
        fieldMapping: {
          id: "id",
          severity: "sev",
          title: "title",
          description: "desc",
          filePath: "file",
          startLine: "start",
          endLine: "end",
          cweId: "cwe",
          cveId: "cve",
          recommendation: "fix",
          snippet: "code",
        },
      },
    });

    const result = await scanner.scan("/tmp");
    expect(result.findings).toHaveLength(1);
    expect(result.findings).toEqual([
      expect.objectContaining({
        startLine: 10,
        endLine: 20,
        cweId: "CWE-79",
        cveId: "CVE-2023-1234",
        recommendation: "Sanitize input",
        snippet: "const x = input;",
      }),
    ]);
    expect(result.findings[0]?.id).toContain("VULN-001");
  });

  it("handles array index in path", async () => {
    const scanner = new CliScanner({
      name: "array-scanner",
      category: "sast",
      command: "cat",
      args: [join(SCANNER_OUTPUT_DIR, "array-path.json")],
      outputFormat: "json",
      parser: {
        resultsPath: "scans[0].findings",
        fieldMapping: {
          severity: "severity",
          title: "message",
          description: "message",
          filePath: "path",
        },
      },
    });

    const result = await scanner.scan("/tmp");
    expect(result.findings).toHaveLength(1);
    expect(result.findings).toEqual([expect.objectContaining({ severity: "low" })]);
  });
});

describe("parseSarif", () => {
  it("parses valid SARIF output", () => {
    const sarifOutput = JSON.stringify({
      runs: [
        {
          tool: {
            driver: {
              rules: [
                {
                  id: "rule-001",
                  name: "Test Rule",
                  shortDescription: { text: "Short desc" },
                  fullDescription: { text: "Full description" },
                  properties: { "security-severity": "7.5" },
                },
              ],
            },
          },
          results: [
            {
              ruleId: "rule-001",
              level: "error",
              message: { text: "Found an issue" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/app.ts" },
                    region: { startLine: 10, endLine: 15 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const findings = parseSarif(sarifOutput, "test-scanner", "sast");
    expect(findings).toHaveLength(1);
    expect(findings).toEqual([
      expect.objectContaining({
        scanner: "test-scanner",
        category: "sast",
        severity: "high", // 7.5 maps to high
        title: "Test Rule",
        filePath: "src/app.ts",
        startLine: 10,
        endLine: 15,
      }),
    ]);
  });

  it("handles empty SARIF output", () => {
    const sarifOutput = JSON.stringify({ runs: [] });
    const findings = parseSarif(sarifOutput, "test-scanner", "sast");
    expect(findings).toHaveLength(0);
  });

  it("handles invalid JSON gracefully", () => {
    const findings = parseSarif("not valid json", "test-scanner", "sast");
    expect(findings).toHaveLength(0);
  });

  it("maps SARIF levels to severity correctly", () => {
    const makeSarif = (level: string) =>
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: "test",
                level,
                locations: [{ physicalLocation: { artifactLocation: { uri: "file.ts" } } }],
              },
            ],
          },
        ],
      });

    expect(parseSarif(makeSarif("error"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "high" }),
    ]);
    expect(parseSarif(makeSarif("warning"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "medium" }),
    ]);
    expect(parseSarif(makeSarif("note"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "low" }),
    ]);
    expect(parseSarif(makeSarif("none"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "info" }),
    ]);
  });

  it("uses security-severity score when available", () => {
    const makeSarif = (score: string) =>
      JSON.stringify({
        runs: [
          {
            tool: {
              driver: {
                rules: [{ id: "test", properties: { "security-severity": score } }],
              },
            },
            results: [
              {
                ruleId: "test",
                locations: [{ physicalLocation: { artifactLocation: { uri: "file.ts" } } }],
              },
            ],
          },
        ],
      });

    expect(parseSarif(makeSarif("9.5"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "critical" }),
    ]);
    expect(parseSarif(makeSarif("7.0"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "high" }),
    ]);
    expect(parseSarif(makeSarif("4.0"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "medium" }),
    ]);
    expect(parseSarif(makeSarif("2.0"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "low" }),
    ]);
    expect(parseSarif(makeSarif("0.0"), "s", "sast")).toEqual([
      expect.objectContaining({ severity: "info" }),
    ]);
  });
});
