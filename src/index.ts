#!/usr/bin/env bun
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ScanManager } from "./scan-manager";
import type { MimirConfig } from "./types";
import { logger } from "./logger";

// ─── Configuration ──────────────────────────────────────────────────────────────

const config: MimirConfig = {
  targetDir: process.env["MIMIR_TARGET_DIR"] ?? process.cwd(),
  enabledScanners: (
    process.env["MIMIR_SCANNERS"] ?? "semgrep,trivy,gitleaks,prompt-injection"
  ).split(","),
  minSeverity: (process.env["MIMIR_MIN_SEVERITY"] as MimirConfig["minSeverity"]) ?? "low",
};

const scanManager = new ScanManager(config);

// ─── MCP Server ─────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "mimir-scan",
  version: "0.1.0",
});

// ─── Tool: mimir_scan ────────────────────────────────────────────────────────────

server.registerTool(
  "mimir_scan",
  {
    description:
      "Run Mimir security scans (SAST, dependency vulnerabilities, secrets detection, IaC misconfigurations) on a codebase. Returns a summary of all findings.",
    inputSchema: {
      target: z
        .string()
        .optional()
        .describe("Directory or file path to scan. Defaults to the configured target directory."),
      scanners: z
        .array(z.enum(["semgrep", "trivy", "gitleaks", "prompt-injection"]))
        .optional()
        .describe("Which scanners to run. Defaults to all enabled scanners."),
    },
  },
  async ({ target, scanners }) => {
    // If specific scanners requested, create a temporary manager
    let mgr = scanManager;
    if (scanners && scanners.length > 0) {
      mgr = new ScanManager({ ...config, enabledScanners: scanners });
    }

    const { summary } = await mgr.runScan(target);

    // Also store findings in the main manager for later reference
    if (mgr !== scanManager) {
      // Re-run on main manager to persist findings (or we could refactor — keep it simple)
      await scanManager.runScan(target);
    }

    return {
      content: [
        {
          type: "text",
          text:
            summary +
            "\n\nUse `mimir_findings` to see detailed findings, or `mimir_fix` to get fix instructions.",
        },
      ],
    };
  }
);

// ─── Tool: mimir_check_scanners ──────────────────────────────────────────────────

server.registerTool(
  "mimir_check_scanners",
  {
    description: "Check which Mimir security scanners are installed and available on the system.",
  },
  async () => {
    const availability = await scanManager.getAvailability();
    const lines = Object.entries(availability).map(
      ([name, available]) => `${name}: ${available ? "✓ installed" : "✗ not found"}`
    );

    const installHints: Record<string, string> = {
      semgrep: "pip install semgrep  OR  brew install semgrep",
      trivy: "brew install trivy  OR  https://aquasecurity.github.io/trivy/",
      gitleaks: "brew install gitleaks  OR  https://github.com/gitleaks/gitleaks",
    };

    const missing = Object.entries(availability)
      .filter(([, available]) => !available)
      .map(([name]) => `  ${name}: ${installHints[name] ?? "check documentation"}`);

    let text = "Scanner availability:\n" + lines.join("\n");
    if (missing.length > 0) {
      text += "\n\nTo install missing scanners:\n" + missing.join("\n");
    }

    return { content: [{ type: "text", text }] };
  }
);

// ─── Tool: mimir_findings ────────────────────────────────────────────────────────

server.registerTool(
  "mimir_findings",
  {
    description:
      "Get detailed security findings from the last scan. Filter by severity, category, or file path.",
    inputSchema: {
      severity: z
        .enum(["critical", "high", "medium", "low", "info"])
        .optional()
        .describe("Minimum severity to include."),
      category: z
        .enum(["sast", "sca", "secrets", "iac", "license", "prompt-injection"])
        .optional()
        .describe("Filter findings by category."),
      filePath: z.string().optional().describe("Filter findings by file path (partial match)."),
      format: z
        .enum(["detailed", "summary"])
        .optional()
        .describe(
          "Output format. 'detailed' shows full info per finding, 'summary' shows a condensed table."
        ),
    },
  },
  async ({ severity, category, filePath, format }) => {
    const findings = scanManager.getFindings({ severity, category, filePath });

    if (findings.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "No findings match the given filters. Run `mimir_scan` first if you haven't scanned yet.",
          },
        ],
      };
    }

    let text: string;

    if (format === "summary") {
      const header = "| Severity | Category | File | Title |";
      const separator = "|----------|----------|------|-------|";
      const rows = findings.map(
        (f) =>
          `| ${f.severity} | ${f.category} | ${f.filePath}${f.startLine ? `:${f.startLine}` : ""} | ${f.title} |`
      );
      text = [header, separator, ...rows].join("\n");
    } else {
      text = findings
        .map((f) => {
          const parts = [
            `**[${f.severity.toUpperCase()}] ${f.title}**`,
            `Scanner: ${f.scanner} | Category: ${f.category}`,
            `File: ${f.filePath}${f.startLine ? `:${f.startLine}` : ""}`,
          ];
          if (f.cweId) parts.push(`CWE: ${f.cweId}`);
          if (f.cveId) parts.push(`CVE: ${f.cveId}`);
          parts.push(`Description: ${f.description}`);
          parts.push(`Recommendation: ${f.recommendation}`);
          if (f.snippet) parts.push(`Snippet:\n\`\`\`\n${f.snippet}\n\`\`\``);
          parts.push(`ID: ${f.id}`);
          return parts.join("\n");
        })
        .join("\n\n---\n\n");
    }

    return {
      content: [
        {
          type: "text",
          text: `Found ${findings.length} finding(s):\n\n${text}`,
        },
      ],
    };
  }
);

// ─── Tool: mimir_fix ─────────────────────────────────────────────────────────────

server.registerTool(
  "mimir_fix",
  {
    description:
      "Generate fix instructions for security findings. Returns a structured prompt that tells the AI agent exactly what to fix, where, and how.",
    inputSchema: {
      findingId: z
        .string()
        .optional()
        .describe(
          "Fix a specific finding by ID. If omitted, generates fix instructions for ALL findings."
        ),
    },
  },
  async ({ findingId }) => {
    const prompt = scanManager.generateFixPrompt(findingId);
    return { content: [{ type: "text", text: prompt }] };
  }
);

// ─── Tool: mimir_verify ─────────────────────────────────────────────────────────

server.registerTool(
  "mimir_verify",
  {
    description:
      "Re-run scans to verify that fixes were applied correctly. Compares new results against previous findings.",
    inputSchema: {
      target: z
        .string()
        .optional()
        .describe("Directory or file to re-scan. Defaults to the configured target directory."),
    },
  },
  async ({ target }) => {
    const previousCount = scanManager.getFindings().length;
    const { summary, findings } = await scanManager.runScan(target);
    const newCount = findings.length;
    const diff = previousCount - newCount;

    let verdict: string;
    if (newCount === 0) {
      verdict = "🎉 All findings resolved! The codebase passes Mimir checks.";
    } else if (diff > 0) {
      verdict = `✓ Progress: ${diff} finding(s) fixed. ${newCount} remaining.`;
    } else if (diff === 0) {
      verdict = `⚠ No change: Still ${newCount} finding(s). Please review the fixes and try again.`;
    } else {
      verdict = `⚠ New issues introduced: ${Math.abs(diff)} new finding(s) appeared. Total: ${newCount}.`;
    }

    return {
      content: [
        {
          type: "text",
          text: `${verdict}\n\n${summary}`,
        },
      ],
    };
  }
);

// ─── Tool: mimir_scan_diff ───────────────────────────────────────────────────────

server.registerTool(
  "mimir_scan_diff",
  {
    description:
      "Scan only git-changed files for security issues. Faster than full scan, ideal for PR reviews and pre-commit checks.",
    inputSchema: {
      base: z
        .string()
        .optional()
        .describe(
          "Base branch or commit to compare against (e.g., 'main', 'HEAD~1'). Defaults to comparing staged/unstaged changes."
        ),
    },
  },
  async ({ base }) => {
    const { summary, findings } = await scanManager.runDiffScan(base);

    let text = summary;
    if (findings.length > 0) {
      text +=
        "\n\nUse `mimir_findings` to see detailed findings, or `mimir_fix` to get fix instructions.";
    }

    return {
      content: [{ type: "text", text }],
    };
  }
);

// ─── Tool: mimir_grade ───────────────────────────────────────────────────────────

server.registerTool(
  "mimir_grade",
  {
    description:
      "Get the security grade (A-F) for the project based on current findings. A = excellent, F = critical issues.",
  },
  async () => {
    const findings = scanManager.getFindings();
    const grade = scanManager.calculateGrade(findings);

    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      counts[f.severity]++;
    }

    const gradeDescriptions: Record<string, string> = {
      A: "Excellent - No critical or high severity issues",
      B: "Good - Minor issues that should be addressed",
      C: "Fair - Several issues requiring attention",
      D: "Poor - Significant security concerns",
      F: "Failing - Critical security vulnerabilities present",
    };

    const text = [
      `# Security Grade: ${grade}`,
      `**${gradeDescriptions[grade]}**`,
      "",
      "## Breakdown",
      `- Critical: ${counts.critical}`,
      `- High: ${counts.high}`,
      `- Medium: ${counts.medium}`,
      `- Low: ${counts.low}`,
      `- Info: ${counts.info}`,
      "",
      "Run `mimir_scan` first if you haven't scanned yet.",
    ].join("\n");

    return { content: [{ type: "text", text }] };
  }
);

// ─── Tool: mimir_sarif ───────────────────────────────────────────────────────────

server.registerTool(
  "mimir_sarif",
  {
    description:
      "Export findings in SARIF format for GitHub Security tab integration and other tools.",
  },
  async () => {
    const sarif = scanManager.toSarif();
    const text = JSON.stringify(sarif, null, 2);

    return {
      content: [
        {
          type: "text",
          text: `SARIF Report (${sarif.runs[0]?.results.length ?? 0} findings):\n\n\`\`\`json\n${text}\n\`\`\``,
        },
      ],
    };
  }
);

// ─── Tool: mimir_autofix ─────────────────────────────────────────────────────────

server.registerTool(
  "mimir_autofix",
  {
    description:
      "Generate auto-fix actions for findings. Can automatically apply safe fixes like dependency upgrades.",
    inputSchema: {
      findingId: z
        .string()
        .optional()
        .describe(
          "Generate fix for a specific finding. If omitted, generates fixes for all findings."
        ),
      apply: z
        .boolean()
        .optional()
        .describe(
          "If true, automatically apply safe fixes (dependency upgrades only). Defaults to false."
        ),
    },
  },
  async ({ findingId, apply }) => {
    const fixes = scanManager.generateAutoFixes(findingId);

    if (fixes.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "No auto-fixes available. Run `mimir_scan` first if you haven't scanned yet.",
          },
        ],
      };
    }

    if (apply) {
      const results = await scanManager.applyAutoFixes(fixes);
      const successful = results.filter((r) => r.success);
      const failed = results.filter((r) => !r.success);

      let text = `# Auto-Fix Results\n\n`;
      text += `Applied: ${successful.length} | Failed: ${failed.length}\n\n`;

      if (successful.length > 0) {
        text += `## Successful\n`;
        for (const r of successful) {
          text += `- ✓ ${r.message}\n`;
        }
      }

      if (failed.length > 0) {
        text += `\n## Failed\n`;
        for (const r of failed) {
          text += `- ✗ ${r.message}\n`;
        }
      }

      text += `\nRun \`mimir_verify\` to confirm fixes were applied correctly.`;

      return { content: [{ type: "text", text }] };
    }

    // Just list available fixes
    let text = `# Available Auto-Fixes (${fixes.length})\n\n`;

    const safeAuto = fixes.filter((f) => f.safe && f.autoApply);
    const manual = fixes.filter((f) => !f.safe || !f.autoApply);

    if (safeAuto.length > 0) {
      text += `## Safe to Auto-Apply (${safeAuto.length})\n`;
      text += `*Use \`mimir_autofix\` with \`apply: true\` to apply these*\n\n`;
      for (const fix of safeAuto) {
        text += `- **${fix.type}**: ${fix.description}\n`;
        if (fix.commands) {
          text += `  \`${fix.commands[0]}\`\n`;
        }
      }
    }

    if (manual.length > 0) {
      text += `\n## Requires Manual Review (${manual.length})\n`;
      for (const fix of manual) {
        text += `- **${fix.type}**: ${fix.description}\n`;
        if (fix.filePath) {
          text += `  File: ${fix.filePath}${fix.startLine ? `:${fix.startLine}` : ""}\n`;
        }
        if (fix.suggestedChange) {
          text += `  Suggestion: ${fix.suggestedChange}\n`;
        }
      }
    }

    return { content: [{ type: "text", text }] };
  }
);

// ─── Tool: mimir_scan_prompt ─────────────────────────────────────────────────────

server.registerTool(
  "mimir_scan_prompt",
  {
    description:
      "Scan text for prompt injection attacks. Use this to validate user inputs, skill files, or any untrusted content before processing.",
    inputSchema: {
      text: z.string().describe("The text content to scan for prompt injection patterns."),
      source: z
        .string()
        .optional()
        .describe("Optional label for the source of the text (e.g., 'user_input', 'skill_file')."),
    },
  },
  async ({ text, source }) => {
    const { PromptInjectionScanner } = await import("./scanners/prompt-injection");
    const scanner = new PromptInjectionScanner();
    const findings = await scanner.scanText(text, source ?? "input");

    if (findings.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "✓ No prompt injection patterns detected. The content appears safe.",
          },
        ],
      };
    }

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      bySeverity[f.severity]++;
    }

    let resultText = `⚠ Detected ${findings.length} potential prompt injection pattern(s):\n\n`;
    resultText += `Critical: ${bySeverity.critical} | High: ${bySeverity.high} | Medium: ${bySeverity.medium} | Low: ${bySeverity.low}\n\n`;

    for (const f of findings) {
      resultText += `### [${f.severity.toUpperCase()}] ${f.title}\n`;
      resultText += `${f.description}\n`;
      resultText += `Line ${f.startLine}: \`${f.snippet}\`\n`;
      resultText += `Recommendation: ${f.recommendation}\n\n`;
    }

    return { content: [{ type: "text", text: resultText }] };
  }
);

// ─── Start Server ───────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("Mimir MCP Server running on stdio");
}

main().catch((err) => {
  logger.error("Fatal error", err);
  process.exit(1);
});
