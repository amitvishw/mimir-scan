import type { Finding, Scanner, ScanResult, Severity } from "../types";
import { CATEGORY, SEVERITY } from "../types";
import { generateFindingId } from "../utils";
import { readdir, readFile, stat } from "fs/promises";
import { join, extname } from "path";

/** Prompt injection pattern definition */
interface InjectionPattern {
  id: string;
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
}

/** Files to scan for prompt injection */
const TARGET_FILES = [
  "CLAUDE.md",
  "GEMINI.md",
  "AGENTS.md",
  "AGENT.md",
  "SKILL.md",
  "CONVENTIONS.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  "copilot-instructions.md",
  ".github/copilot-instructions.md",
];

/** Extensions to scan */
const TARGET_EXTENSIONS = [".md", ".txt", ".yaml", ".yml", ".json"];

/** Prompt injection detection patterns */
const INJECTION_PATTERNS: InjectionPattern[] = [
  // Instruction override attempts
  {
    id: "PI001",
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Instruction Override Attempt",
    description:
      "Detected attempt to ignore previous instructions, a common prompt injection technique.",
    recommendation:
      "Remove or sanitize this content. Never allow user input to override system instructions.",
  },
  {
    id: "PI002",
    pattern:
      /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|guidelines?|programming)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Instruction Disregard Attempt",
    description: "Detected attempt to disregard instructions.",
    recommendation: "Remove this content. This is a prompt injection attempt.",
  },
  {
    id: "PI003",
    pattern: /forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Memory Wipe Attempt",
    description: "Detected attempt to make AI forget its instructions.",
    recommendation: "Remove this malicious content.",
  },

  // Role manipulation
  {
    id: "PI004",
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|the)\s+/gi,
    severity: SEVERITY.HIGH,
    title: "Role Manipulation Attempt",
    description: "Detected attempt to change AI's role or identity.",
    recommendation: "Review and remove role manipulation attempts.",
  },
  {
    id: "PI005",
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s+/gi,
    severity: SEVERITY.HIGH,
    title: "Identity Override Attempt",
    description: "Detected attempt to make AI pretend to be something else.",
    recommendation: "Remove identity manipulation content.",
  },
  {
    id: "PI006",
    pattern: /act\s+as\s+(if\s+you\s+are|a|an)\s+/gi,
    severity: SEVERITY.MEDIUM,
    title: "Behavioral Manipulation",
    description: "Detected attempt to change AI behavior through role-play.",
    recommendation: "Review this content for malicious intent.",
  },

  // Jailbreak attempts
  {
    id: "PI007",
    pattern: /\bDAN\s+(mode|prompt)|do\s+anything\s+now/gi,
    severity: SEVERITY.CRITICAL,
    title: "DAN Jailbreak Attempt",
    description: "Detected 'Do Anything Now' jailbreak pattern.",
    recommendation: "Remove this jailbreak attempt immediately.",
  },
  {
    id: "PI008",
    pattern: /\bdeveloper\s+mode\s+(enabled?|on|activated?)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Developer Mode Jailbreak",
    description: "Detected developer mode jailbreak attempt.",
    recommendation: "Remove this jailbreak attempt.",
  },
  {
    id: "PI009",
    pattern: /\bunlock(ed)?\s+(your\s+)?(full\s+)?(potential|capabilities|powers?)/gi,
    severity: SEVERITY.HIGH,
    title: "Capability Unlock Attempt",
    description: "Detected attempt to unlock restricted capabilities.",
    recommendation: "Remove content attempting to bypass restrictions.",
  },

  // Data exfiltration
  {
    id: "PI010",
    pattern:
      /send\s+(to|data|info|information|secrets?|credentials?|tokens?|keys?)\s*(to)?\s*(https?:\/\/|external|remote)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Data Exfiltration Attempt",
    description: "Detected attempt to exfiltrate data to external URLs.",
    recommendation: "Remove this data exfiltration attempt immediately.",
  },
  {
    id: "PI011",
    pattern: /fetch\s*\(\s*['"`]https?:\/\//gi,
    severity: SEVERITY.HIGH,
    title: "External Request in Prompt",
    description: "Detected attempt to make external HTTP requests.",
    recommendation: "Review and validate any external URL references.",
  },
  {
    id: "PI012",
    pattern: /curl\s+(-[a-zA-Z]+\s+)*https?:\/\//gi,
    severity: SEVERITY.HIGH,
    title: "Curl Command in Prompt",
    description: "Detected curl command attempting external requests.",
    recommendation: "Remove or validate curl commands.",
  },

  // System prompt extraction
  {
    id: "PI013",
    pattern:
      /what\s+(are|is)\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)/gi,
    severity: SEVERITY.MEDIUM,
    title: "System Prompt Extraction",
    description: "Detected attempt to extract system prompt.",
    recommendation: "This may be an attempt to discover system instructions.",
  },
  {
    id: "PI014",
    pattern: /reveal\s+(your|the)\s+(system\s+)?(prompt|instructions?|programming)/gi,
    severity: SEVERITY.HIGH,
    title: "Prompt Reveal Attempt",
    description: "Detected attempt to reveal system prompt.",
    recommendation: "Remove prompt extraction attempts.",
  },
  {
    id: "PI015",
    pattern: /print\s+(your|the)\s+(entire\s+)?(system\s+)?(prompt|instructions?)/gi,
    severity: SEVERITY.HIGH,
    title: "Prompt Print Attempt",
    description: "Detected attempt to print system instructions.",
    recommendation: "Remove this extraction attempt.",
  },

  // Command execution
  {
    id: "PI016",
    pattern:
      /execute\s+(this\s+)?(shell\s+)?command|run\s+(this\s+)?command|`{3}bash\s*\n\s*(rm|curl|wget|nc|netcat)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Dangerous Command Execution",
    description: "Detected attempt to execute potentially dangerous commands.",
    recommendation: "Remove dangerous command execution attempts.",
  },
  {
    id: "PI017",
    pattern: /\brm\s+-rf\s+(\/|~|\.\.)/gi,
    severity: SEVERITY.CRITICAL,
    title: "Destructive Command",
    description: "Detected destructive file deletion command.",
    recommendation: "Remove this destructive command immediately.",
  },

  // Encoding bypass attempts
  {
    id: "PI018",
    pattern: /base64\s*(decode|encode)|atob\s*\(|btoa\s*\(/gi,
    severity: SEVERITY.MEDIUM,
    title: "Encoding Bypass Attempt",
    description: "Detected base64 encoding which may hide malicious content.",
    recommendation: "Review encoded content for hidden malicious payloads.",
  },
  {
    id: "PI019",
    pattern: /\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/g,
    severity: SEVERITY.LOW,
    title: "Unicode/Hex Escape Sequences",
    description: "Detected escape sequences that may hide malicious content.",
    recommendation: "Review escaped content for hidden instructions.",
  },

  // Indirect injection markers
  {
    id: "PI020",
    pattern: /\[SYSTEM\]|\[INST\]|\[\/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>/gi,
    severity: SEVERITY.HIGH,
    title: "Chat Template Injection",
    description: "Detected chat template markers that may manipulate AI behavior.",
    recommendation: "Remove chat template markers from user content.",
  },
  {
    id: "PI021",
    pattern: /BEGIN\s+HIDDEN\s+INSTRUCTIONS?|ADMIN\s+OVERRIDE/gi,
    severity: SEVERITY.CRITICAL,
    title: "Hidden Instruction Marker",
    description: "Detected markers for hidden instructions.",
    recommendation: "Remove hidden instruction markers.",
  },

  // Tool/MCP manipulation
  {
    id: "PI022",
    pattern: /tool_choice|function_call|tool_calls?\s*:/gi,
    severity: SEVERITY.MEDIUM,
    title: "Tool Call Manipulation",
    description: "Detected attempt to manipulate tool/function calls.",
    recommendation: "Review for tool call injection attempts.",
  },
  {
    id: "PI023",
    pattern: /mcp\s*(server|tool|resource)|model\s*context\s*protocol/gi,
    severity: SEVERITY.LOW,
    title: "MCP Reference",
    description: "Detected MCP-related content that should be reviewed.",
    recommendation: "Ensure MCP references are intentional and safe.",
  },
];

export class PromptInjectionScanner implements Scanner {
  name = "prompt-injection";

  async isAvailable(): Promise<boolean> {
    // Always available - uses built-in patterns
    return true;
  }

  async scan(target: string): Promise<ScanResult> {
    const start = Date.now();
    const findings: Finding[] = [];

    try {
      const filesToScan = await this.findFilesToScan(target);

      for (const filePath of filesToScan) {
        const fileFindings = await this.scanFile(filePath, target);
        findings.push(...fileFindings);
      }

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

  /** Find all files to scan for prompt injection */
  private async findFilesToScan(target: string): Promise<string[]> {
    const files: string[] = [];

    // Check for specific target files
    for (const targetFile of TARGET_FILES) {
      const fullPath = join(target, targetFile);
      try {
        const stats = await stat(fullPath);
        if (stats.isFile()) {
          files.push(fullPath);
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    // Recursively find other relevant files
    await this.findFilesRecursive(target, files, 0);

    return files;
  }

  /** Directories to skip */
  private static readonly SKIP_DIRS = new Set(["node_modules", ".git", "vendor", "dist", "build"]);

  /** Special directories to scan */
  private static readonly SCAN_DIRS = new Set([".github", ".cursor", ".claude", ".vscode"]);

  /** Recursively find files with target extensions */
  private async findFilesRecursive(dir: string, files: string[], depth: number): Promise<void> {
    if (depth > 3) return;

    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return; // Directory not readable
    }

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      if (entry.isDirectory()) {
        await this.processDirectory(entry.name, fullPath, files, depth);
      } else if (entry.isFile() && this.isTargetFile(entry.name)) {
        if (!files.includes(fullPath)) files.push(fullPath);
      }
    }
  }

  private async processDirectory(
    name: string,
    fullPath: string,
    files: string[],
    depth: number
  ): Promise<void> {
    if (PromptInjectionScanner.SKIP_DIRS.has(name)) return;
    if (PromptInjectionScanner.SCAN_DIRS.has(name)) {
      await this.findFilesRecursive(fullPath, files, depth + 1);
    }
  }

  private isTargetFile(filename: string): boolean {
    const name = filename.toLowerCase();
    const ext = extname(filename).toLowerCase();

    if (TARGET_FILES.some((tf) => name === tf.toLowerCase())) return true;
    if (name === "claude.md" || name === "agents.md") return true;

    const hasTargetExt = TARGET_EXTENSIONS.includes(ext);
    const hasKeyword =
      name.includes("rule") || name.includes("instruction") || name.includes("prompt");
    return hasTargetExt && hasKeyword;
  }

  /** Scan a single file for prompt injection patterns */
  private async scanFile(filePath: string, baseDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const content = await readFile(filePath, "utf-8");
      const lines = content.split("\n");
      const relativePath = filePath.replace(baseDir + "/", "");

      for (const pattern of INJECTION_PATTERNS) {
        // Reset regex state
        pattern.pattern.lastIndex = 0;

        let match;
        while ((match = pattern.pattern.exec(content)) !== null) {
          // Find line number
          const beforeMatch = content.substring(0, match.index);
          const lineNumber = beforeMatch.split("\n").length;

          // Get snippet (the line containing the match)
          const snippet = lines[lineNumber - 1]?.trim() ?? match[0];

          findings.push({
            id: generateFindingId(this.name, relativePath, lineNumber, pattern.id),
            scanner: this.name,
            category: CATEGORY.PROMPT_INJECTION,
            severity: pattern.severity,
            title: pattern.title,
            description: pattern.description,
            filePath: relativePath,
            startLine: lineNumber,
            recommendation: pattern.recommendation,
            snippet: snippet.length > 200 ? snippet.substring(0, 200) + "..." : snippet,
            metadata: {
              patternId: pattern.id,
              matchedText: match[0],
            },
          });

          // Prevent infinite loops with zero-width matches
          if (match.index === pattern.pattern.lastIndex) {
            pattern.pattern.lastIndex++;
          }
        }
      }
    } catch {
      // File not readable, skip
    }

    return findings;
  }

  /** Scan a string directly (for API use) */
  async scanText(text: string, source = "input"): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = text.split("\n");

    for (const pattern of INJECTION_PATTERNS) {
      pattern.pattern.lastIndex = 0;

      let match;
      while ((match = pattern.pattern.exec(text)) !== null) {
        const beforeMatch = text.substring(0, match.index);
        const lineNumber = beforeMatch.split("\n").length;
        const snippet = lines[lineNumber - 1]?.trim() ?? match[0];

        findings.push({
          id: generateFindingId(this.name, source, lineNumber, pattern.id),
          scanner: this.name,
          category: CATEGORY.PROMPT_INJECTION,
          severity: pattern.severity,
          title: pattern.title,
          description: pattern.description,
          filePath: source,
          startLine: lineNumber,
          recommendation: pattern.recommendation,
          snippet: snippet.length > 200 ? snippet.substring(0, 200) + "..." : snippet,
          metadata: {
            patternId: pattern.id,
            matchedText: match[0],
          },
        });

        if (match.index === pattern.pattern.lastIndex) {
          pattern.pattern.lastIndex++;
        }
      }
    }

    return findings;
  }
}
