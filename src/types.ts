/** Severity levels for security findings */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Severity constants for type-safe usage */
export const SEVERITY = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
} as const satisfies Record<string, Severity>;

/** Categories of security findings */
export type FindingCategory =
  | "sast" // Static Application Security Testing
  | "sca" // Software Composition Analysis (dependency vulnerabilities)
  | "secrets" // Hardcoded secrets/credentials
  | "iac" // Infrastructure as Code misconfigurations
  | "license" // License compliance issues
  | "prompt-injection"; // Prompt injection attacks

/** Category constants for type-safe usage */
export const CATEGORY = {
  SAST: "sast",
  SCA: "sca",
  SECRETS: "secrets",
  IAC: "iac",
  LICENSE: "license",
  PROMPT_INJECTION: "prompt-injection",
} as const satisfies Record<string, FindingCategory>;

/** Security grade for the project */
export type SecurityGrade = "A" | "B" | "C" | "D" | "F";

/** Output format for scan results */
export type OutputFormat = "text" | "json" | "sarif";

/** A single security finding from a scanner */
export interface Finding {
  id: string;
  scanner: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  filePath: string;
  startLine?: number;
  endLine?: number;
  cweId?: string;
  cveId?: string;
  recommendation: string;
  snippet?: string;
  metadata?: Record<string, unknown>;
}

/** Result of a scan operation */
export interface ScanResult {
  scanner: string;
  success: boolean;
  findings: Finding[];
  error?: string;
  durationMs: number;
}

/** Configuration for the Mimir server */
export interface MimirConfig {
  /** Directory to scan (defaults to cwd) */
  targetDir: string;
  /** Which scanners to enable */
  enabledScanners: string[];
  /** Minimum severity to report */
  minSeverity: Severity;
}

/** Interface that all scanner wrappers implement */
export interface Scanner {
  name: string;
  /** Check if the scanner binary is available */
  isAvailable(): Promise<boolean>;
  /** Run the scan on a target directory or file */
  scan(target: string): Promise<ScanResult>;
}

/** Severity ordering for filtering */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** SARIF severity levels */
export const SARIF_SEVERITY_MAP: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/** SARIF output format (Static Analysis Results Interchange Format) */
export interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  properties?: {
    category?: string;
    "security-severity"?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: {
        startLine?: number;
        endLine?: number;
        startColumn?: number;
        endColumn?: number;
      };
    };
  }[];
  fingerprints?: Record<string, string>;
}

/** Prompt injection pattern for detection */
export interface PromptInjectionPattern {
  id: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}

/** Auto-fix action types */
export type AutoFixType = "dependency_upgrade" | "command" | "code_change" | "manual";

/** Fix type constants for type-safe usage */
export const FIX_TYPE = {
  DEPENDENCY_UPGRADE: "dependency_upgrade",
  COMMAND: "command",
  CODE_CHANGE: "code_change",
  MANUAL: "manual",
} as const satisfies Record<string, AutoFixType>;

/** Auto-fix action for a finding */
export interface AutoFixAction {
  findingId: string;
  type: AutoFixType;
  description: string;
  /** Commands to run (for dependency upgrades) */
  commands?: string[];
  /** File to modify (for code changes) */
  filePath?: string;
  startLine?: number;
  endLine?: number;
  /** Suggested code replacement */
  suggestedChange?: string;
  /** Whether this fix is safe to auto-apply */
  safe: boolean;
  /** Whether to auto-apply without confirmation */
  autoApply: boolean;
}

/** Result of applying an auto-fix */
export interface AutoFixResult {
  findingId: string;
  success: boolean;
  message: string;
  command?: string;
}
