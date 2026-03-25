import type { FindingCategory, Severity } from "../types";

/** Configuration for a custom scanner plugin */
export interface PluginConfig {
  /** Unique name for this scanner */
  name: string;
  /** Display name */
  displayName?: string;
  /** Category of findings this scanner produces */
  category: FindingCategory;
  /** Command to check if scanner is available */
  checkCommand?: string;
  /** Command to run the scan (use {{target}} as placeholder) */
  command: string;
  /** Arguments for the scan command */
  args?: string[];
  /** Output format the scanner produces */
  outputFormat: "sarif" | "json" | "lines";
  /** Custom parser for JSON output (maps tool output to findings) */
  parser?: ParserConfig;
  /** Environment variables to set */
  env?: Record<string, string>;
  /** Timeout in milliseconds */
  timeout?: number;
}

/** Configuration for parsing custom JSON output */
export interface ParserConfig {
  /** JSON path to the results array (e.g., "vulnerabilities", "results", "issues") */
  resultsPath: string;
  /** Mapping from tool fields to Finding fields */
  fieldMapping: {
    id?: string;
    severity: string;
    title: string;
    description: string;
    filePath: string;
    startLine?: string;
    endLine?: string;
    cweId?: string;
    cveId?: string;
    recommendation?: string;
    snippet?: string;
  };
  /** Map tool severity values to our severity levels */
  severityMapping?: Record<string, Severity>;
}

/** Main configuration file format (.mimir.json) */
export interface MimirPluginConfig {
  /** Custom scanner plugins */
  plugins?: PluginConfig[];
  /** Override default scanner settings */
  scannerOverrides?: Record<string, Partial<PluginConfig>>;
  /** Global settings */
  settings?: {
    /** Default timeout for all scanners */
    timeout?: number;
    /** Patterns to exclude from scanning */
    exclude?: string[];
  };
}

/** Built-in parser presets for popular tools */
export const PARSER_PRESETS: Record<string, Partial<PluginConfig>> = {
  snyk: {
    category: "sca",
    command: "snyk",
    args: ["test", "--json"],
    outputFormat: "json",
    parser: {
      resultsPath: "vulnerabilities",
      fieldMapping: {
        id: "id",
        severity: "severity",
        title: "title",
        description: "description",
        filePath: "from[0]",
        cveId: "identifiers.CVE[0]",
        cweId: "identifiers.CWE[0]",
        recommendation: "fixedIn[0]",
      },
      severityMapping: {
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
      },
    },
  },
  checkov: {
    category: "iac",
    command: "checkov",
    args: ["-d", "{{target}}", "-o", "json"],
    outputFormat: "json",
    parser: {
      resultsPath: "results.failed_checks",
      fieldMapping: {
        id: "check_id",
        severity: "severity",
        title: "check_id",
        description: "description",
        filePath: "file_path",
        startLine: "file_line_range[0]",
        endLine: "file_line_range[1]",
        recommendation: "guideline",
      },
      severityMapping: {
        CRITICAL: "critical",
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
        INFO: "info",
      },
    },
  },
  bandit: {
    category: "sast",
    command: "bandit",
    args: ["-r", "{{target}}", "-f", "json"],
    outputFormat: "json",
    parser: {
      resultsPath: "results",
      fieldMapping: {
        id: "test_id",
        severity: "issue_severity",
        title: "test_name",
        description: "issue_text",
        filePath: "filename",
        startLine: "line_number",
        recommendation: "more_info",
        snippet: "code",
      },
      severityMapping: {
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
      },
    },
  },
  njsscan: {
    category: "sast",
    command: "njsscan",
    args: ["--json", "-o", "-", "{{target}}"],
    outputFormat: "json",
    parser: {
      resultsPath: "nodejs",
      fieldMapping: {
        id: "metadata.owasp",
        severity: "metadata.severity",
        title: "metadata.description",
        description: "metadata.description",
        filePath: "files[0].file_path",
        startLine: "files[0].match_lines[0]",
        cweId: "metadata.cwe",
        recommendation: "metadata.description",
      },
    },
  },
};
