import type { Finding, FindingCategory, Severity } from "../../types";
import { generateFindingId } from "../../utils";
import { logger } from "../../logger";

interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  fullDescription?: { text: string };
  properties?: {
    "security-severity"?: string;
  };
}

interface SarifInput {
  runs?: {
    tool?: {
      driver?: {
        rules?: SarifRule[];
      };
    };
    results?: {
      ruleId: string;
      level?: string;
      message?: { text: string };
      locations?: {
        physicalLocation?: {
          artifactLocation?: { uri: string };
          region?: {
            startLine?: number;
            endLine?: number;
          };
        };
      }[];
    }[];
  }[];
}

/**
 * Parse SARIF format output from any tool
 */
export function parseSarif(
  output: string,
  scannerName: string,
  category: FindingCategory
): Finding[] {
  try {
    const sarif: SarifInput = JSON.parse(output);
    const findings: Finding[] = [];

    for (const run of sarif.runs ?? []) {
      const rules = new Map<string, SarifRule>();

      // Index rules by ID for lookup
      for (const rule of run.tool?.driver?.rules ?? []) {
        rules.set(rule.id, rule);
      }

      for (const result of run.results ?? []) {
        const rule = rules.get(result.ruleId);
        const location = result.locations?.[0]?.physicalLocation;
        const filePath = location?.artifactLocation?.uri ?? "unknown";
        const startLine = location?.region?.startLine;

        const severity = mapSarifLevel(result.level, rule?.properties?.["security-severity"]);

        findings.push({
          id: generateFindingId(scannerName, filePath, startLine ?? 0, result.ruleId),
          scanner: scannerName,
          category,
          severity,
          title: rule?.name ?? rule?.shortDescription?.text ?? result.ruleId,
          description:
            result.message?.text ??
            rule?.fullDescription?.text ??
            rule?.shortDescription?.text ??
            "",
          filePath,
          startLine,
          endLine: location?.region?.endLine,
          recommendation: `Fix the issue identified by rule: ${result.ruleId}`,
        });
      }
    }

    return findings;
  } catch (err) {
    logger.error("Failed to parse SARIF output", err);
    return [];
  }
}

function mapSarifLevel(level?: string, securitySeverity?: string): Severity {
  // Use security-severity if available (CVSS-like score)
  if (securitySeverity) {
    const score = parseFloat(securitySeverity);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    if (score >= 0.1) return "low";
    return "info";
  }

  // Fall back to SARIF level
  switch (level?.toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    case "none":
      return "info";
    default:
      return "medium";
  }
}
