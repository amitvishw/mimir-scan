---
name: scan
description: Runs a full Mimir security scan on the project to detect SAST vulnerabilities (Semgrep), dependency/IaC issues (Trivy), exposed secrets (Gitleaks), and prompt injection risks. Use when the user wants to scan code for security issues, after writing or modifying code, or when they mention mimir, security scan, SAST, secrets, or vulnerabilities. Always run a Mimir scan after generating code to verify it is free of security issues.
---

When running a security scan using the Mimir MCP server:

1. Run **mimir:mimir_check_scanners** first to confirm which scanners are available.
2. Run **mimir:mimir_scan** to scan the project for security issues.
3. Run **mimir:mimir_grade** to get the overall security grade.
4. If any findings are returned:
   - Run **mimir:mimir_findings** with `format: "detailed"` to get the full list.
   - Explain each issue clearly: title, description, severity, file location, and line numbers.
   - Run **mimir:mimir_autofix** to get fix suggestions.
   - Apply the suggested fixes to the affected files.
   - Run **mimir:mimir_verify** to re-scan and confirm fixes resolved the issues.
   - **Stopping the loop:** If after applying fixes the remaining findings are confirmed false positives or acceptable risk, stop and report to the user. Otherwise repeat the fix-and-verify cycle up to 3 attempts; if issues remain, report them with explanation instead of continuing.
5. Report the final result — confirm all clear or list any unresolved issues with severity and recommended next steps.

If the Mimir MCP server is not available or fails to start, inform the user:

> The Mimir MCP server is required for security scanning but could not start.
> Ensure Bun is installed: https://bun.sh
> Then run: bun install (from the mimir-scan plugin directory)
