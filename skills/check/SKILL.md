---
name: check
description: Checks which Mimir security scanners (Semgrep, Trivy, Gitleaks) are installed and available on the system. Use when the user asks about scanner status, setup, or installation requirements.
---

Run **mimir:mimir_check_scanners** and report which scanners are installed and which are missing.

For any missing scanners, provide the install command:

- **Semgrep**: `pip install semgrep` or `brew install semgrep`
- **Trivy**: `brew install trivy` (macOS) or https://github.com/aquasecurity/trivy/releases
- **Gitleaks**: `brew install gitleaks` (macOS) or https://github.com/gitleaks/gitleaks/releases
- **Prompt Injection**: built-in, no installation required

All four scanners are used by **mimir:mimir_scan**:
- **Semgrep** — SAST (static analysis for code vulnerabilities)
- **Trivy** — SCA + IaC (dependency vulnerabilities and infrastructure misconfigurations)
- **Gitleaks** — Secrets detection (hardcoded credentials, API keys)
- **Prompt Injection** — AI-specific attacks in config files and user-facing content
