# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Claude Code Plugin skills**: `/mimir-scan:scan` runs the full scan → fix → verify workflow automatically; `/mimir-scan:check` reports scanner availability with install hints
- **`check` skill**: expanded with descriptions of all four scanners and their detection categories

### Changed

- MCP server key renamed from `mimir-scan` to `mimir` in `.mcp.json`, consistent with the README examples and all other MCP client configs. Tool names in Claude Code simplify from `plugin:mimir-scan:mimir-scan - mimir_*` to `plugin:mimir-scan:mimir - mimir_*`

### Fixed

- Trivy scan now retries without `--skip-db-update` when the vulnerability database has not been downloaded yet, preventing a failure on first run
---

## [0.1.0] - 2026-03-23

### Added

- Initial release
- **Scanners**
  - Semgrep integration for SAST (code vulnerability detection)
  - Trivy integration for SCA (dependency vulnerabilities) and IaC scanning
  - Gitleaks integration for secrets detection
  - Built-in prompt injection scanner with 23+ detection patterns
- **MCP Tools**
  - `mimir_scan` - Run all security scans on the codebase
  - `mimir_scan_diff` - Scan only git-changed files for fast PR reviews
  - `mimir_scan_prompt` - Scan text for prompt injection attacks
  - `mimir_check_scanners` - Check which scanners are installed
  - `mimir_findings` - List findings with filtering by severity, category, file
  - `mimir_grade` - Get security grade (A-F) for the project
  - `mimir_fix` - Generate fix instructions for the AI agent
  - `mimir_autofix` - Generate and apply safe auto-fixes
  - `mimir_sarif` - Export findings in SARIF 2.1.0 format
  - `mimir_verify` - Re-scan to verify fixes were applied
- **Features**
  - Security grading system (A-F based on finding severity)
  - SARIF 2.1.0 export for GitHub Security tab integration
  - Auto-fix support for dependency upgrades
  - Git diff scanning for efficient PR reviews
  - Docker image with all scanners pre-installed
- **Documentation**
  - Comprehensive README with setup instructions
  - Integration guides for Claude Code, VS Code/Copilot, and Cursor
  - Environment variable configuration

### Security

- Prompt injection detection for AI configuration files
- Scans CLAUDE.md, .cursorrules, and other AI instruction files
