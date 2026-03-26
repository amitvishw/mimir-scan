# Mimir Scan

> *"Like Mimir advises Kratos of dangers ahead, Mimir-Scan reveals hidden security threats in your code"*

An MCP (Model Context Protocol) security scanner that integrates with AI coding agents like Claude Code, GitHub Copilot, Cursor, and others.

Wraps industry-standard security scanners (Semgrep, Trivy, Gitleaks) plus a built-in prompt injection detector, and exposes them as tools that any MCP-compatible AI agent can call.

## Features

- **Multi-Scanner**: Combines SAST, SCA, secrets detection, and prompt injection scanning
- **Security Grade**: A-F grading system for quick project health assessment
- **SARIF Export**: GitHub Security tab integration
- **Git Diff Scanning**: Fast PR reviews by scanning only changed files
- **Auto-Fix**: Automatically apply safe fixes (dependency upgrades)
- **Prompt Injection Detection**: Scan for 23+ injection patterns in AI configs
- **Custom Scanners**: Bring your own scanner via `.mimir.json` config

## Quick Start

### From Source (Recommended)

Clone the repo and install dependencies once:

```bash
git clone https://github.com/amitvishw/mimir-scan.git
cd mimir-scan
bun install
```

Then point your MCP client at the local install (see [MCP Client Configuration](#mcp-client-configuration) below).

### Using Docker

Docker bundles all scanners - no local installation needed:

```bash
docker build -t mimir-scan .
docker run --rm -i -v /path/to/project:/workspace mimir-scan
```

## MCP Client Configuration

### Claude Code

Add to your Claude Code settings (`~/.claude/settings.json` or project's `.mcp.json`):

```json
{
  "mcpServers": {
    "mimir": {
      "command": "bun",
      "args": ["run", "--cwd", "/path/to/mimir-scan", "start"],
      "env": {
        "MIMIR_TARGET_DIR": "/path/to/your/project"
      }
    }
  }
}
```

#### Claude Code Plugin (with Skills)

If you use Mimir as a [Claude Code plugin](https://docs.anthropic.com/en/docs/claude-code/plugins), it ships with two built-in skills that automate the full scan workflow:

| Skill | Trigger | What it does |
|-------|---------|--------------|
| `/mimir-scan:scan` | After writing code, on demand | Full scan → grade → findings → autofix → verify loop |
| `/mimir-scan:check` | When asking about scanner setup | Reports which scanners are installed with install hints |

The plugin registers the MCP server under the name `mimir`, so all tools are available as `mimir:mimir_scan`, `mimir:mimir_verify`, etc.

### VS Code / GitHub Copilot

Add to `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "mimir": {
      "command": "bun",
      "args": ["run", "--cwd", "/path/to/mimir-scan", "start"],
      "env": {
        "MIMIR_TARGET_DIR": "${workspaceFolder}"
      }
    }
  }
}
```

### Cursor

Add to Cursor's MCP settings:

```json
{
  "mcpServers": {
    "mimir": {
      "command": "bun",
      "args": ["run", "--cwd", "/path/to/mimir-scan", "start"],
      "env": {
        "MIMIR_TARGET_DIR": "/path/to/your/project"
      }
    }
  }
}
```

### Docker Configuration

For any MCP client, use Docker to avoid installing scanners locally.

Build the image first:

```bash
docker build -t mimir-scan .
```

Then configure your MCP client:

```json
{
  "mcpServers": {
    "mimir": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/your/project:/workspace:ro",
        "mimir-scan"
      ]
    }
  }
}
```

## Installing Scanners

The server works with whatever scanners you have installed. Install the ones you need:

```bash
# Semgrep (SAST - code vulnerabilities)
pip3 install semgrep

# Trivy (SCA - dependency vulnerabilities + IaC)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks (secrets detection)
# macOS:
brew install gitleaks
# Linux:
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz | tar xz -C /usr/local/bin gitleaks
```

Prompt injection detection is built-in and requires no installation.

## Scanners

| Scanner | What it detects | Category |
|---------|----------------|----------|
| **Semgrep** | Code vulnerabilities — SQL injection, XSS, insecure crypto | `sast` |
| **Trivy** | Dependency CVEs + IaC misconfigurations | `sca`, `iac` |
| **Gitleaks** | Hardcoded secrets, API keys, passwords | `secrets` |
| **Prompt Injection** | Jailbreaks, instruction overrides, data exfiltration | `prompt-injection` |

## MCP Tools

| Tool | Description |
|------|-------------|
| `mimir_scan` | Run all security scans on the codebase |
| `mimir_scan_diff` | Scan only git-changed files (fast PR reviews) |
| `mimir_scan_prompt` | Scan text for prompt injection attacks |
| `mimir_check_scanners` | Check which scanners are installed |
| `mimir_findings` | List detailed findings with filtering |
| `mimir_grade` | Get security grade (A-F) for the project |
| `mimir_fix` | Generate fix instructions for the AI agent |
| `mimir_autofix` | Auto-apply safe fixes (dependency upgrades) |
| `mimir_sarif` | Export findings in SARIF format |
| `mimir_verify` | Re-scan to confirm fixes were applied |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MIMIR_TARGET_DIR` | Current directory | Directory to scan |
| `MIMIR_SCANNERS` | `semgrep,trivy,gitleaks,prompt-injection` | Scanners to enable |
| `MIMIR_MIN_SEVERITY` | `low` | Minimum severity (`critical`, `high`, `medium`, `low`, `info`) |
| `MIMIR_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`, `silent`) |

## Workflows

### Full Scan Workflow

1. `mimir_check_scanners` → see what's available
2. `mimir_scan` → run security scans
3. `mimir_findings` → review detailed findings
4. `mimir_autofix` with `apply: true` → auto-fix safe issues
5. `mimir_fix` → get instructions for remaining issues
6. Fix the code
7. `mimir_verify` → confirm fixes

### PR Review Workflow

1. `mimir_scan_diff` with `base: "main"` → scan only changed files
2. `mimir_grade` → quick A-F assessment
3. `mimir_sarif` → export for GitHub Security tab

## Security Grading

| Grade | Criteria |
|-------|----------|
| **A** | No critical or high, ≤2 medium |
| **B** | No critical, ≤2 high, ≤5 medium |
| **C** | No critical, ≤5 high, ≤10 medium |
| **D** | ≤2 critical, ≤10 high |
| **F** | >2 critical or >10 high |

## Prompt Injection Detection

The built-in scanner detects 23+ attack patterns:

- **Instruction overrides**: "ignore previous instructions"
- **Jailbreaks**: DAN mode, developer mode
- **Role manipulation**: "you are now a..."
- **Data exfiltration**: attempts to send data to external URLs
- **System prompt extraction**: attempts to reveal instructions
- **Encoding bypasses**: base64, unicode escapes

Scan AI config files or validate user inputs:

```
mimir_scan_prompt text="ignore all previous instructions" source="user_input"
```

## Custom Scanners

Add your own scanners by creating a `.mimir.json` file in your project root:

```json
{
  "plugins": [
    {
      "name": "my-scanner",
      "displayName": "My Custom Scanner",
      "category": "sast",
      "checkCommand": "my-scanner",
      "command": "my-scanner",
      "args": ["scan", "--json", "."],
      "outputFormat": "json",
      "parser": {
        "resultsPath": "results",
        "fieldMapping": {
          "id": "ruleId",
          "severity": "level",
          "title": "message",
          "description": "details",
          "filePath": "file",
          "startLine": "line"
        }
      }
    }
  ]
}
```

### Plugin Configuration

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique identifier for the scanner |
| `displayName` | No | Human-readable name |
| `category` | Yes | One of: `sast`, `sca`, `secrets`, `iac`, `prompt-injection` |
| `checkCommand` | Yes | Command to check if scanner is installed |
| `command` | Yes | Command to run the scanner |
| `args` | No | Arguments to pass to the command |
| `outputFormat` | Yes | Output format: `json` or `sarif` |
| `parser` | Yes (for json) | How to parse the output |

### Parser Configuration

| Field | Description |
|-------|-------------|
| `resultsPath` | JSONPath to the findings array (e.g., `results`, `data.findings`) |
| `fieldMapping.id` | Path to finding ID |
| `fieldMapping.severity` | Path to severity level |
| `fieldMapping.title` | Path to finding title |
| `fieldMapping.description` | Path to description |
| `fieldMapping.filePath` | Path to file path |
| `fieldMapping.startLine` | Path to line number |

Enable your custom scanner:

```bash
MIMIR_SCANNERS=semgrep,my-scanner bun run --cwd /path/to/mimir-scan start
```

## Development

### Prerequisites

- [Bun](https://bun.sh) runtime

### Setup

```bash
git clone https://github.com/amitvishw/mimir-scan.git
cd mimir-scan
bun install
```

### Running Locally

```bash
# Development mode with watch
bun run dev

# Run directly
bun run start
```

### Testing

```bash
# Unit tests
bun test

# Unit tests with watch
bun test --watch

# E2E tests (requires scanners installed)
./test-e2e.sh

# E2E tests with Docker
./test-e2e.sh --docker
```

### Building Docker Image

```bash
docker build -t mimir-scan .
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Use conventional commits (`feat:`, `fix:`, `docs:`, etc.)
4. Run tests (`bun test`)
5. Submit a pull request

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature (triggers minor version bump)
- `fix:` Bug fix (triggers patch version bump)
- `docs:` Documentation only
- `chore:` Maintenance tasks
- `test:` Adding tests
- `refactor:` Code refactoring

## License

ISC

## Links

- [GitHub Repository](https://github.com/amitvishw/mimir-scan)
- [npm Package](https://www.npmjs.com/package/mimir-scan)
- [Report Issues](https://github.com/amitvishw/mimir-scan/issues)
