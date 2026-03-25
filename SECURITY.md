# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainer directly or use GitHub's private vulnerability reporting
3. Include details about the vulnerability and steps to reproduce

We aim to respond within 48 hours and will work with you to understand and resolve the issue.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Best Practices

When using this tool:

- Run scans in read-only mode (`-v /path:/workspace:ro`) when using Docker
- Review auto-fix suggestions before applying them
- Keep scanners updated (Semgrep, Trivy, Gitleaks)
- Don't commit SARIF reports containing sensitive file paths to public repos
