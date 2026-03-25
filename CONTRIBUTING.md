# Contributing to Mimir Scan

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/mimir-scan.git`
3. Install dependencies: `bun install`
4. Run tests: `bun test`

## Development Setup

### Prerequisites

- [Bun](https://bun.sh/) runtime
- For full testing, install the scanners:
  - Semgrep: `pip3 install semgrep`
  - Trivy: See [installation guide](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
  - Gitleaks: See [installation guide](https://github.com/gitleaks/gitleaks#installing)

### Running Locally

```bash
# Start the MCP server
bun run start

# Development mode with hot reload
bun run dev

# Run unit tests
bun test

# Run e2e tests (requires scanners installed)
bun run test:e2e

# Run e2e tests with Docker (all scanners included)
bun run test:e2e:docker
```

## Making Changes

### Code Style

- Use TypeScript for all source files
- Follow existing code patterns and naming conventions
- Keep functions focused and small
- Add JSDoc comments for public APIs

### Testing

- Add unit tests for new functionality in `*.test.ts` files
- Ensure all tests pass before submitting: `bun test`
- For scanner integrations, add test cases to `fixtures/`

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add new scanner support`
- `fix: handle edge case in prompt injection detection`
- `docs: update README with new examples`
- `test: add tests for SARIF export`

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/your-feature`
2. Make your changes and commit them
3. Push to your fork: `git push origin feat/your-feature`
4. Open a Pull Request against the `main` branch
5. Fill out the PR template with a clear description
6. Wait for review and address any feedback

## Adding New Scanners

To add a new scanner:

1. Create a new file in `src/scanners/` implementing the `Scanner` interface
2. Export it from `src/scanners/index.ts`
3. Add it to `ScanManager.initScanners()` in `src/scan-manager.ts`
4. Add test cases to `fixtures/`
5. Update the README with scanner details

## Adding New Prompt Injection Patterns

To add new detection patterns:

1. Edit `src/scanners/prompt-injection.ts`
2. Add patterns to the appropriate category array
3. Add test cases in `src/scanners/prompt-injection.test.ts`
4. Test with real-world examples in `fixtures/CLAUDE.md`

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Provide context about your environment

## License

By contributing, you agree that your contributions will be licensed under the ISC License.
