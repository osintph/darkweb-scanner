# Contributing to Dark Web Scanner

Thank you for considering contributing! This document explains how to get involved.

---

## Code of Conduct

Be respectful and constructive. This project exists for legitimate security research — contributions that attempt to facilitate illegal activity will be rejected and reported.

---

## Getting Started

```bash
git clone https://github.com/osintph/darkweb-scanner
cd darkweb-scanner
make dev-install   # installs all dev dependencies
make setup         # creates config files from examples
make test          # verify everything works
```

---

## How to Contribute

### Reporting Bugs

Open an issue using the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:
- OS and Python version
- Exact steps to reproduce
- Relevant log output

### Suggesting Features

Open an issue using the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).

### Submitting a Pull Request

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Make your changes
4. Add or update tests as needed
5. Run `make lint` and `make test` — both must pass
6. Commit with a descriptive message (see below)
7. Push and open a PR against `main`

---

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add regex keyword support
fix: handle timeout errors in crawler
docs: update deployment guide
test: add scanner edge case tests
chore: bump aiohttp to 3.10
```

---

## Code Style

- Formatted with `ruff format` (run `make format`)
- Linted with `ruff` and `mypy` (run `make lint`)
- Type hints on all public functions
- Docstrings on all public classes and methods

---

## Testing

- Unit tests live in `tests/unit/` — these run in CI and don't require Tor
- Integration tests live in `tests/integration/` — require a live Tor daemon (`TOR_INTEGRATION=1`)
- Aim for test coverage on any new functionality
- Run tests: `make test`

---

## Security Issues

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
