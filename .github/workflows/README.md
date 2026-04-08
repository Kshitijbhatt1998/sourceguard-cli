# SourceGuard

Secret detection for developers. Scans source code for hardcoded credentials, API keys, tokens, and high-entropy strings before they reach production.

```
$ sourceguard scan .

7 secret(s) found  (CRITICAL: 2  HIGH: 1  MEDIUM: 4)

------------------------------------------------------------

[CRITICAL] AWS Access Key ID
  File  : config.py:14
  Match : AKIAIOSFODNN7EXAMPLE
  Why   : AWS Access Key IDs grant programmatic access to your AWS account.
  Fix   : Rotate immediately in AWS IAM. Delete old key. Update all services.
```

## Install

```bash
pip install sourceguard
```

Or from source:

```bash
git clone https://github.com/Kshitijbhatt1998/sourceguard-cli
cd sourceguard-cli
pip install -e .
```

## Usage

```bash
# Scan current directory
sourceguard scan .

# Scan a specific path
sourceguard scan src/

# JSON output (for CI pipelines)
sourceguard scan . --json

# Only report HIGH and CRITICAL findings
sourceguard scan . --severity HIGH

# Disable entropy detection (regex rules only)
sourceguard scan . --no-entropy
```

Exit code `1` if any findings match the severity threshold, `0` if clean.

## Detects

| Rule | Severity | Examples |
|------|----------|---------|
| AWS Access Key ID | CRITICAL | `AKIA...` |
| AWS Secret Access Key | CRITICAL | 40-char alphanumeric after `aws_secret` |
| Stripe Secret Key | CRITICAL | `sk_live_...`, `sk_test_...` |
| Database Connection String | CRITICAL | `postgres://user:pass@host` |
| Private Key / Certificate | CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| GitHub Token | HIGH | `ghp_...`, `gho_...`, `ghs_...` |
| Generic API Key | HIGH | `api_key = "..."` |
| JWT Secret | HIGH | `jwt_secret = "..."` |
| Generic Secret / Password | MEDIUM | `password = "..."`, `secret = "..."` |
| High-Entropy String | MEDIUM | Entropy ≥ 4.5 bits/char in quoted values |

## Ignoring Files

Create `.sourceguardignore` in your project root (gitignore syntax):

```
# Ignore test fixtures
tests/fixtures/
*.example
```

By default, `node_modules/`, `.git/`, lock files, and common binary extensions are ignored.

## GitHub Actions

Add to `.github/workflows/sourceguard.yml`:

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install sourceguard
      - run: sourceguard scan . --severity HIGH
```

Fails the build on HIGH or CRITICAL findings, blocking the merge.

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Kshitijbhatt1998/sourceguard-cli
    rev: v0.1.0
    hooks:
      - id: sourceguard
        args: [--severity, HIGH]
```

## License

MIT