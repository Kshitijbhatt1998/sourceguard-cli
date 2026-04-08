# SourceGuard
**Catch hardcoded secrets before they leak.**

SourceGuard is a developer-first CLI tool that scans your codebase for API keys, passwords, and credentials — with plain-English explanations and actionable fixes, not just raw regex matches.

---

## Install

```bash
pip install sourceguard
```

Or run directly from the repo:

```bash
git clone https://github.com/Kshitijbhatt1998/sourceguard
cd sourceguard
pip install -e .
```

---

## Usage

```bash
# Scan current directory
sourceguard scan .

# Scan a specific file
sourceguard scan config.py

# Only report HIGH and CRITICAL
sourceguard scan . --severity HIGH

# Machine-readable JSON output
sourceguard scan . --json
```

---

## Example Output

```
🚨  2 secret(s) found  CRITICAL: 1  HIGH: 1

────────────────────────────────────────────────────────────

[CRITICAL] AWS Access Key ID
  File  : config.py:12
  Match : AKIAIOSFODNN7EXAMPLE
  Why   : AWS Access Key IDs grant programmatic access to your AWS account.
          If exposed, attackers can spin up resources, exfiltrate data, or run up bills.
  Fix   : Rotate the key immediately in AWS IAM → delete old key → update all services.

[HIGH] GitHub Token
  File  : scripts/deploy.py:45
  Match : ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456
  Why   : GitHub tokens can read private repos, push code, and access org data.
  Fix   : Revoke at github.com/settings/tokens. Use GitHub Actions secrets for CI.

────────────────────────────────────────────────────────────
Scanned 34 file(s), skipped 8.
```

---

## JSON Output

```bash
sourceguard scan . --json
```

```json
[
  {
    "rule_id": "AWS_ACCESS_KEY",
    "type": "AWS Access Key ID",
    "severity": "CRITICAL",
    "file": "config.py",
    "line": 12,
    "match": "AKIAIOSFODNN7EXAMPLE",
    "explanation": "AWS Access Key IDs grant programmatic access...",
    "fix": "Rotate the key immediately in AWS IAM..."
  }
]
```

---

## What It Detects

| Secret Type | Severity |
|:---|:---|
| AWS Access Key ID | CRITICAL |
| AWS Secret Access Key | CRITICAL |
| GCP Service Account Key | CRITICAL |
| Database connection strings | CRITICAL |
| PEM Private Keys | CRITICAL |
| Stripe Secret Key | CRITICAL |
| Azure Client Secret | CRITICAL |
| GitHub / GitLab tokens | HIGH |
| Slack tokens & webhooks | HIGH / MEDIUM |
| SendGrid / Twilio keys | HIGH |
| JWT secrets | HIGH |
| Generic API keys | MEDIUM |
| High-entropy strings | MEDIUM |

---

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

## Ignore Files

Create a `.sourceguardignore` in your project root:

```
# Ignore test fixtures
tests/fixtures/*

# Ignore vendor code
vendor/*
```

Copy `.sourceguardignore.example` to get started.

---

## GitHub Action

Add to `.github/workflows/sourceguard.yml`:

```yaml
name: SourceGuard Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install sourceguard
      - run: sourceguard scan . --severity HIGH
```

Exits `1` if secrets are found → blocks the PR merge.

---

## Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: sourceguard
        name: SourceGuard secret scan
        entry: sourceguard scan
        args: ["--severity", "HIGH"]
        language: system
        pass_filenames: false
```

---

## Exit Codes

| Code | Meaning |
|:---|:---|
| `0` | No secrets found |
| `1` | One or more secrets found |

---

## License

MIT
