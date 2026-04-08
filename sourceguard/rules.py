"""
Detection rules — regex patterns with severity, explanation, and fix suggestion.
Each rule is tried against every line of every scanned file.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Rule:
    id:          str
    name:        str
    pattern:     re.Pattern
    severity:    str          # CRITICAL | HIGH | MEDIUM | LOW
    explanation: str
    fix:         str
    confidence:  str = "HIGH" # HIGH | MEDIUM (medium = needs entropy check)


RULES: list[Rule] = [
    # ── Cloud providers ──────────────────────────────────────────── #
    Rule(
        id="AWS_ACCESS_KEY",
        name="AWS Access Key ID",
        pattern=re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        severity="CRITICAL",
        explanation="AWS Access Key IDs grant programmatic access to your AWS account. "
                    "If exposed, attackers can spin up resources, exfiltrate data, or run up bills.",
        fix="Rotate the key immediately in AWS IAM → delete old key → update all services.",
    ),
    Rule(
        id="AWS_SECRET_KEY",
        name="AWS Secret Access Key",
        pattern=re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
        severity="CRITICAL",
        explanation="AWS Secret Access Keys are the password to your AWS Access Key ID.",
        fix="Rotate immediately in AWS IAM. Never hardcode secrets — use environment variables or AWS Secrets Manager.",
    ),
    Rule(
        id="GCP_SERVICE_ACCOUNT",
        name="GCP Service Account Key",
        pattern=re.compile(r'"type"\s*:\s*"service_account"'),
        severity="CRITICAL",
        explanation="GCP service account credentials grant full API access scoped to the account's roles.",
        fix="Revoke the key in Google Cloud Console → IAM & Admin → Service Accounts. Use Workload Identity Federation instead.",
    ),
    Rule(
        id="AZURE_CLIENT_SECRET",
        name="Azure Client Secret",
        pattern=re.compile(r"(?i)(client.?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9_\-~.]{34,})['\"]?"),
        severity="CRITICAL",
        explanation="Azure client secrets authenticate service principals with access to Azure resources.",
        fix="Rotate in Azure Active Directory → App registrations → Certificates & secrets.",
    ),

    # ── Payment providers ────────────────────────────────────────── #
    Rule(
        id="STRIPE_SECRET_KEY",
        name="Stripe Secret Key",
        pattern=re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
        severity="CRITICAL",
        explanation="Stripe secret keys can create charges, access customer data, and issue refunds.",
        fix="Roll the key at dashboard.stripe.com/apikeys. Use restricted keys scoped to only what each service needs.",
    ),
    Rule(
        id="STRIPE_PUBLISHABLE_KEY",
        name="Stripe Publishable Key",
        pattern=re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}"),
        severity="LOW",
        explanation="Publishable keys are designed to be public, but exposing live keys in source can indicate poor secrets hygiene.",
        fix="No rotation needed, but move to an environment variable for consistency.",
    ),
    Rule(
        id="PAYPAL_SECRET",
        name="PayPal Client Secret",
        pattern=re.compile(r"(?i)paypal.{0,20}(secret|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{30,})['\"]?"),
        severity="CRITICAL",
        explanation="PayPal client secrets allow full API access to process payments and refunds.",
        fix="Regenerate at developer.paypal.com → My Apps → Credentials.",
    ),

    # ── Source control & CI ──────────────────────────────────────── #
    Rule(
        id="GITHUB_TOKEN",
        name="GitHub Token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
        severity="HIGH",
        explanation="GitHub tokens can read private repos, push code, and access org data depending on their scope.",
        fix="Revoke at github.com/settings/tokens. Use GitHub Actions secrets for CI workflows.",
    ),
    Rule(
        id="GITHUB_OAUTH",
        name="GitHub OAuth Token",
        pattern=re.compile(r"gho_[A-Za-z0-9]{36}"),
        severity="HIGH",
        explanation="OAuth tokens grant access on behalf of a GitHub user.",
        fix="Revoke at github.com/settings/applications.",
    ),
    Rule(
        id="GITLAB_TOKEN",
        name="GitLab Personal Access Token",
        pattern=re.compile(r"glpat-[A-Za-z0-9\-_]{20}"),
        severity="HIGH",
        explanation="GitLab PATs can access repos, CI pipelines, and registry packages.",
        fix="Revoke at gitlab.com/-/user_settings/personal_access_tokens.",
    ),

    # ── Messaging & communication ────────────────────────────────── #
    Rule(
        id="SLACK_TOKEN",
        name="Slack Bot/User Token",
        pattern=re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
        severity="HIGH",
        explanation="Slack tokens can read messages, post as the bot/user, and access workspace data.",
        fix="Revoke at api.slack.com/apps → OAuth & Permissions. Regenerate and store in environment variables.",
    ),
    Rule(
        id="SLACK_WEBHOOK",
        name="Slack Incoming Webhook",
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        severity="MEDIUM",
        explanation="Slack webhooks allow anyone with the URL to post messages to your channel.",
        fix="Revoke the webhook in Slack App settings and create a new one.",
    ),
    Rule(
        id="TWILIO_SID",
        name="Twilio Account SID",
        pattern=re.compile(r"AC[a-z0-9]{32}"),
        severity="HIGH",
        explanation="Combined with an Auth Token, this grants full Twilio API access (send SMS, make calls).",
        fix="Rotate Auth Token at console.twilio.com → Account → API keys.",
    ),
    Rule(
        id="SENDGRID_KEY",
        name="SendGrid API Key",
        pattern=re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
        severity="HIGH",
        explanation="SendGrid API keys can send email on your behalf and access contact lists.",
        fix="Revoke at app.sendgrid.com/settings/api_keys.",
    ),

    # ── Databases ────────────────────────────────────────────────── #
    Rule(
        id="DATABASE_URL",
        name="Database Connection String",
        pattern=re.compile(
            r"(?i)(postgres|mysql|mongodb|redis|sqlite)://[^:]+:[^@\s'\"]{6,}@[^\s'\"]+"
        ),
        severity="CRITICAL",
        explanation="Database URLs with credentials grant direct read/write access to your data.",
        fix="Move to an environment variable (DATABASE_URL). Rotate the password immediately.",
    ),

    # ── Private keys ─────────────────────────────────────────────── #
    Rule(
        id="PRIVATE_KEY",
        name="PEM Private Key",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        severity="CRITICAL",
        explanation="Private keys are used to authenticate servers, sign JWTs, and decrypt data.",
        fix="Revoke/replace the key pair. Never commit private keys — use a secrets vault.",
    ),
    Rule(
        id="JWT_SECRET",
        name="Hardcoded JWT Secret",
        pattern=re.compile(r"(?i)(jwt.?secret|SECRET_KEY)\s*[=:]\s*['\"]([^'\"]{16,})['\"]"),
        severity="HIGH",
        explanation="JWT secrets are used to sign tokens. Anyone with the secret can forge valid sessions.",
        fix="Move to an environment variable. Rotate the secret and invalidate existing tokens.",
    ),

    # ── Generic patterns (lower confidence) ──────────────────────── #
    Rule(
        id="GENERIC_API_KEY",
        name="Generic API Key",
        pattern=re.compile(
            r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"
        ),
        severity="MEDIUM",
        explanation="Hardcoded API keys can be extracted from source control history even after deletion.",
        fix="Move to an environment variable. Check the service's dashboard and rotate if compromised.",
        confidence="MEDIUM",
    ),
    Rule(
        id="GENERIC_SECRET",
        name="Generic Secret / Password",
        pattern=re.compile(
            r"(?i)(password|passwd|secret|token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
        ),
        severity="MEDIUM",
        explanation="Hardcoded passwords can be extracted from version control history.",
        fix="Move to an environment variable or secrets manager. Rotate if already committed.",
        confidence="MEDIUM",
    ),
]
