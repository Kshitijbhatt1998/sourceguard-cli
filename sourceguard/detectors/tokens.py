import re
from typing import List, Dict, Any
from .base import RegexDetector

class TokenDetector(RegexDetector):
    @property
    def detector_id(self) -> str:
        return "Tokens"

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "GCP Service Account Key",
                "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
                "severity": "CRITICAL",
                "message": "GCP service account credentials grant full API access scoped to the account's roles.",
                "suggestion": "Revoke the key in Google Cloud Console → IAM & Admin → Service Accounts. Use Workload Identity Federation instead."
            },
            {
                "name": "Azure Client Secret",
                "pattern": re.compile(r"(?i)(client.?secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9_\-~.]{34,})['\"]?"),
                "severity": "CRITICAL",
                "message": "Azure client secrets authenticate service principals with access to Azure resources.",
                "suggestion": "Rotate in Azure Active Directory → App registrations → Certificates & secrets."
            },
            {
                "name": "PayPal Client Secret",
                "pattern": re.compile(r"(?i)paypal.{0,20}(secret|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{30,})['\"]?"),
                "severity": "CRITICAL",
                "message": "PayPal client secrets allow full API access to process payments and refunds.",
                "suggestion": "Regenerate at developer.paypal.com → My Apps → Credentials."
            },
            {
                "name": "GitHub Token",
                "pattern": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
                "severity": "HIGH",
                "message": "GitHub tokens can read private repos, push code, and access org data depending on their scope.",
                "suggestion": "Revoke at github.com/settings/tokens. Use GitHub Actions secrets for CI workflows."
            },
            {
                "name": "Slack Bot/User Token",
                "pattern": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
                "severity": "HIGH",
                "message": "Slack tokens can read messages, post as the bot/user, and access workspace data.",
                "suggestion": "Revoke at api.slack.com/apps → OAuth & Permissions. Regenerate and store in environment variables."
            },
            {
                "name": "Twilio Account SID",
                "pattern": re.compile(r"AC[a-z0-9]{32}"),
                "severity": "HIGH",
                "message": "Twilio Account SIDs combined with an Auth Token grant full Twilio API access.",
                "suggestion": "Rotate Auth Token at console.twilio.com → Account → API keys."
            },
            {
                "name": "SendGrid API Key",
                "pattern": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
                "severity": "HIGH",
                "message": "SendGrid API keys can send email on your behalf and access contact lists.",
                "suggestion": "Revoke at app.sendgrid.com/settings/api_keys."
            },
            {
                "name": "Hardcoded JWT Secret",
                "pattern": re.compile(r"(?i)(jwt.?secret|SECRET_KEY)\s*[=:]\s*['\"]([^'\"]{16,})['\"]"),
                "severity": "HIGH",
                "message": "JWT secrets are used to sign tokens. Anyone with the secret can forge valid sessions.",
                "suggestion": "Move to an environment variable. Rotate the secret and invalidate existing tokens."
            },
            {
                "name": "Generic API Key",
                "pattern": re.compile(r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]"),
                "severity": "MEDIUM",
                "message": "Hardcoded API keys can be extracted from source control history even after deletion.",
                "suggestion": "Move to an environment variable. Check the service's dashboard and rotate if compromised."
            }
        ]
