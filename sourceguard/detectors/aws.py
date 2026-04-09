import re
from typing import List, Dict, Any
from .base import RegexDetector

class AWSDetector(RegexDetector):
    @property
    def detector_id(self) -> str:
        return "AWS"

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "AWS Access Key ID",
                "pattern": re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
                "severity": "CRITICAL",
                "message": "AWS Access Key IDs grant programmatic access to your AWS account. If exposed, attackers can spin up resources, exfiltrate data, or run up bills.",
                "suggestion": "Rotate the key immediately in AWS IAM → delete old key → update all services."
            },
            {
                "name": "AWS Secret Access Key",
                "pattern": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
                "severity": "CRITICAL",
                "message": "AWS Secret Access Keys are the password to your AWS Access Key ID.",
                "suggestion": "Rotate immediately in AWS IAM. Never hardcode secrets — use environment variables or AWS Secrets Manager."
            }
        ]
