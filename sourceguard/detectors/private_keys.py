import re
from typing import List, Dict, Any
from .base import RegexDetector

class PrivateKeyDetector(RegexDetector):
    @property
    def detector_id(self) -> str:
        return "PrivateKey"

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "PEM Private Key",
                "pattern": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                "severity": "CRITICAL",
                "message": "Private keys are used to authenticate servers, sign JWTs, and decrypt data.",
                "suggestion": "Revoke/replace the key pair. Never commit private keys — use a secrets vault."
            }
        ]
