import re
from typing import List, Dict, Any
from .base import RegexDetector

class StripeDetector(RegexDetector):
    @property
    def detector_id(self) -> str:
        return "Stripe"

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Stripe Secret Key",
                "pattern": re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
                "severity": "CRITICAL",
                "message": "Stripe secret keys can create charges, access customer data, and issue refunds.",
                "suggestion": "Roll the key at dashboard.stripe.com/apikeys. Use restricted keys scoped to only what each service needs."
            },
            {
                "name": "Stripe Publishable Key",
                "pattern": re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}"),
                "severity": "LOW",
                "message": "Publishable keys are designed to be public, but exposing live keys in source can indicate poor secrets hygiene.",
                "suggestion": "No rotation needed, but move to an environment variable for consistency."
            }
        ]
