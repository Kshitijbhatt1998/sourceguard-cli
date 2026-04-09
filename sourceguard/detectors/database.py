import re
from typing import List, Dict, Any
from .base import RegexDetector

class DatabaseDetector(RegexDetector):
    @property
    def detector_id(self) -> str:
        return "Database"

    @property
    def rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Database Connection String",
                "pattern": re.compile(r"(?i)(postgres|mysql|mongodb|redis|sqlite)://[^:]+:[^@\s'\"]{6,}@[^\s'\"]+"),
                "severity": "CRITICAL",
                "message": "Database URLs with credentials grant direct read/write access to your data.",
                "suggestion": "Move to an environment variable (DATABASE_URL). Rotate the password immediately."
            }
        ]
