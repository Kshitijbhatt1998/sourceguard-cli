import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..models import Finding

class BaseDetector(ABC):
    @property
    @abstractmethod
    def detector_id(self) -> str:
        pass

    @abstractmethod
    def detect(self, line: str, file_path: str, line_number: int) -> List[Finding]:
        """Runs detection on a single line of text."""
        pass

class RegexDetector(BaseDetector):
    """Base class for detectors that use a set of regex patterns."""
    
    @property
    @abstractmethod
    def rules(self) -> List[Dict[str, Any]]:
        """
        Expected format:
        [
            {
                "name": "rule_name",
                "pattern": re.Pattern,
                "severity": "HIGH",
                "message": "...",
                "suggestion": "..."
            }
        ]
        """
        pass

    def detect(self, line: str, file_path: str, line_number: int) -> List[Finding]:
        findings = []
        for rule in self.rules:
            match = rule["pattern"].search(line)
            if match:
                findings.append(Finding(
                    detector_id=self.detector_id,
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    file=file_path,
                    line_number=line_number,
                    line_content=line.strip(),
                    match_text=match.group(0),
                    explanation=rule["message"],
                    fix_suggestion=rule["suggestion"]
                ))
        return findings
