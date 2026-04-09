from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Finding:
    detector_id: str
    rule_name: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    file: str
    line_number: int
    line_content: str
    match_text: str
    explanation: str
    fix_suggestion: str
    entropy: Optional[float] = None
    
    # For SaaS/Backend enrichment
    risk_score: Optional[float] = None
    secret_hash: Optional[str] = None  # SHA256 of the match (for deduplication)
    masked_match: Optional[str] = None # e.g. AKIA****

@dataclass
class ScanResult:
    target_path: str
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    duration_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def is_clean(self) -> bool:
        return self.total_findings == 0
