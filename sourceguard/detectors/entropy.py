import math
import re
from typing import List, Dict, Any
from .base import BaseDetector
from ..models import Finding

class EntropyDetector(BaseDetector):
    # Characters common in base64/hex secrets
    _B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    _HEX = "0123456789abcdefABCDEF"
    
    ENTROPY_THRESHOLD = 4.5
    MIN_LENGTH = 20
    MAX_LENGTH = 120

    @property
    def detector_id(self) -> str:
        return "Entropy"

    def _shannon(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())

    def detect(self, line: str, file_path: str, line_number: int) -> List[Finding]:
        findings = []
        # Pattern to find potential tokens in quotes or as word chunks
        pat = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{%d,%d})['"]|(?<![.\w])([A-Za-z0-9+/=_\-]{%d,%d})(?![.\w])""" % (self.MIN_LENGTH, self.MAX_LENGTH, self.MIN_LENGTH, self.MAX_LENGTH))
        
        for m in pat.finditer(line):
            token = m.group(1) or m.group(2)
            if not token:
                continue
                
            b64r = sum(1 for c in token if c in self._B64) / len(token)
            hexr = sum(1 for c in token if c in self._HEX) / len(token)
            
            # Focus on things that look like base64 or hex
            if b64r < 0.6 and hexr < 0.8:
                continue
                
            e = self._shannon(token)
            if e >= self.ENTROPY_THRESHOLD:
                findings.append(Finding(
                    detector_id=self.detector_id,
                    rule_name="High-Entropy String",
                    severity="MEDIUM",
                    file=file_path,
                    line_number=line_number,
                    line_content=line.strip(),
                    match_text=token[:60] + ("…" if len(token) > 60 else ""),
                    explanation=f"This string has unusually high entropy ({round(e, 2)} bits/char), which is a strong indicator of a secret, key, or token.",
                    fix_suggestion="Verify this is not a hardcoded secret. If it is, move it to an environment variable.",
                    entropy=round(e, 2)
                ))
        return findings
