"""
Core scanner — walks files, applies rules + entropy check, returns findings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .entropy import high_entropy_strings
from .ignore import is_ignored, load_ignore_patterns
from .rules import RULES, Rule

MAX_FILE_BYTES = 1_000_000   # skip files > 1 MB (binaries, dumps)
MAX_LINE_LEN   = 2_000       # skip minified lines


@dataclass
class Finding:
    rule_id:     str
    rule_name:   str
    severity:    str
    file:        str
    line_number: int
    line:        str
    match:       str
    explanation: str
    fix:         str
    entropy:     Optional[float] = None   # set for entropy-only findings


@dataclass
class ScanResult:
    findings:     list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0


def scan_line(line: str, rule: Rule) -> Optional[str]:
    """Return the matched string if the rule fires on this line, else None."""
    m = rule.pattern.search(line)
    return m.group(0) if m else None


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []

    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return findings
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(path.relative_to(root))

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if len(line) > MAX_LINE_LEN:
            continue

        # 1. Rule-based detection
        for rule in RULES:
            match = scan_line(line, rule)
            if match:
                findings.append(Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file=rel,
                    line_number=lineno,
                    line=line.strip(),
                    match=match,
                    explanation=rule.explanation,
                    fix=rule.fix,
                ))

        # 2. Entropy-based detection (catches unknown secrets)
        for hit in high_entropy_strings(line):
            # Avoid duplicate: skip if a rule already flagged this line
            already_flagged = any(
                f.file == rel and f.line_number == lineno for f in findings
            )
            if not already_flagged:
                findings.append(Finding(
                    rule_id="HIGH_ENTROPY",
                    rule_name="High-Entropy String",
                    severity="MEDIUM",
                    file=rel,
                    line_number=lineno,
                    line=line.strip(),
                    match=hit["token"][:60] + ("…" if len(hit["token"]) > 60 else ""),
                    explanation=(
                        f"This string has unusually high entropy ({hit['entropy']} bits/char), "
                        "which is a strong indicator of a secret, key, or token."
                    ),
                    fix="Verify this is not a hardcoded secret. If it is, move it to an environment variable.",
                    entropy=hit["entropy"],
                ))

    return findings


def scan(target: str, include_entropy: bool = True) -> ScanResult:
    """
    Scan a file or directory tree.

    Parameters
    ----------
    target          : file or directory path
    include_entropy : whether to run entropy detection (default True)
    """
    result = ScanResult()
    root   = Path(target).resolve()

    if root.is_file():
        result.files_scanned += 1
        result.findings.extend(scan_file(root, root.parent))
        return result

    patterns = load_ignore_patterns(root)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place (prevents os.walk descending)
        dirnames[:] = [
            d for d in dirnames
            if not is_ignored(Path(dirpath) / d, root, patterns)
        ]

        for fname in filenames:
            fpath = Path(dirpath) / fname
            if is_ignored(fpath, root, patterns):
                result.files_skipped += 1
                continue
            result.files_scanned += 1
            result.findings.extend(scan_file(fpath, root))

    return result
