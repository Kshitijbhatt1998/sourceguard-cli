"""Formatted terminal output and JSON serialisation."""

import json
import sys
from .scanner import Finding, ScanResult

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[33m",   # yellow
    "MEDIUM":   "\033[36m",   # cyan
    "LOW":      "\033[37m",   # white
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _color(text: str, severity: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{SEVERITY_COLOR.get(severity, '')}{text}{RESET}"


def _bold(text: str) -> str:
    return f"{BOLD}{text}{RESET}" if sys.stdout.isatty() else text


def print_results(result: ScanResult, target: str) -> None:
    findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    if result.clean:
        print(f"\n✅  {_bold('No secrets found.')}  Scanned {result.files_scanned} file(s).\n")
        return

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = "  ".join(
        f"{_color(sev, sev)}: {n}"
        for sev, n in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))
    )
    print(f"\n🚨  {_bold(f'{len(findings)} secret(s) found')}  ({summary})\n")
    print(f"{'─' * 60}")

    for f in findings:
        label = _color(f"[{f.severity}]", f.severity)
        print(f"\n{label} {_bold(f.rule_name)}")
        print(f"  File  : {f.file}:{f.line_number}")
        print(f"  Match : {f.match[:120]}")
        print(f"  Why   : {f.explanation}")
        print(f"  Fix   : {_bold(f.fix)}")
        if f.entropy:
            print(f"  Entropy: {f.entropy} bits/char")

    print(f"\n{'─' * 60}")
    print(f"Scanned {result.files_scanned} file(s), skipped {result.files_skipped}.\n")


def print_json(result: ScanResult) -> None:
    out = [
        {
            "rule_id":     f.rule_id,
            "type":        f.rule_name,
            "severity":    f.severity,
            "file":        f.file,
            "line":        f.line_number,
            "match":       f.match,
            "explanation": f.explanation,
            "fix":         f.fix,
            **({"entropy": f.entropy} if f.entropy else {}),
        }
        for f in sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    ]
    print(json.dumps(out, indent=2))
