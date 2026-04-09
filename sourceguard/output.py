import json
import sys
from typing import List
from .models import Finding, ScanResult

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

def print_results(result: ScanResult) -> None:
    findings = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    if result.is_clean:
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
        print(f"  Detector: {f.detector_id}")
        print(f"  File     : {f.file}:{f.line_number}")
        print(f"  Match    : {f.match_text[:120]}")
        print(f"  Why      : {f.explanation}")
        print(f"  Fix      : {_bold(f.fix_suggestion)}")
        if f.entropy:
            print(f"  Entropy  : {f.entropy} bits/char")

    print(f"\n{'─' * 60}")
    print(f"Scanned {result.files_scanned} file(s), skipped {result.files_skipped} (Duration: {result.duration_seconds}s).\n")

def print_json(result: ScanResult) -> None:
    export_data = {
        "target": result.target_path,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "duration": result.duration_seconds,
        "findings": [
            {
                "detector_id": f.detector_id,
                "rule": f.rule_name,
                "severity": f.severity,
                "file": f.file,
                "line": f.line_number,
                "match": f.match_text,
                "explanation": f.explanation,
                "fix": f.fix_suggestion,
                "entropy": f.entropy
            }
            for f in result.findings
        ]
    }
    print(json.dumps(export_data, indent=2))

def generate_html_report(result: ScanResult, output_path: str) -> None:
    # Basic HTML report generator stub
    html_content = f"""
    <html>
    <head>
        <title>SourceGuard Report</title>
        <style>
            body {{ font-family: sans-serif; margin: 2rem; background: #1a1a1a; color: #eee; }}
            .finding {{ border: 1px solid #444; padding: 1rem; margin-bottom: 1rem; border-radius: 8px; }}
            .CRITICAL {{ border-left: 5px solid #ff4444; }}
            .HIGH {{ border-left: 5px solid #ffbb33; }}
            .MEDIUM {{ border-left: 5px solid #0099cc; }}
            .LOW {{ border-left: 5px solid #999; }}
            h1 {{ color: #fff; }}
        </style>
    </head>
    <body>
        <h1>SourceGuard Scan Report</h1>
        <p>Target: {result.target_path}</p>
        <p>Files Scanned: {result.files_scanned} | Duration: {result.duration_seconds}s</p>
        <hr>
        {"".join([f'<div class="finding {f.severity}"><h3>[{f.severity}] {f.rule_name}</h3><p>File: {f.file}:{f.line_number}</p><p>Match: <code>{f.match_text}</code></p></div>' for f in result.findings])}
    </body>
    </html>
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"Report generated: {output_path}")
