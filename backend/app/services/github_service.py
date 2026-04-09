"""
Clone a GitHub repo, run the SourceGuard scanner, persist findings.
Intended to run as a FastAPI BackgroundTask — NOT on the main request thread.
"""

import datetime
import hashlib
import subprocess
import tempfile
import uuid
from pathlib import Path

from ..db.models import Finding, ProjectRiskSnapshot, Scan, ScanStatus
from ..db.session import get_sync_session


def _mask(match: str) -> str:
    """Show first 4 and last 4 chars, mask the rest."""
    if len(match) <= 8:
        return "****"
    return match[:4] + ("*" * (len(match) - 8)) + match[-4:]


def run_github_scan(scan_id: str, repo_url: str) -> None:
    """Entry point called by BackgroundTasks."""
    # Import here to avoid circular imports at startup
    from sourceguard.scanner import scan as sg_scan

    with tempfile.TemporaryDirectory() as tmpdir:
        clone_path = Path(tmpdir) / "repo"

        proc = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_path)],
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            _fail_scan(scan_id)
            return

        try:
            scan_result = sg_scan(str(clone_path))
        except Exception:
            _fail_scan(scan_id)
            return

    _persist_results(scan_id, scan_result)


def _fail_scan(scan_id: str) -> None:
    with get_sync_session() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if scan:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.datetime.utcnow()
            session.add(scan)
            session.commit()


def _persist_results(scan_id: str, scan_result) -> None:
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_risk = 0

    with get_sync_session() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if not scan:
            return

        for f in scan_result.findings:
            sev = f.severity.upper()
            total_risk += severity_weights.get(sev, 1)
            counts[sev] = counts.get(sev, 0) + 1

            finding = Finding(
                scan_id=scan.id,
                project_id=scan.project_id,
                type=f.rule_name,
                severity=sev,
                file_path=f.file,
                line_number=f.line_number,
                match_masked=_mask(f.match),
                hash=hashlib.sha256(f.match.encode()).hexdigest(),
                message=f.explanation,
                suggestion=f.fix,
                entropy=f.entropy,
            )
            session.add(finding)

        scan.status = ScanStatus.COMPLETED
        scan.total_findings = len(scan_result.findings)
        scan.total_files = scan_result.files_scanned
        scan.risk_score = total_risk
        scan.completed_at = datetime.datetime.utcnow()
        session.add(scan)

        session.add(
            ProjectRiskSnapshot(
                project_id=scan.project_id,
                total_findings=len(scan_result.findings),
                critical_count=counts["CRITICAL"],
                high_count=counts["HIGH"],
                medium_count=counts["MEDIUM"],
                low_count=counts["LOW"],
                risk_score=total_risk,
            )
        )
        session.commit()
