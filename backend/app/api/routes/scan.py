import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, col, select

from ...core.security import get_current_user, get_current_user_jwt
from ...db.models import (
    Finding,
    Membership,
    Organization,
    Project,
    ProjectRiskSnapshot,
    Role,
    Scan,
    ScanStatus,
    User,
)
from ...db.session import get_session

router = APIRouter(prefix="/scan", tags=["scan"])


# ---------------------------------------------------------------------------
# Request models (CLI upload)
# ---------------------------------------------------------------------------

class FindingCreate(BaseModel):
    rule_name: str
    severity: str
    file: str
    line: int
    explanation: str
    fix: str
    masked_secret: str
    secret_hash: str
    entropy: Optional[float] = None


class ScanCreate(BaseModel):
    project_id: Optional[str] = "local-scan"
    findings: List[FindingCreate]


# ---------------------------------------------------------------------------
# CLI: POST /scan/ — upload findings from the CLI
# ---------------------------------------------------------------------------

@router.post("/")
def create_scan(
    data: ScanCreate,
    user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    # 1. Auto-provision Organization
    org = session.exec(
        select(Organization).join(Membership).where(Membership.user_id == user.id)
    ).first()
    if not org:
        org = Organization(name="Personal")
        session.add(org)
        session.commit()
        session.refresh(org)
        session.add(Membership(user_id=user.id, organization_id=org.id, role=Role.OWNER))
        session.commit()

    # 2. Auto-provision Project
    p_name = data.project_id or "local-scan"
    project = session.exec(
        select(Project).where(Project.organization_id == org.id, Project.name == p_name)
    ).first()
    if not project:
        project = Project(organization_id=org.id, name=p_name)
        session.add(project)
        session.commit()
        session.refresh(project)

    # 3. Create Scan
    scan = Scan(project_id=project.id, triggered_by=user.id, status=ScanStatus.RUNNING)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # 4. Risk scoring + findings
    severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_risk = 0

    for f in data.findings:
        sev = f.severity.upper()
        total_risk += severity_weights.get(sev, 1)
        counts[sev] = counts.get(sev, 0) + 1
        session.add(Finding(
            scan_id=scan.id,
            project_id=project.id,
            type=f.rule_name,
            severity=sev,
            file_path=f.file,
            line_number=f.line,
            match_masked=f.masked_secret,
            hash=f.secret_hash,
            message=f.explanation,
            suggestion=f.fix,
            entropy=f.entropy,
        ))

    # 5. Finalise scan
    scan.risk_score = total_risk
    scan.total_findings = len(data.findings)
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.utcnow()
    session.add(scan)

    # 6. Risk snapshot
    session.add(ProjectRiskSnapshot(
        project_id=project.id,
        total_findings=len(data.findings),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        risk_score=total_risk,
    ))
    session.commit()

    return {
        "scan_id": str(scan.id),
        "risk_score": total_risk,
        "findings_count": len(data.findings),
        "organization": org.name,
        "project": project.name,
    }


# ---------------------------------------------------------------------------
# Dashboard: GET /scan/projects — list projects (JWT auth)
# ---------------------------------------------------------------------------

@router.get("/projects")
def list_projects(
    user: User = Depends(get_current_user_jwt),
    session: Session = Depends(get_session),
):
    org = session.exec(
        select(Organization).join(Membership).where(Membership.user_id == user.id)
    ).first()
    if not org:
        return []

    projects = session.exec(
        select(Project).where(Project.organization_id == org.id)
    ).all()

    return [
        {
            "id": str(p.id),
            "name": p.name,
            "repo_url": p.repo_url,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        for p in projects
    ]


# ---------------------------------------------------------------------------
# Dashboard: GET /scan/ — list recent scans (JWT auth)
# ---------------------------------------------------------------------------

@router.get("/")
def list_scans(
    user: User = Depends(get_current_user_jwt),
    session: Session = Depends(get_session),
):
    org = session.exec(
        select(Organization).join(Membership).where(Membership.user_id == user.id)
    ).first()
    if not org:
        return []

    project_ids = [
        p.id for p in session.exec(
            select(Project).where(Project.organization_id == org.id)
        ).all()
    ]
    if not project_ids:
        return []

    scans = session.exec(
        select(Scan)
        .where(col(Scan.project_id).in_(project_ids))
        .order_by(col(Scan.started_at).desc())
        .limit(100)
    ).all()

    # Build a project-name lookup
    projects = {
        p.id: p.name for p in session.exec(
            select(Project).where(col(Project.id).in_(project_ids))
        ).all()
    }

    return [
        {
            "id": str(s.id),
            "project_id": str(s.project_id),
            "project_name": projects.get(s.project_id, ""),
            "source": s.source,
            "status": s.status,
            "total_findings": s.total_findings,
            "risk_score": s.risk_score,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in scans
    ]


# ---------------------------------------------------------------------------
# Dashboard: GET /scan/{scan_id}/findings (JWT auth)
# ---------------------------------------------------------------------------

@router.get("/{scan_id}/findings")
def get_findings(
    scan_id: str,
    _user: User = Depends(get_current_user_jwt),
    session: Session = Depends(get_session),
):
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID.")

    scan = session.get(Scan, sid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan.id)
    ).all()

    return [
        {
            "id": str(f.id),
            "type": f.type,
            "severity": f.severity,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "match_masked": f.match_masked,
            "message": f.message,
            "suggestion": f.suggestion,
            "entropy": f.entropy,
            "is_resolved": f.is_resolved,
        }
        for f in findings
    ]
