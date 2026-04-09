from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select
from pydantic import BaseModel

from ...db.models import Project, Scan, Finding, User, Organization, Membership, Role, ScanStatus, ProjectRiskSnapshot
from ...db.session import get_session
from ...core.security import get_current_user

router = APIRouter(prefix="/scan", tags=["scan"])

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

@router.post("/")
def create_scan(
    data: ScanCreate, 
    user: User = Depends(get_current_user), 
    session: Session = Depends(get_session)
):
    # 1. Auto-provision Organization if needed
    statement = select(Organization).join(Membership).where(Membership.user_id == user.id)
    org = session.exec(statement).first()
    if not org:
        org = Organization(name="Personal")
        session.add(org)
        session.commit()
        session.refresh(org)
        
        # Create membership
        membership = Membership(user_id=user.id, organization_id=org.id, role=Role.OWNER)
        session.add(membership)
        session.commit()
    
    # 2. Auto-provision Project if needed
    p_name = data.project_id or "local-scan"
    statement = select(Project).where(Project.organization_id == org.id, Project.name == p_name)
    project = session.exec(statement).first()
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
    
    # 4. Risk Scoring & Findings
    severity_weights = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1
    }
    
    total_risk = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for f_data in data.findings:
        sev = f_data.severity.upper()
        total_risk += severity_weights.get(sev, 1)
        counts[sev] = counts.get(sev, 0) + 1
        
        finding = Finding(
            scan_id=scan.id,
            project_id=project.id,
            type=f_data.rule_name,
            severity=sev,
            file_path=f_data.file,
            line_number=f_data.line,
            match_masked=f_data.masked_secret,
            hash=f_data.secret_hash,
            message=f_data.explanation,
            suggestion=f_data.fix,
            entropy=f_data.entropy
        )
        session.add(finding)
    
    # 5. Finalize Scan
    scan.risk_score = total_risk
    scan.total_findings = len(data.findings)
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.utcnow()
    session.add(scan)
    
    # 6. Update Project Risk Snapshot
    snapshot = ProjectRiskSnapshot(
        project_id=project.id,
        total_findings=len(data.findings),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        risk_score=total_risk
    )
    session.add(snapshot)
    
    session.commit()
    
    return {
        "scan_id": str(scan.id),
        "risk_score": total_risk,
        "findings_count": len(data.findings),
        "organization": org.name,
        "project": project.name
    }
