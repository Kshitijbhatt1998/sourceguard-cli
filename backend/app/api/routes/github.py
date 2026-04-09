from fastapi import APIRouter, Request, HTTPException
from ...db.session import get_sync_session
from ...db.models import Project, Scan, ScanStatus
import uuid
import datetime

router = APIRouter(prefix="/github", tags=["github"])

@router.post("/webhook")
async def github_webhook(request: Request):
    payload = await request.json()
    
    # Check if it's a push or pull_request event
    event = request.headers.get("X-GitHub-Event", "ping")
    
    if event == "ping":
        return {"msg": "pong"}
        
    if event not in ["push", "pull_request"]:
        return {"msg": f"Ignoring event type: {event}"}
        
    repo_url = payload.get("repository", {}).get("clone_url")
    repo_name = payload.get("repository", {}).get("full_name")
    
    if not repo_url:
        raise HTTPException(status_code=400, detail="Invalid GitHub payload: Missing repository URL")

    # In a real system, we would trigger an async task here (Celery/RQ)
    # For now, we log the intent and create a 'pending' scan record.
    
    with get_sync_session() as session:
        # Try to find a project that matches this repo URL
        from sqlmodel import select
        project = session.exec(select(Project).where(Project.repo_url == repo_url)).first()
        
        if not project:
            # For demonstration, we'll return acknowledged but won't auto-create 
            # without an associated organization/user.
            return {"msg": "Webhook received. No matching project found for auto-scan.", "repo": repo_name}
            
        # Create a pending scan
        scan = Scan(
            project_id=project.id,
            source="github",
            status=ScanStatus.PENDING,
            started_at=datetime.datetime.utcnow()
        )
        session.add(scan)
        session.commit()
        
        return {
            "msg": "GitHub event received and scan queued.",
            "scan_id": str(scan.id),
            "event": event,
            "repo": repo_name
        }
