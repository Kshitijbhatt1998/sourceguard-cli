import datetime
import json

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from sqlmodel import select

from ...core.github_security import verify_github_signature
from ...db.models import Project, Scan, ScanStatus
from ...db.session import get_sync_session
from ...services.github_service import run_github_scan

router = APIRouter(prefix="/github", tags=["github"])


@router.post("/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(...),
):
    """
    Receives GitHub App webhook events.
    Verifies the HMAC signature, creates a pending Scan record,
    then runs the full clone-and-scan in a background task.
    """
    body = await request.body()
    verify_github_signature(body, x_hub_signature_256)

    payload = json.loads(body)
    event = request.headers.get("X-GitHub-Event", "ping")

    if event == "ping":
        return {"msg": "pong"}

    if event not in ("push", "pull_request"):
        return {"msg": f"Ignoring event: {event}"}

    repo_url = payload.get("repository", {}).get("clone_url")
    repo_name = payload.get("repository", {}).get("full_name")

    if not repo_url:
        raise HTTPException(status_code=400, detail="Missing repository URL in payload.")

    with get_sync_session() as session:
        project = session.exec(
            select(Project).where(Project.repo_url == repo_url)
        ).first()

        if not project:
            return {
                "msg": "Webhook acknowledged. No matching project found for auto-scan.",
                "repo": repo_name,
            }

        scan = Scan(
            project_id=project.id,
            source="github",
            status=ScanStatus.PENDING,
            started_at=datetime.datetime.utcnow(),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = str(scan.id)

    # Off the main thread — safe to clone large repos
    background_tasks.add_task(run_github_scan, scan_id, repo_url)

    return {
        "msg": "Webhook received. Scan queued.",
        "scan_id": scan_id,
        "event": event,
        "repo": repo_name,
    }
