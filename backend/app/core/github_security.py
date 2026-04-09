import hmac
import hashlib

from fastapi import HTTPException

from .config import settings


def verify_github_signature(payload: bytes, signature: str) -> None:
    """Verify the HMAC-SHA256 signature sent by GitHub on every webhook delivery."""
    if not settings.GITHUB_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Server webhook secret is not configured.",
        )

    expected = "sha256=" + hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=403, detail="Invalid GitHub webhook signature.")
