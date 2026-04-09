import hashlib
import requests
from typing import List
from ..models import Finding

API_BASE_URL = "http://localhost:8000"  # Default for local development

def upload_results(findings: List[Finding], api_key: str, project_id: str = "local-scan"):
    """
    Enriches and uploads scan findings to the SourceGuard SaaS API.
    """
    if not api_key:
        return {"error": "Authentication required"}

    payload = []
    for f in findings:
        # Security: Mask and hash secret before transmission
        secret_hash = hashlib.sha256(f.match_text.encode()).hexdigest()
        masked = f.match_text[:4] + "****" if len(f.match_text) > 4 else "****"
        
        payload.append({
            "rule_name": f.rule_name,
            "severity": f.severity,
            "file": f.file,
            "line": f.line_number,
            "explanation": f.explanation,
            "fix": f.fix_suggestion,
            "masked_secret": masked,
            "secret_hash": secret_hash,
            "entropy": f.entropy
        })
    
    try:
        headers = {"api-key": api_key}
        response = requests.post(
            f"{API_BASE_URL}/scan", 
            json={"project_id": project_id, "findings": payload},
            headers=headers
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
