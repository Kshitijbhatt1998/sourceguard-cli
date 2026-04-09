import os
import time
from pathlib import Path
from typing import List, Optional

from ..models import Finding, ScanResult
from ..detectors.registry import DETECTORS
from ..ignore import is_ignored, load_ignore_patterns

MAX_FILE_BYTES = 1_000_000   # 1 MB
MAX_LINE_LEN = 2_000         # Skip minified lines

def run_scan(path: str) -> ScanResult:
    """
    Main orchestrator logic to scan a file or directory.
    """
    start_time = time.time()
    root = Path(path).resolve()
    result = ScanResult(target_path=str(root))
    
    if root.is_file():
        result.files_scanned += 1
        result.findings.extend(_scan_file(root, root.parent))
    elif root.is_dir():
        patterns = load_ignore_patterns(root)
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directories
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
                result.findings.extend(_scan_file(fpath, root))
    
    result.duration_seconds = round(time.time() - start_time, 2)
    return result

def _scan_file(path: Path, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    
    try:
        # Check file size
        if path.stat().st_size > MAX_FILE_BYTES:
            return findings
        
        # Read file content safely
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel_path = str(path.relative_to(root))
    
    for line_no, content_line in enumerate(content.splitlines(), start=1):
        if len(content_line) > MAX_LINE_LEN:
            continue
            
        for detector in DETECTORS:
            detector_findings = detector.detect(content_line, rel_path, line_no)
            if detector_findings:
                # Deduplicate or manage findings here if needed
                # For example, if multiple detectors flag the same line
                findings.extend(detector_findings)
                
    return findings
