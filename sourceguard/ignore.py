"""
.sourceguardignore — gitignore-style ignore rules.
Checked against file paths before scanning.
"""

import fnmatch
import os
from pathlib import Path

# Always skip these regardless of ignore file
DEFAULT_IGNORE = [
    ".git", ".git/*",
    "*.lock", "package-lock.json", "yarn.lock", "poetry.lock",
    "node_modules/*", ".venv/*", "venv/*", "__pycache__/*",
    "*.min.js", "*.min.css",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.pdf", "*.zip", "*.tar.gz", "*.whl",
    "*.pyc", "*.pyo", "*.so", "*.dll", "*.exe",
    ".sourceguardignore",
]

IGNORE_FILENAME = ".sourceguardignore"


def load_ignore_patterns(root: Path) -> list[str]:
    patterns = list(DEFAULT_IGNORE)
    ignore_file = root / IGNORE_FILENAME
    if ignore_file.exists():
        for line in ignore_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    rel = str(path.relative_to(root)).replace(os.sep, "/")
    name = path.name
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        if fnmatch.fnmatch(name, pat):
            return True
        # Support directory prefix patterns like "node_modules/*"
        if pat.endswith("/*") and rel.startswith(pat[:-2]):
            return True
    return False
