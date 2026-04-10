"""
Pytest configuration for Ai:oS test suite.

Automatically skips git-crypt encrypted files that haven't been unlocked,
and ensures the repo root is on sys.path.
"""

import sys
from pathlib import Path

# Ensure repo root is importable
_root = str(Path(__file__).resolve().parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)


def pytest_collect_file(parent, file_path):
    """Skip git-crypt encrypted files that contain null bytes."""
    if file_path.suffix == ".py":
        try:
            raw = file_path.read_bytes()[:16]
            if b"\x00GITCRYPT\x00" in raw or b"\x00" in raw:
                return None
        except Exception:
            pass
    return None  # fall through to default collection
