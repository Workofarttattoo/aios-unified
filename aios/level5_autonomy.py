"""Forwarding shim — re-exports everything from the root-level level5_autonomy module."""
import sys as _sys
from pathlib import Path as _Path

# Ensure repo root is importable
_root = str(_Path(__file__).resolve().parent.parent)
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from level5_autonomy import *  # noqa: F401,F403
try:
    from level5_autonomy import __all__ as _upstream_all  # noqa: F401
except ImportError:
    pass
