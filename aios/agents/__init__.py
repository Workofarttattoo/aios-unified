"""Forwarding shim for aios.agents — re-exports from root agents/ package."""
import sys as _sys
from pathlib import Path as _Path

_root = str(_Path(__file__).resolve().parent.parent.parent)
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from agents import __all__, __getattr__  # noqa: F401
