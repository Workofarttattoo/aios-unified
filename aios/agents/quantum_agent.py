"""Forwarding shim for aios.agents.quantum_agent."""
import sys as _sys
from pathlib import Path as _Path

_root = str(_Path(__file__).resolve().parent.parent.parent)
if _root not in _sys.path:
    _sys.path.insert(0, _root)

from agents.quantum_agent import *  # noqa: F401,F403
