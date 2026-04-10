"""
aios — Ai:oS Python package.

Re-exports core modules so ``from aios.config import ...`` and friends resolve
correctly regardless of whether the caller is inside the repository tree or
has installed the package.
"""

from __future__ import annotations

__all__: list[str] = []
