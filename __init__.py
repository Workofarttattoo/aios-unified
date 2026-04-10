"""
Compatibility package that mirrors the legacy ``Ai:oS`` namespace.

Many integration tests and third-party extensions still reference
``Ai:oS.virtualization``. The canonical implementation now lives in
``aios.virtualization``; this shim keeps old imports working while the codebase
converges on the new layout.
"""

from __future__ import annotations

try:
    from . import virtualization  # noqa: F401
except ImportError:
    # When loaded outside a package context (e.g. pytest collection), the
    # relative import is not available — fall back to an absolute import.
    try:
        import virtualization  # noqa: F401
    except ImportError:
        virtualization = None  # type: ignore[assignment]

__all__ = ["virtualization"]
