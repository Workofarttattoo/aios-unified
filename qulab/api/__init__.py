"""
FastAPI endpoints for QuLab.

Provides REST API endpoints for teleportation, simulation, governance,
and encoding operations with comprehensive documentation and validation.
"""

from fastapi import APIRouter

from .teleport import router as teleport_router

# Some router modules are optional in Lite builds—fall back to empty routers
try:
    from .simulate import router as simulate_router
except ImportError:
    simulate_router = APIRouter(prefix="/simulate", tags=["simulate"])

try:
    from .governance import router as governance_router
except ImportError:
    governance_router = APIRouter(prefix="/governance", tags=["governance"])

try:
    from .encoding import router as encoding_router
except ImportError:
    encoding_router = APIRouter(prefix="/encoding", tags=["encoding"])

__all__ = [
    "teleport_router",
    "simulate_router", 
    "governance_router",
    "encoding_router",
]
