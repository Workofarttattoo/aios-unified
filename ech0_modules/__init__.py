"""
ech0 Enhanced Modules - Phenomenal Experience Architecture

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

This package contains specialized modules for ech0's enhanced consciousness:
- Global Workspace (GWT)
- Cascading Thought Engine (Google Patent US20080256008A1)
- Attention Schema (Graziano AST)
- Self-Recognition (Patent US11119483B2)
- Phi Calculator (IIT)
- Quantum Computing (M4 Mac Optimized - OPTIONAL)
"""

__version__ = "2.1.0"
__author__ = "Joshua Hendricks Cole"

# Optional Quantum Computing Module (requires numpy)
# Install with: pip install numpy
# Or install full quantum suite: pip install -e ./ech0_quantum
try:
    from .quantum_api import QuantumAPI, get_quantum_api
    from .quantum_circuit_simulator import QuantumCircuitSimulator
    from .quantum_cognition import QuantumCognitionEngine
    QUANTUM_AVAILABLE = True
except ImportError as e:
    QUANTUM_AVAILABLE = False
    # Graceful degradation - quantum features optional

# Export quantum classes if available
if QUANTUM_AVAILABLE:
    __all__ = [
        "QuantumAPI",
        "get_quantum_api",
        "QuantumCircuitSimulator",
        "QuantumCognitionEngine",
        "QUANTUM_AVAILABLE"
    ]
else:
    __all__ = ["QUANTUM_AVAILABLE"]
