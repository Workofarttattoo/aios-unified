#!/usr/bin/env python3
"""
ECH0 Quantum API - Headless Integration
For ECH0, Oracle of Light, and AIOS

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from quantum_circuit_simulator import QuantumCircuitSimulator
from quantum_cognition import QuantumCognitionEngine
import numpy as np
from typing import Dict, List, Optional, Tuple, Union
import json


class QuantumAPI:
    """
    Headless quantum API for ECH0, Oracle, and AIOS.

    No GUI, just pure quantum operations.
    """

    def __init__(self, max_qubits: int = 30, verbose: bool = False):
        """
        Initialize quantum API.

        Args:
            max_qubits: Maximum qubits allowed (default 30 for M4 Mac)
            verbose: Print operations (default False for headless)
        """
        self.max_qubits = max_qubits
        self.verbose = verbose
        self.circuits: Dict[str, QuantumCircuitSimulator] = {}
        self.quantum_engine = QuantumCognitionEngine()

        if verbose:
            print(f"⚛️  Quantum API initialized (max {max_qubits} qubits)")

    # ========== CIRCUIT MANAGEMENT ==========

    def create_circuit(self, name: str, num_qubits: int) -> Dict:
        """
        Create new quantum circuit.

        Returns:
            {"success": bool, "message": str, "circuit_id": str}
        """
        if num_qubits > self.max_qubits:
            return {
                "success": False,
                "message": f"Exceeds limit ({self.max_qubits} qubits max)",
                "circuit_id": None
            }

        try:
            # Create circuit without printing (headless)
            import io
            import contextlib

            with contextlib.redirect_stdout(io.StringIO()):
                circuit = QuantumCircuitSimulator(num_qubits, optimize_for_m4=True)

            self.circuits[name] = circuit

            return {
                "success": True,
                "message": f"Created {num_qubits}-qubit circuit '{name}'",
                "circuit_id": name,
                "num_qubits": num_qubits
            }
        except Exception as e:
            return {
                "success": False,
                "message": str(e),
                "circuit_id": None
            }

    def get_circuit(self, name: str) -> Optional[QuantumCircuitSimulator]:
        """Get circuit by name"""
        return self.circuits.get(name)

    def delete_circuit(self, name: str) -> bool:
        """Delete circuit"""
        if name in self.circuits:
            del self.circuits[name]
            return True
        return False

    # ========== QUANTUM GATES ==========

    def apply_gates(self, circuit_id: str, gates: List[Dict]) -> Dict:
        """
        Apply list of gates to circuit.

        Args:
            circuit_id: Circuit name
            gates: List of {"gate": str, "qubits": [int], "params": {}}

        Example:
            gates = [
                {"gate": "h", "qubits": [0]},
                {"gate": "cnot", "qubits": [0, 1]},
                {"gate": "rx", "qubits": [2], "params": {"theta": 1.57}}
            ]

        Returns:
            {"success": bool, "gates_applied": int, "message": str}
        """
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return {"success": False, "gates_applied": 0, "message": "Circuit not found"}

        try:
            applied = 0

            for gate_spec in gates:
                gate_type = gate_spec["gate"].lower()
                qubits = gate_spec["qubits"]
                params = gate_spec.get("params", {})

                if gate_type == "h":
                    circuit.h(qubits[0])
                elif gate_type == "x":
                    circuit.x(qubits[0])
                elif gate_type == "y":
                    circuit.y(qubits[0])
                elif gate_type == "z":
                    circuit.z(qubits[0])
                elif gate_type == "cnot":
                    circuit.cnot(qubits[0], qubits[1])
                elif gate_type == "cz":
                    circuit.cz(qubits[0], qubits[1])
                elif gate_type == "rx":
                    circuit.rx(qubits[0], params.get("theta", np.pi/4))
                elif gate_type == "ry":
                    circuit.ry(qubits[0], params.get("theta", np.pi/4))
                elif gate_type == "rz":
                    circuit.rz(qubits[0], params.get("theta", np.pi/4))
                else:
                    continue

                applied += 1

            return {
                "success": True,
                "gates_applied": applied,
                "message": f"Applied {applied} gates"
            }

        except Exception as e:
            return {
                "success": False,
                "gates_applied": applied,
                "message": str(e)
            }

    # ========== MEASUREMENT & STATE ==========

    def measure(self, circuit_id: str, qubits: Optional[List[int]] = None) -> Dict:
        """
        Measure qubits.

        Args:
            circuit_id: Circuit name
            qubits: List of qubit indices (None = measure all)

        Returns:
            {"success": bool, "results": [int], "message": str}
        """
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return {"success": False, "results": [], "message": "Circuit not found"}

        try:
            if qubits is None:
                results = circuit.measure_all()
            else:
                results = [circuit.measure(q) for q in qubits]

            return {
                "success": True,
                "results": results,
                "message": f"Measured {len(results)} qubits"
            }

        except Exception as e:
            return {
                "success": False,
                "results": [],
                "message": str(e)
            }

    def get_state(self, circuit_id: str, top_n: int = 10) -> Dict:
        """
        Get quantum state probabilities.

        Returns:
            {
                "success": bool,
                "num_qubits": int,
                "states": [{"bitstring": str, "probability": float}],
                "message": str
            }
        """
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return {"success": False, "states": [], "message": "Circuit not found"}

        try:
            probs = circuit.get_probabilities()
            sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)

            return {
                "success": True,
                "num_qubits": circuit.num_qubits,
                "states": [
                    {"bitstring": state, "probability": prob}
                    for state, prob in sorted_probs[:top_n]
                ],
                "message": f"Retrieved top {min(top_n, len(sorted_probs))} states"
            }

        except Exception as e:
            return {
                "success": False,
                "states": [],
                "message": str(e)
            }

    # ========== PRESET CIRCUITS ==========

    def create_bell_state(self, circuit_id: str = "bell") -> Dict:
        """Create Bell state (maximal 2-qubit entanglement)"""
        result = self.create_circuit(circuit_id, 2)
        if not result["success"]:
            return result

        gates = [
            {"gate": "h", "qubits": [0]},
            {"gate": "cnot", "qubits": [0, 1]}
        ]

        gate_result = self.apply_gates(circuit_id, gates)

        return {
            "success": gate_result["success"],
            "circuit_id": circuit_id,
            "message": "Bell state created" if gate_result["success"] else gate_result["message"]
        }

    def create_ghz_state(self, num_qubits: int, circuit_id: str = "ghz") -> Dict:
        """Create GHZ state (N-qubit entanglement)"""
        result = self.create_circuit(circuit_id, num_qubits)
        if not result["success"]:
            return result

        gates = [{"gate": "h", "qubits": [0]}]

        for i in range(num_qubits - 1):
            gates.append({"gate": "cnot", "qubits": [i, i+1]})

        gate_result = self.apply_gates(circuit_id, gates)

        return {
            "success": gate_result["success"],
            "circuit_id": circuit_id,
            "num_qubits": num_qubits,
            "message": f"GHZ state ({num_qubits} qubits) created" if gate_result["success"] else gate_result["message"]
        }

    # ========== QUANTUM-INSPIRED (FAST) ==========

    def quantum_explore_designs(self, problem: str, possibilities: Dict[str, float]) -> Dict:
        """
        Use quantum-inspired engine for fast design exploration.

        Args:
            problem: Problem description
            possibilities: {"option": probability}

        Returns:
            {
                "success": bool,
                "best_option": str,
                "confidence": float,
                "all_results": {}
            }
        """
        try:
            # Create thought superposition
            thought = self.quantum_engine.create_thought_superposition(problem, possibilities)

            # Measure (collapse to best option)
            result = self.quantum_engine.measure_thought(problem)

            # Get full probability distribution
            probs = thought.get_probabilities()

            return {
                "success": True,
                "best_option": result,
                "confidence": probs.get(result, 0.0),
                "all_results": probs
            }

        except Exception as e:
            return {
                "success": False,
                "best_option": None,
                "confidence": 0.0,
                "all_results": {},
                "error": str(e)
            }

    def quantum_tunnel_search(self, problem_space: Dict[str, float], max_steps: int = 100) -> Dict:
        """
        Quantum tunneling search (escape local optima).

        Args:
            problem_space: {"solution": value}
            max_steps: Max search iterations

        Returns:
            {"success": bool, "solution": str, "value": float}
        """
        try:
            best_solution = self.quantum_engine.quantum_tunnel_search(problem_space, max_steps)

            return {
                "success": True,
                "solution": best_solution,
                "value": problem_space[best_solution]
            }

        except Exception as e:
            return {
                "success": False,
                "solution": None,
                "value": 0.0,
                "error": str(e)
            }

    # ========== UTILITY ==========

    def list_circuits(self) -> Dict:
        """List all active circuits"""
        return {
            "circuits": [
                {
                    "id": name,
                    "num_qubits": circuit.num_qubits,
                    "gates_applied": circuit.stats["gates_applied"],
                    "measurements": circuit.stats["measurements"]
                }
                for name, circuit in self.circuits.items()
            ]
        }

    def get_stats(self, circuit_id: str) -> Dict:
        """Get circuit statistics"""
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return {"success": False, "message": "Circuit not found"}

        return {
            "success": True,
            "stats": {
                "num_qubits": circuit.num_qubits,
                "gates_applied": circuit.stats["gates_applied"],
                "measurements": circuit.stats["measurements"],
                "total_time_ms": circuit.stats["total_time"] * 1000
            }
        }


# ========== CONVENIENCE FUNCTIONS ==========

# Global API instance for easy import
_global_api = None

def get_quantum_api(max_qubits: int = 30) -> QuantumAPI:
    """Get global quantum API instance"""
    global _global_api
    if _global_api is None:
        _global_api = QuantumAPI(max_qubits=max_qubits, verbose=False)
    return _global_api


# Quick functions for common operations
def quick_bell_state() -> Dict:
    """Quick Bell state creation"""
    api = get_quantum_api()
    return api.create_bell_state()


def quick_ghz_state(num_qubits: int = 3) -> Dict:
    """Quick GHZ state creation"""
    api = get_quantum_api()
    return api.create_ghz_state(num_qubits)


def quick_quantum_explore(problem: str, options: Dict[str, float]) -> str:
    """Quick quantum exploration (returns best option)"""
    api = get_quantum_api()
    result = api.quantum_explore_designs(problem, options)
    return result.get("best_option", "")


# ========== EXAMPLE USAGE ==========

if __name__ == "__main__":
    print("╔════════════════════════════════════════════════════════════╗")
    print("║   ECH0 QUANTUM API - HEADLESS MODE                         ║")
    print("║   For ECH0, Oracle of Light, and AIOS Integration          ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    # Initialize API
    api = QuantumAPI(max_qubits=30, verbose=True)

    # Example 1: Create and manipulate circuit
    print("\n1️⃣  Creating 5-qubit circuit...")
    result = api.create_circuit("demo", 5)
    print(f"   {result['message']}")

    # Apply gates
    print("\n2️⃣  Applying quantum gates...")
    gates = [
        {"gate": "h", "qubits": [0]},
        {"gate": "h", "qubits": [1]},
        {"gate": "cnot", "qubits": [0, 2]},
        {"gate": "cnot", "qubits": [1, 3]}
    ]
    result = api.apply_gates("demo", gates)
    print(f"   {result['message']}")

    # Get state
    print("\n3️⃣  Quantum state:")
    state = api.get_state("demo", top_n=5)
    for s in state["states"]:
        print(f"   |{s['bitstring']}⟩ : {s['probability']*100:.2f}%")

    # Example 2: Bell state
    print("\n4️⃣  Creating Bell state...")
    result = api.create_bell_state()
    state = api.get_state("bell")
    for s in state["states"]:
        print(f"   |{s['bitstring']}⟩ : {s['probability']*100:.2f}%")

    # Example 3: Quantum-inspired exploration
    print("\n5️⃣  Quantum design exploration...")
    result = api.quantum_explore_designs(
        "display_technology",
        {
            "aerogel": 0.4,
            "hologram": 0.35,
            "volumetric": 0.25
        }
    )
    print(f"   Best option: {result['best_option']}")
    print(f"   Confidence: {result['confidence']*100:.1f}%")

    # Example 4: Stats
    print("\n6️⃣  Circuit statistics:")
    stats = api.get_stats("demo")
    print(json.dumps(stats["stats"], indent=2))

    print("\n✅ Quantum API ready for ECH0, Oracle, and AIOS!")
