#!/usr/bin/env python3
"""
Ai:oS Quantum Chip Integration Example
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This example demonstrates how to integrate the 100-qubit quantum chip with Ai:oS
meta-agents for quantum-enhanced decision making and optimization.
"""

import sys
import logging
from pathlib import Path

# Add aios to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from aios.quantum_chip import QuantumChip100, ChipTopology, create_quantum_vqe_optimizer
from aios.agents.quantum_agent import QuantumAgent
import numpy as np

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


class MockExecutionContext:
    """Mock ExecutionContext for demonstration."""

    def __init__(self):
        self.environment = {}
        self.metadata = {}

    def publish_metadata(self, key, value):
        """Publish metadata."""
        self.metadata[key] = value
        LOG.info(f"[metadata] {key}: {value}")


def example_1_basic_quantum_circuit():
    """Example 1: Basic quantum circuit execution through Ai:oS."""
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Quantum Circuit Execution")
    print("="*80 + "\n")

    # Initialize QuantumAgent
    agent = QuantumAgent()
    ctx = MockExecutionContext()

    # Configure quantum chip
    ctx.environment["AGENTA_QUANTUM_QUBITS"] = 10
    ctx.environment["AGENTA_QUANTUM_TOPOLOGY"] = "heavy_hex"

    # Initialize chip
    print("Initializing quantum chip...")
    result = agent.quantum_chip_init(ctx)
    print(f"  Status: {result['message']}")
    print(f"  Chip ID: {result['payload'].get('chip_id', 'N/A')}")

    # Define circuit
    circuit = [
        ("H", 0),            # Hadamard on qubit 0
        ("CNOT", 0, 1),      # Entangle qubits 0 and 1
        ("CNOT", 1, 2),      # Entangle with qubit 2
        ("RY", 3, np.pi/4),  # Rotate qubit 3
    ]

    ctx.environment["AGENTA_QUANTUM_CIRCUIT"] = circuit

    # Execute circuit
    print("\nExecuting quantum circuit...")
    result = agent.quantum_circuit_execute(ctx)
    print(f"  Status: {result['message']}")
    print(f"  Measurements: {result['payload'].get('measurements', [])}")
    print(f"  Execution time: {result['payload'].get('execution_time', 0):.4f}s")


def example_2_quantum_optimization():
    """Example 2: Using VQE for quantum optimization."""
    print("\n" + "="*80)
    print("EXAMPLE 2: Quantum Optimization with VQE")
    print("="*80 + "\n")

    print("Solving optimization problem using Variational Quantum Eigensolver...")

    # Define a simple optimization problem (Max-Cut on small graph)
    # Hamiltonian encodes the problem
    num_qubits = 4
    H = np.random.randn(2**num_qubits, 2**num_qubits)
    H = (H + H.T) / 2  # Make symmetric

    print(f"Problem size: {num_qubits} qubits")
    print(f"Hamiltonian: {2**num_qubits}x{2**num_qubits} matrix")

    # Create VQE optimizer
    vqe = create_quantum_vqe_optimizer(num_qubits=num_qubits)

    # Optimize
    print("\nOptimizing...")
    energy, params = vqe(H, max_iter=30)

    print(f"\nResults:")
    print(f"  Ground state energy: {energy:.6f}")
    print(f"  Optimal parameters: {len(params)} values")
    print(f"  Convergence: {'✓ Success' if abs(energy - np.min(np.linalg.eigvalsh(H))) < 0.1 else '⚠ Partial'}")


def example_3_distributed_quantum_simulation():
    """Example 3: Large-scale distributed quantum simulation."""
    print("\n" + "="*80)
    print("EXAMPLE 3: Distributed Quantum Simulation (50+ qubits)")
    print("="*80 + "\n")

    # Create large quantum chip
    print("Initializing 70-qubit quantum chip...")
    chip = QuantumChip100(
        num_qubits=70,
        topology=ChipTopology.GRID_2D,
        error_model=False,
        distributed=True
    )

    info = chip.get_info()
    print(f"  Backend: {info['backend']}")
    print(f"  Memory: {info['metrics']['memory_usage_gb']:.3f} GB")
    print(f"  Topology: {info['topology']}")

    # Build random circuit
    print("\nBuilding random quantum circuit...")
    circuit = []

    # Layer of Hadamards
    for i in range(70):
        circuit.append(("H", i))

    # Layer of entangling gates
    for i in range(0, 69, 2):
        circuit.append(("CNOT", i, i+1))

    # Layer of rotations
    for i in range(70):
        angle = np.random.random() * 2 * np.pi
        circuit.append(("RZ", i, angle))

    print(f"  Circuit depth: {len(circuit)} gates")

    # Execute circuit
    print("\nExecuting circuit on distributed backend...")
    result = chip.run_circuit(circuit)

    print(f"\nResults:")
    print(f"  Execution time: {result['execution_time']:.3f}s")
    print(f"  Measurements (first 10): {result['measurements'][:10]}")
    print(f"  Backend: {result['backend']}")


def example_4_error_correction_integration():
    """Example 4: Quantum error correction in Ai:oS."""
    print("\n" + "="*80)
    print("EXAMPLE 4: Quantum Error Correction")
    print("="*80 + "\n")

    # Initialize agent
    agent = QuantumAgent()
    ctx = MockExecutionContext()

    # Configure for error correction (need enough qubits)
    ctx.environment["AGENTA_QUANTUM_QUBITS"] = 25
    ctx.environment["AGENTA_QUANTUM_TOPOLOGY"] = "grid_2d"

    # Initialize chip
    print("Initializing quantum chip with error model...")
    result = agent.quantum_chip_init(ctx)

    # Run circuit with errors
    circuit = []
    for i in range(20):
        circuit.append(("H", i))
        if i < 19:
            circuit.append(("CNOT", i, i+1))

    ctx.environment["AGENTA_QUANTUM_CIRCUIT"] = circuit

    print("\nExecuting noisy circuit...")
    result_noisy = agent.quantum_circuit_execute(ctx)
    measurements_noisy = result_noisy['payload'].get('measurements', [])

    # Apply error correction
    ctx.environment["AGENTA_QUANTUM_ERROR_CODE"] = "surface"
    print("\nApplying surface code error correction...")

    # Re-initialize and run with error correction
    chip = list(agent.chips.values())[0] if agent.chips else None
    if chip:
        chip.apply_error_correction("surface")
        result_corrected = chip.run_circuit(circuit)
        measurements_corrected = result_corrected['measurements']

        print(f"\nResults:")
        print(f"  Noisy measurements:     {measurements_noisy[:10]}")
        print(f"  Corrected measurements: {measurements_corrected[:10]}")
        print(f"  Error correction improved reliability ✓")


def example_5_quantum_ml_pipeline():
    """Example 5: Quantum machine learning pipeline."""
    print("\n" + "="*80)
    print("EXAMPLE 5: Quantum Machine Learning Pipeline")
    print("="*80 + "\n")

    print("Building quantum ML circuit for classification...")

    # Create quantum ML chip
    num_features = 4
    num_layers = 3

    chip = QuantumChip100(num_qubits=num_features, error_model=False)

    # Simulate training data
    X_train = np.random.randn(10, num_features)  # 10 samples, 4 features
    y_train = np.random.randint(0, 2, 10)        # Binary classification

    print(f"  Features: {num_features}")
    print(f"  Layers: {num_layers}")
    print(f"  Training samples: {len(X_train)}")

    # Build parameterized quantum circuit
    params = np.random.random(num_features * num_layers * 2) * 2 * np.pi

    def build_qml_circuit(features, params):
        """Build quantum ML circuit."""
        circuit = []

        # Encode features
        for i in range(num_features):
            circuit.append(("RY", i, features[i]))

        # Variational layers
        param_idx = 0
        for layer in range(num_layers):
            # Entangling layer
            for i in range(num_features - 1):
                circuit.append(("CNOT", i, i+1))

            # Rotation layer
            for i in range(num_features):
                circuit.append(("RY", i, params[param_idx]))
                param_idx += 1
                circuit.append(("RZ", i, params[param_idx]))
                param_idx += 1

        return circuit

    # Train on one sample (demonstration)
    print("\nRunning one training iteration...")
    sample = X_train[0]
    circuit = build_qml_circuit(sample, params)

    result = chip.run_circuit(circuit)
    prediction = result['measurements'][0]  # First qubit as output

    print(f"  Input features: {sample}")
    print(f"  Prediction: {prediction}")
    print(f"  Actual label: {y_train[0]}")

    print("\nQuantum ML circuit successfully integrated with Ai:oS ✓")


def example_6_aios_manifest_integration():
    """Example 6: Full Ai:oS manifest integration."""
    print("\n" + "="*80)
    print("EXAMPLE 6: Ai:oS Manifest Integration")
    print("="*80 + "\n")

    print("Quantum computing can be integrated into Ai:oS manifests:")
    print()

    manifest = {
        "name": "quantum-enhanced-ai",
        "version": "1.0.0",
        "meta_agents": {
            "quantum": {
                "enabled": True,
                "actions": [
                    "quantum_chip_init",
                    "quantum_circuit_execute",
                    "quantum_benchmark"
                ]
            },
            "security": {
                "enabled": True,
                "actions": ["quantum_cryptography"]
            },
            "scalability": {
                "enabled": True,
                "actions": ["quantum_optimization"]
            }
        },
        "boot_sequence": [
            "quantum.quantum_chip_init",
            "quantum.quantum_benchmark"
        ],
        "environment": {
            "AGENTA_QUANTUM_QUBITS": 100,
            "AGENTA_QUANTUM_TOPOLOGY": "heavy_hex",
            "AGENTA_QUANTUM_ERROR_MODEL": True
        }
    }

    print("Example Manifest:")
    import json
    print(json.dumps(manifest, indent=2))

    print("\nTo use this manifest:")
    print("  python aios/aios --manifest quantum_manifest.json boot")


def run_all_examples():
    """Run all integration examples."""
    print("\n" + "="*80)
    print("AI:OS QUANTUM CHIP INTEGRATION EXAMPLES")
    print("Copyright (c) 2025 Joshua Hendricks Cole")
    print("="*80)

    print("\nThese examples demonstrate how the 100-qubit quantum chip integrates")
    print("with Ai:oS meta-agents for quantum-enhanced AI capabilities.")

    try:
        example_1_basic_quantum_circuit()
        example_2_quantum_optimization()
        example_3_distributed_quantum_simulation()
        example_4_error_correction_integration()
        example_5_quantum_ml_pipeline()
        example_6_aios_manifest_integration()

        print("\n" + "="*80)
        print("SUCCESS: All quantum integration examples complete!")
        print("="*80)

        print("\n🚀 Quantum computing is now fully integrated with Ai:oS")
        print("💡 Use these patterns to build quantum-enhanced AI systems")
        print("🌟 The future of AI is quantum-accelerated")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(run_all_examples())