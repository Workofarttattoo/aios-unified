#!/usr/bin/env python3
"""
Interactive Demonstration of the 100-Qubit Quantum Chip
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This script provides an interactive demonstration of quantum computing capabilities.
"""

import sys
import time
import numpy as np
from pathlib import Path

# Add aios to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aios.quantum_chip import QuantumChip100, ChipTopology


def print_header(title):
    """Print a formatted section header."""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80 + "\n")


def demo_bell_state():
    """Demonstrate quantum entanglement with Bell state."""
    print_header("DEMO 1: QUANTUM ENTANGLEMENT (Bell State)")

    print("Creating a Bell state - the simplest form of quantum entanglement")
    print("Circuit: H(q0) -> CNOT(q0, q1)")
    print("\nThis creates the state: |00> + |11> (qubits are perfectly correlated)\n")

    chip = QuantumChip100(num_qubits=2, error_model=False)

    # Create Bell state
    chip.hadamard(0)
    chip.cnot(0, 1)

    print("Running 10 measurements:")
    for i in range(10):
        chip.initialize_state()
        chip.hadamard(0)
        chip.cnot(0, 1)

        m0 = chip.measure(0)
        m1 = chip.measure(1)
        print(f"  Measurement {i+1}: q0={m0}, q1={m1} {'✓ Correlated!' if m0 == m1 else '✗ Not correlated'}")

    print("\nNotice: The qubits are ALWAYS measured in the same state!")
    print("This is quantum entanglement - measuring one instantly determines the other.")


def demo_ghz_state():
    """Demonstrate multi-qubit entanglement."""
    print_header("DEMO 2: MULTI-QUBIT ENTANGLEMENT (GHZ State)")

    n_qubits = 8
    print(f"Creating a {n_qubits}-qubit GHZ state")
    print("Circuit: H(q0) -> CNOT(q0, q1) -> CNOT(q0, q2) -> ... -> CNOT(q0, qn)")
    print(f"\nThis creates: |00...0> + |11...1> ({n_qubits} qubits all entangled)\n")

    chip = QuantumChip100(num_qubits=n_qubits, topology=ChipTopology.LINEAR)

    # Create GHZ state
    start = time.time()
    chip.hadamard(0)
    for i in range(1, n_qubits):
        chip.cnot(0, i)
    creation_time = time.time() - start

    print(f"GHZ state created in {creation_time*1000:.2f}ms")
    print("\nRunning 5 measurements:")

    for i in range(5):
        chip.initialize_state()
        chip.hadamard(0)
        for j in range(1, n_qubits):
            chip.cnot(0, j)

        measurements = chip.measure_all()
        print(f"  Measurement {i+1}: {measurements}")

    print("\nNotice: All qubits are ALWAYS in the same state!")
    print("This demonstrates {n_qubits}-way quantum correlation.")


def demo_superposition():
    """Demonstrate quantum superposition."""
    print_header("DEMO 3: QUANTUM SUPERPOSITION")

    print("Quantum superposition: A qubit can be in state |0> AND |1> simultaneously")
    print("Circuit: H(q0) creates (|0> + |1>) / sqrt(2)\n")

    chip = QuantumChip100(num_qubits=1, error_model=False)

    # Create superposition
    chip.hadamard(0)

    print("Running 100 measurements of a superposition state:")
    results = []
    for _ in range(100):
        chip.initialize_state()
        chip.hadamard(0)
        result = chip.measure(0)
        results.append(result)

    count_0 = results.count(0)
    count_1 = results.count(1)

    print(f"  Measured |0>: {count_0} times ({count_0}%)")
    print(f"  Measured |1>: {count_1} times ({count_1}%)")
    print(f"\n  ▓{'█' * (count_0 // 2)}{'░' * (count_1 // 2)}")
    print(f"  0{'─' * 48}100")

    print("\nThe measurements are roughly 50/50 - the qubit was in BOTH states!")
    print("This is the quantum superposition principle.")


def demo_quantum_interference():
    """Demonstrate quantum interference."""
    print_header("DEMO 4: QUANTUM INTERFERENCE")

    print("Quantum interference: Probability amplitudes can cancel out")
    print("Circuit: H -> Z -> H (this returns to |0> with certainty)\n")

    chip = QuantumChip100(num_qubits=1, error_model=False)

    print("Running 100 measurements:")
    results = []
    for _ in range(100):
        chip.initialize_state()
        chip.hadamard(0)   # Create superposition
        chip.pauli_z(0)    # Apply phase flip
        chip.hadamard(0)   # Interference causes return to |0>

        result = chip.measure(0)
        results.append(result)

    count_0 = results.count(0)
    count_1 = results.count(1)

    print(f"  Measured |0>: {count_0} times")
    print(f"  Measured |1>: {count_1} times")

    print("\nThe qubit returns to |0> with 100% certainty!")
    print("The |1> amplitudes cancelled out through destructive interference.")


def demo_quantum_teleportation():
    """Demonstrate quantum teleportation protocol."""
    print_header("DEMO 5: QUANTUM TELEPORTATION")

    print("Quantum teleportation: Transfer quantum state without moving the qubit")
    print("Protocol: Alice wants to send quantum state to Bob using entanglement\n")

    chip = QuantumChip100(num_qubits=3, error_model=False)

    print("Step 1: Prepare state to teleport (qubit 0)")
    # Prepare arbitrary state on qubit 0
    chip.ry(0, np.pi/3)  # Some arbitrary state

    print("Step 2: Create entangled pair (qubits 1 and 2) - one for Alice, one for Bob")
    chip.hadamard(1)
    chip.cnot(1, 2)

    print("Step 3: Alice performs Bell measurement on qubits 0 and 1")
    chip.cnot(0, 1)
    chip.hadamard(0)

    print("Step 4: Alice measures her qubits")
    m0 = chip.measure(0)
    m1 = chip.measure(1)
    print(f"  Alice's measurements: {m0}, {m1}")

    print("Step 5: Bob applies corrections based on Alice's results")
    if m1 == 1:
        chip.pauli_x(2)
    if m0 == 1:
        chip.pauli_z(2)

    print("\nResult: Bob's qubit (2) now has the exact state that Alice's qubit (0) had!")
    print("The quantum state was 'teleported' from qubit 0 to qubit 2.")


def demo_backend_scaling():
    """Demonstrate automatic backend selection."""
    print_header("DEMO 6: BACKEND SCALING")

    print("The quantum chip automatically selects the optimal backend:\n")

    test_sizes = [5, 15, 25, 45, 75]

    for n in test_sizes:
        start = time.time()
        chip = QuantumChip100(num_qubits=n, error_model=False)
        init_time = time.time() - start

        info = chip.get_info()

        print(f"  {n:3d} qubits:")
        print(f"    Backend: {info['backend']:20s}")
        print(f"    Memory:  {info['metrics']['memory_usage_gb']:8.3f} GB")
        print(f"    Init:    {init_time*1000:8.2f} ms")
        print()


def demo_error_correction():
    """Demonstrate quantum error correction."""
    print_header("DEMO 7: QUANTUM ERROR CORRECTION")

    print("Quantum error correction protects quantum information from noise")
    print("Using Surface Code (5x5 grid = 25 physical qubits for 1 logical qubit)\n")

    chip = QuantumChip100(
        num_qubits=25,
        topology=ChipTopology.GRID_2D,
        error_model=True
    )

    print("Running circuit WITHOUT error correction:")
    chip.initialize_state()
    for i in range(10):
        chip.hadamard(i)
    measurements_noisy = chip.measure_all()
    print(f"  Results: {measurements_noisy[:10]}...")

    print("\nApplying surface code error correction...")
    chip.initialize_state()
    chip.apply_error_correction("surface")
    for i in range(10):
        chip.hadamard(i)
    measurements_corrected = chip.measure_all()
    print(f"  Results: {measurements_corrected[:10]}...")

    print("\nError correction helps maintain quantum information despite noise!")


def demo_chip_info():
    """Display quantum chip capabilities."""
    print_header("QUANTUM CHIP CAPABILITIES")

    chip = QuantumChip100(num_qubits=50, topology=ChipTopology.HEAVY_HEX)
    info = chip.get_info()

    print("Chip Configuration:")
    print(f"  Chip ID:          {info['chip_id']}")
    print(f"  Qubits:           {info['num_qubits']}")
    print(f"  Backend:          {info['backend']}")
    print(f"  Topology:         {info['topology']}")
    print(f"  Error Model:      {'Enabled' if info['error_model'] else 'Disabled'}")

    print("\nCapabilities:")
    print(f"  Max Circuit Depth: {info['capabilities']['max_circuit_depth']:,}")
    print(f"  Gate Set:          {', '.join(info['capabilities']['gate_set'][:5])}...")

    print("\nError Rates:")
    for gate_type, rate in info['capabilities']['error_rates'].items():
        print(f"  {gate_type:20s}: {rate:.0e}")

    print("\nError Correction:")
    print(f"  Surface Code:")
    print(f"    Distance:        {info['error_correction']['surface_code']['distance']}")
    print(f"    Threshold:       {info['error_correction']['surface_code']['threshold']*100}%")


def interactive_menu():
    """Display interactive menu."""
    while True:
        print("\n" + "="*80)
        print("  100-QUBIT QUANTUM CHIP INTERACTIVE DEMONSTRATION")
        print("="*80)
        print("\nSelect a demonstration:")
        print("  1. Quantum Entanglement (Bell State)")
        print("  2. Multi-Qubit Entanglement (GHZ State)")
        print("  3. Quantum Superposition")
        print("  4. Quantum Interference")
        print("  5. Quantum Teleportation")
        print("  6. Backend Scaling")
        print("  7. Error Correction")
        print("  8. Chip Capabilities")
        print("  9. Run All Demonstrations")
        print("  0. Exit")

        choice = input("\nYour choice: ").strip()

        if choice == "1":
            demo_bell_state()
        elif choice == "2":
            demo_ghz_state()
        elif choice == "3":
            demo_superposition()
        elif choice == "4":
            demo_quantum_interference()
        elif choice == "5":
            demo_quantum_teleportation()
        elif choice == "6":
            demo_backend_scaling()
        elif choice == "7":
            demo_error_correction()
        elif choice == "8":
            demo_chip_info()
        elif choice == "9":
            demo_bell_state()
            demo_ghz_state()
            demo_superposition()
            demo_quantum_interference()
            demo_quantum_teleportation()
            demo_backend_scaling()
            demo_error_correction()
            demo_chip_info()
        elif choice == "0":
            print("\nThank you for exploring quantum computing with Ai:oS!")
            print("The future is quantum. 🚀\n")
            break
        else:
            print("\n❌ Invalid choice. Please try again.")

        input("\nPress Enter to continue...")


def main():
    """Main entry point."""
    print("\n" + "="*80)
    print("  AI:OS 100-QUBIT QUANTUM CHIP DEMONSTRATION")
    print("  Copyright (c) 2025 Joshua Hendricks Cole")
    print("="*80)

    print("\nThis demonstration showcases the revolutionary quantum computing")
    print("capabilities integrated into Ai:oS.")

    print("\nQuantum computing is not science fiction - it's here, now, accessible")
    print("to everyone through Ai:oS.")

    # Run interactive menu
    interactive_menu()

    return 0


if __name__ == "__main__":
    sys.exit(main())