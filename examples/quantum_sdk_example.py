#!/usr/bin/env python
"""
Quantum SDK Integration Examples for Ai:oS

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This demonstrates the full capabilities of the quantum computing infrastructure.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.quantum_agent_enhanced import (
    EnhancedQuantumAgent,
    QuantumBackend,
    QuantumAlgorithmType
)


def example_multi_sdk_circuits():
    """Demonstrate creating circuits with different SDKs."""
    print("\n" + "="*70)
    print("MULTI-SDK QUANTUM CIRCUIT CREATION")
    print("="*70)

    agent = EnhancedQuantumAgent()

    # Test each backend
    backends = [
        QuantumBackend.QISKIT,
        QuantumBackend.CIRQ,
        QuantumBackend.PENNYLANE,
        QuantumBackend.STRAWBERRY_FIELDS,
        QuantumBackend.CUSTOM
    ]

    for backend in backends:
        print(f"\n[{backend.value.upper()}] Creating quantum circuits...")

        # Skip if not available
        if not agent.backends.get(backend.value, {}).get("available"):
            print(f"  ⚠️  {backend.value} is not installed")
            continue

        # Create different circuit types
        circuit_types = ["bell_state", "ghz", "superposition"]

        for circuit_type in circuit_types:
            try:
                result = agent.create_quantum_circuit(
                    num_qubits=4,
                    backend=backend,
                    circuit_type=circuit_type
                )

                if result["status"] == "success":
                    print(f"  ✓ {circuit_type}: {result['description']}")
                    print(f"    Creation time: {result['creation_time_seconds']:.4f}s")
                else:
                    print(f"  ✗ {circuit_type}: {result.get('message', 'Failed')}")

            except Exception as e:
                print(f"  ✗ {circuit_type}: Error - {str(e)}")


def example_vqe_algorithm():
    """Demonstrate VQE across multiple backends."""
    print("\n" + "="*70)
    print("VARIATIONAL QUANTUM EIGENSOLVER (VQE)")
    print("="*70)

    agent = EnhancedQuantumAgent()

    # Run VQE on different backends
    backends = [QuantumBackend.QISKIT, QuantumBackend.PENNYLANE, QuantumBackend.CUSTOM]

    for backend in backends:
        if not agent.backends.get(backend.value, {}).get("available"):
            continue

        print(f"\n[{backend.value.upper()}] Running VQE...")

        try:
            result = agent.run_quantum_algorithm(
                algorithm=QuantumAlgorithmType.VQE,
                backend=backend,
                num_qubits=3,
                hamiltonian="ZZ"
            )

            if result["status"] == "success":
                energy = result["result"].get("ground_state_energy", "N/A")
                runtime = result["runtime_seconds"]
                print(f"  ✓ Ground state energy: {energy}")
                print(f"    Runtime: {runtime:.4f}s")
            else:
                print(f"  ✗ Error: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")


def example_qaoa_algorithm():
    """Demonstrate QAOA for optimization."""
    print("\n" + "="*70)
    print("QUANTUM APPROXIMATE OPTIMIZATION ALGORITHM (QAOA)")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.QISKIT.value, {}).get("available"):
        print("\n[QISKIT] Running QAOA for Max-Cut problem...")

        try:
            result = agent.run_quantum_algorithm(
                algorithm=QuantumAlgorithmType.QAOA,
                backend=QuantumBackend.QISKIT,
                num_qubits=4
            )

            if result["status"] == "success":
                optimal = result["result"].get("optimal_value", "N/A")
                print(f"  ✓ Optimal value: {optimal}")
                print(f"    Runtime: {result['runtime_seconds']:.4f}s")
            else:
                print(f"  ✗ Error: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    else:
        print("  ⚠️  Qiskit not available for QAOA")


def example_grover_algorithm():
    """Demonstrate Grover's search algorithm."""
    print("\n" + "="*70)
    print("GROVER'S SEARCH ALGORITHM")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.QISKIT.value, {}).get("available"):
        print("\n[QISKIT] Searching for marked state '101'...")

        try:
            result = agent.run_quantum_algorithm(
                algorithm=QuantumAlgorithmType.GROVER,
                backend=QuantumBackend.QISKIT,
                num_qubits=3,
                marked_state="101"
            )

            if result["status"] == "success":
                grover_result = result["result"]
                found = grover_result.get("found_state", "N/A")
                success = grover_result.get("success", False)
                iterations = grover_result.get("iterations", 0)

                print(f"  ✓ Found state: {found}")
                print(f"    Success: {success}")
                print(f"    Iterations: {iterations}")
                print(f"    Runtime: {result['runtime_seconds']:.4f}s")

                # Show measurement distribution
                counts = grover_result.get("measurement_counts", {})
                if counts:
                    print("    Measurement distribution:")
                    for state, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                        print(f"      |{state}⟩: {count}/1000")
            else:
                print(f"  ✗ Error: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    else:
        print("  ⚠️  Qiskit not available for Grover's algorithm")


def example_quantum_fourier_transform():
    """Demonstrate Quantum Fourier Transform."""
    print("\n" + "="*70)
    print("QUANTUM FOURIER TRANSFORM (QFT)")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.QISKIT.value, {}).get("available"):
        print("\n[QISKIT] Creating QFT circuit...")

        try:
            result = agent.run_quantum_algorithm(
                algorithm=QuantumAlgorithmType.QFT,
                backend=QuantumBackend.QISKIT,
                num_qubits=5
            )

            if result["status"] == "success":
                qft_result = result["result"]
                depth = qft_result.get("circuit_depth", "N/A")
                gates = qft_result.get("num_gates", "N/A")

                print(f"  ✓ QFT circuit created")
                print(f"    Circuit depth: {depth}")
                print(f"    Number of gates: {gates}")
                print(f"    Runtime: {result['runtime_seconds']:.4f}s")
            else:
                print(f"  ✗ Error: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    else:
        print("  ⚠️  Qiskit not available for QFT")


def example_deutsch_algorithm():
    """Demonstrate Deutsch's algorithm."""
    print("\n" + "="*70)
    print("DEUTSCH'S ALGORITHM")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.QISKIT.value, {}).get("available"):
        print("\n[QISKIT] Determining if function is constant or balanced...")

        try:
            result = agent.run_quantum_algorithm(
                algorithm=QuantumAlgorithmType.DEUTSCH,
                backend=QuantumBackend.QISKIT
            )

            if result["status"] == "success":
                deutsch_result = result["result"]
                func_type = deutsch_result.get("function_type", "N/A")
                counts = deutsch_result.get("measurement_counts", {})

                print(f"  ✓ Function type: {func_type}")
                print(f"    Measurement counts: {counts}")
                print(f"    Runtime: {result['runtime_seconds']:.4f}s")
            else:
                print(f"  ✗ Error: {result.get('error', 'Unknown')}")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    else:
        print("  ⚠️  Qiskit not available for Deutsch's algorithm")


def example_backend_benchmark():
    """Benchmark all available quantum backends."""
    print("\n" + "="*70)
    print("QUANTUM BACKEND BENCHMARK")
    print("="*70)

    agent = EnhancedQuantumAgent()

    print("\nBenchmarking all backends with 5 qubits...")
    benchmark_result = agent.benchmark_backends(num_qubits=5)

    print("\n📊 Benchmark Results:")
    print(f"  Total backends: {benchmark_result['total_backends']}")
    print(f"  Available backends: {benchmark_result['available_backends']}")
    print(f"  Qubits tested: {benchmark_result['num_qubits_tested']}")

    print("\n  Performance Metrics:")
    for backend, metrics in benchmark_result["benchmark_results"].items():
        if metrics.get("available"):
            print(f"\n  [{backend.upper()}]")
            print(f"    Version: {metrics.get('version', 'N/A')}")
            print(f"    Circuit creation: {metrics.get('circuit_creation_time', 0):.4f}s")

            if 'vqe_time' in metrics:
                print(f"    VQE runtime: {metrics['vqe_time']:.4f}s")
                print(f"    VQE success: {metrics['vqe_success']}")

            features = metrics.get('features', [])
            if features:
                print(f"    Features: {', '.join(features[:3])}")
        else:
            print(f"\n  [{backend.upper()}] Not installed")


def example_photonic_quantum():
    """Demonstrate photonic quantum computing with Strawberry Fields."""
    print("\n" + "="*70)
    print("PHOTONIC QUANTUM COMPUTING")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.STRAWBERRY_FIELDS.value, {}).get("available"):
        print("\n[STRAWBERRY FIELDS] Creating photonic quantum states...")

        circuit_types = ["bell_state", "ghz", "superposition"]

        for circuit_type in circuit_types:
            try:
                result = agent.create_quantum_circuit(
                    num_qubits=3,  # Called modes in photonic systems
                    backend=QuantumBackend.STRAWBERRY_FIELDS,
                    circuit_type=circuit_type
                )

                if result["status"] == "success":
                    print(f"  ✓ {circuit_type}: {result['description']}")
                    print(f"    Creation time: {result['creation_time_seconds']:.4f}s")
                else:
                    print(f"  ✗ {circuit_type}: Failed")

            except Exception as e:
                print(f"  ✗ {circuit_type}: Error - {str(e)}")
    else:
        print("  ⚠️  Strawberry Fields not available")


def example_quantum_ml_integration():
    """Demonstrate quantum machine learning with PennyLane."""
    print("\n" + "="*70)
    print("QUANTUM MACHINE LEARNING")
    print("="*70)

    agent = EnhancedQuantumAgent()

    if agent.backends.get(QuantumBackend.PENNYLANE.value, {}).get("available"):
        print("\n[PENNYLANE] Quantum ML - Variational Classifier...")

        try:
            # Create a quantum circuit for ML
            result = agent.create_quantum_circuit(
                num_qubits=4,
                backend=QuantumBackend.PENNYLANE,
                circuit_type="superposition"
            )

            if result["status"] == "success":
                print(f"  ✓ Quantum ML circuit created")
                print(f"    Description: {result['description']}")
                print(f"    Creation time: {result['creation_time_seconds']:.4f}s")

                # Run VQE for parameter optimization
                vqe_result = agent.run_quantum_algorithm(
                    algorithm=QuantumAlgorithmType.VQE,
                    backend=QuantumBackend.PENNYLANE,
                    num_qubits=4
                )

                if vqe_result["status"] == "success":
                    energy = vqe_result["result"].get("ground_state_energy", "N/A")
                    print(f"  ✓ Optimization complete")
                    print(f"    Optimized energy: {energy}")
                    print(f"    Runtime: {vqe_result['runtime_seconds']:.4f}s")

        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
    else:
        print("  ⚠️  PennyLane not available for quantum ML")


def show_quantum_system_health():
    """Display comprehensive quantum system health."""
    print("\n" + "="*70)
    print("QUANTUM SYSTEM HEALTH CHECK")
    print("="*70)

    agent = EnhancedQuantumAgent()
    health = agent.get_quantum_health()

    print(f"\n🏥 System Status: {health['status'].upper()}")
    print(f"📊 Summary: {health['summary']}")

    details = health.get("details", {})

    # Show backend status
    print("\n📦 Installed Backends:")
    for backend_name, info in details.get("backends", {}).items():
        if info.get("available"):
            version = info.get("version", "N/A")
            print(f"  ✓ {backend_name}: v{version}")

            # Show features
            features = info.get("features", [])
            if features:
                print(f"    Features: {', '.join(features)}")

            # Show simulators/devices
            if "simulators" in info:
                print(f"    Simulators: {', '.join(info['simulators'][:3])}")
            elif "devices" in info:
                print(f"    Devices: {', '.join(info['devices'][:3])}")
            elif "engines" in info:
                print(f"    Engines: {', '.join(info['engines'])}")
        else:
            print(f"  ✗ {backend_name}: Not installed")

    # Show metrics
    metrics = details.get("metrics", {})
    if metrics:
        print("\n📈 Usage Metrics:")
        print(f"  Circuits created: {metrics.get('circuits_created', 0)}")
        print(f"  Algorithms run: {metrics.get('algorithms_run', 0)}")
        print(f"  Total qubits used: {metrics.get('total_qubits_used', 0)}")
        print(f"  Total runtime: {metrics.get('total_runtime_seconds', 0):.2f}s")

    # Show available algorithms
    algorithms = details.get("algorithms_available", [])
    if algorithms:
        print("\n🧮 Available Algorithms:")
        for algo in algorithms:
            print(f"  • {algo}")


def main():
    """Run all quantum SDK examples."""
    print("\n" + "="*80)
    print(" " * 20 + "QUANTUM SDK INTEGRATION SHOWCASE")
    print(" " * 15 + "Ai:oS Quantum Computing Infrastructure")
    print("="*80)

    # Run all examples
    show_quantum_system_health()
    example_multi_sdk_circuits()
    example_vqe_algorithm()
    example_qaoa_algorithm()
    example_grover_algorithm()
    example_quantum_fourier_transform()
    example_deutsch_algorithm()
    example_photonic_quantum()
    example_quantum_ml_integration()
    example_backend_benchmark()

    # Final summary
    print("\n" + "="*80)
    print(" " * 25 + "QUANTUM SDK DEMO COMPLETE")
    print("="*80)

    print("\n✨ Successfully demonstrated:")
    print("  • Multi-SDK quantum circuit creation")
    print("  • VQE optimization across backends")
    print("  • QAOA for combinatorial optimization")
    print("  • Grover's quantum search")
    print("  • Quantum Fourier Transform")
    print("  • Deutsch's algorithm")
    print("  • Photonic quantum computing")
    print("  • Quantum machine learning")
    print("  • Cross-backend benchmarking")

    print("\n🌐 Websites:")
    print("  • https://aios.is")
    print("  • https://thegavl.com")
    print("  • https://red-team-tools.aios.is")

    print("\nCopyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).")
    print("All Rights Reserved. PATENT PENDING.\n")


if __name__ == "__main__":
    main()