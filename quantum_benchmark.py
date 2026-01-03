#!/usr/bin/env python3
"""
Comprehensive Quantum Computing Benchmark for Ai:oS
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Benchmarks quantum simulation performance across:
- Intel x86_64 vs Apple Silicon ARM
- CPU vs GPU vs MPS acceleration
- Docker vs QEMU vs native execution
"""

import os
import sys
import time
import json
import platform
import argparse
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import numpy as np

# Import quantum engines
try:
    from quantum_virtualization import QuantumVirtualizationEngine, QuantumVMConfig, QuantumBackend
    from quantum_apple_silicon import AppleSiliconQuantumEngine
    QUANTUM_AVAILABLE = True
except ImportError:
    QUANTUM_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import qiskit
    from qiskit_aer import AerSimulator
    QISKIT_AVAILABLE = True
except ImportError:
    QISKIT_AVAILABLE = False

LOG = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Result from a single benchmark run."""
    name: str
    platform: str
    processor: str
    backend: str
    num_qubits: int
    execution_time: float
    gates_per_second: float
    memory_used_mb: float
    success: bool
    error: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class QuantumBenchmarkSuite:
    """Comprehensive quantum benchmark suite."""

    def __init__(self, output_dir: Path = None):
        """Initialize benchmark suite."""
        self.output_dir = output_dir or Path.home() / ".aios" / "quantum" / "benchmarks"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.results: List[BenchmarkResult] = []

        # Detect hardware
        self.platform_info = {
            "system": platform.system(),
            "processor": platform.processor(),
            "machine": platform.machine(),
            "python_version": platform.python_version(),
            "is_apple_silicon": self._is_apple_silicon()
        }

        if TORCH_AVAILABLE:
            self.platform_info["torch_version"] = torch.__version__
            self.platform_info["cuda_available"] = torch.cuda.is_available()
            if hasattr(torch.backends, 'mps'):
                self.platform_info["mps_available"] = torch.backends.mps.is_available()

        LOG.info(f"[info] Benchmark suite initialized")
        LOG.info(f"[info] Platform: {self.platform_info}")

    def _is_apple_silicon(self) -> bool:
        """Check if running on Apple Silicon."""
        return (
            platform.system() == "Darwin" and
            platform.machine() == "arm64"
        )

    async def benchmark_native_statevector(self, num_qubits: int) -> BenchmarkResult:
        """Benchmark native statevector simulation."""
        if not TORCH_AVAILABLE:
            return BenchmarkResult(
                name="native_statevector",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="unavailable",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error="PyTorch not available"
            )

        try:
            start_time = time.time()

            # Create statevector
            dim = 2 ** num_qubits
            state = torch.zeros(dim, dtype=torch.complex128)
            state[0] = 1.0

            # Apply gates
            num_gates = 2 * num_qubits

            # Hadamard gates
            for i in range(num_qubits):
                state = self._apply_h(state, i, num_qubits)

            # CNOT gates
            for i in range(num_qubits - 1):
                state = self._apply_cnot(state, i, i + 1, num_qubits)

            # Measure
            probs = torch.abs(state) ** 2
            samples = torch.multinomial(probs, 1000, replacement=True)

            execution_time = time.time() - start_time

            # Memory used (approximate)
            memory_mb = (dim * 16) / (1024 ** 2)  # 16 bytes per complex number

            return BenchmarkResult(
                name="native_statevector",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="cpu",
                num_qubits=num_qubits,
                execution_time=execution_time,
                gates_per_second=num_gates / execution_time,
                memory_used_mb=memory_mb,
                success=True
            )

        except Exception as e:
            return BenchmarkResult(
                name="native_statevector",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="cpu",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error=str(e)
            )

    def _apply_h(self, state, qubit, num_qubits):
        """Apply Hadamard gate."""
        dim = 2 ** num_qubits
        sqrt2 = 1.0 / np.sqrt(2.0)
        bit_mask = 1 << (num_qubits - qubit - 1)

        state_np = state.numpy()
        for i in range(0, dim, 2 * (bit_mask + 1)):
            for j in range(i, i + bit_mask):
                k = j | bit_mask
                temp = state_np[j]
                state_np[j] = sqrt2 * (temp + state_np[k])
                state_np[k] = sqrt2 * (temp - state_np[k])

        return torch.from_numpy(state_np)

    def _apply_cnot(self, state, control, target, num_qubits):
        """Apply CNOT gate."""
        dim = 2 ** num_qubits
        control_mask = 1 << (num_qubits - control - 1)
        target_mask = 1 << (num_qubits - target - 1)

        state_np = state.numpy()
        for i in range(dim):
            if (i & control_mask) and not (i & target_mask):
                j = i | target_mask
                state_np[i], state_np[j] = state_np[j], state_np[i]

        return torch.from_numpy(state_np)

    async def benchmark_apple_silicon(self, num_qubits: int) -> BenchmarkResult:
        """Benchmark Apple Silicon optimized simulation."""
        if not self._is_apple_silicon() or not QUANTUM_AVAILABLE:
            return BenchmarkResult(
                name="apple_silicon",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="unavailable",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error="Apple Silicon or quantum libraries not available"
            )

        try:
            engine = AppleSiliconQuantumEngine()

            start_time = time.time()

            # Create state
            state = engine.create_statevector(num_qubits)

            # Apply gates
            for i in range(num_qubits):
                state = engine.apply_hadamard(state, i, num_qubits)

            for i in range(num_qubits - 1):
                state = engine.apply_cnot(state, i, i + 1, num_qubits)

            # Measure
            counts = engine.measure(state, shots=1000)

            execution_time = time.time() - start_time

            num_gates = 2 * num_qubits
            memory_mb = (2 ** num_qubits * 8) / (1024 ** 2)  # complex64

            return BenchmarkResult(
                name="apple_silicon",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend=engine.device,
                num_qubits=num_qubits,
                execution_time=execution_time,
                gates_per_second=num_gates / execution_time,
                memory_used_mb=memory_mb,
                success=True
            )

        except Exception as e:
            return BenchmarkResult(
                name="apple_silicon",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="error",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error=str(e)
            )

    async def benchmark_qiskit_aer(self, num_qubits: int) -> BenchmarkResult:
        """Benchmark Qiskit Aer simulator."""
        if not QISKIT_AVAILABLE:
            return BenchmarkResult(
                name="qiskit_aer",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="unavailable",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error="Qiskit not available"
            )

        try:
            from qiskit import QuantumCircuit, transpile

            # Create circuit
            qc = QuantumCircuit(num_qubits)

            # Apply gates
            for i in range(num_qubits):
                qc.h(i)

            for i in range(num_qubits - 1):
                qc.cx(i, i + 1)

            qc.measure_all()

            # Run simulation
            simulator = AerSimulator()

            start_time = time.time()

            compiled = transpile(qc, simulator)
            job = simulator.run(compiled, shots=1000)
            result = job.result()
            counts = result.get_counts()

            execution_time = time.time() - start_time

            num_gates = 2 * num_qubits

            return BenchmarkResult(
                name="qiskit_aer",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="statevector",
                num_qubits=num_qubits,
                execution_time=execution_time,
                gates_per_second=num_gates / execution_time,
                memory_used_mb=0,  # Not easily measurable
                success=True
            )

        except Exception as e:
            return BenchmarkResult(
                name="qiskit_aer",
                platform=self.platform_info["system"],
                processor=self.platform_info["processor"],
                backend="error",
                num_qubits=num_qubits,
                execution_time=0,
                gates_per_second=0,
                memory_used_mb=0,
                success=False,
                error=str(e)
            )

    async def run_comprehensive_benchmark(
        self,
        qubit_counts: List[int] = [5, 10, 15, 20, 25]
    ) -> Dict[str, Any]:
        """Run comprehensive benchmark across all backends."""
        LOG.info("[info] Starting comprehensive quantum benchmark")

        all_results = []

        for num_qubits in qubit_counts:
            LOG.info(f"[info] Benchmarking {num_qubits} qubits...")

            # Run all benchmarks for this qubit count
            tasks = [
                self.benchmark_native_statevector(num_qubits),
                self.benchmark_apple_silicon(num_qubits),
                self.benchmark_qiskit_aer(num_qubits)
            ]

            results = await asyncio.gather(*tasks)
            all_results.extend(results)
            self.results.extend(results)

            # Print immediate results
            for result in results:
                if result.success:
                    LOG.info(
                        f"[info]   {result.name} ({result.backend}): "
                        f"{result.execution_time:.3f}s "
                        f"({result.gates_per_second:.1f} gates/sec)"
                    )
                else:
                    LOG.warning(f"[warn]   {result.name}: {result.error}")

        # Generate report
        report = self._generate_report()

        # Save results
        self._save_results(report)

        return report

    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report."""
        report = {
            "platform_info": self.platform_info,
            "timestamp": time.time(),
            "results": [asdict(r) for r in self.results],
            "summary": {}
        }

        # Group results by backend
        backend_results = {}
        for result in self.results:
            if result.success:
                backend = f"{result.name}_{result.backend}"
                if backend not in backend_results:
                    backend_results[backend] = []
                backend_results[backend].append(result)

        # Calculate summary statistics
        for backend, results in backend_results.items():
            if results:
                avg_time = np.mean([r.execution_time for r in results])
                avg_gates = np.mean([r.gates_per_second for r in results])

                report["summary"][backend] = {
                    "num_benchmarks": len(results),
                    "avg_execution_time": avg_time,
                    "avg_gates_per_second": avg_gates,
                    "max_qubits": max([r.num_qubits for r in results])
                }

        return report

    def _save_results(self, report: Dict[str, Any]) -> None:
        """Save benchmark results to JSON."""
        timestamp = int(time.time())
        output_file = self.output_dir / f"benchmark_{timestamp}.json"

        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        LOG.info(f"[info] Results saved to {output_file}")

        # Also save as latest
        latest_file = self.output_dir / "benchmark_latest.json"
        with open(latest_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

    def print_comparison(self) -> None:
        """Print performance comparison table."""
        if not self.results:
            print("[warn] No results to compare")
            return

        print("\n" + "="*80)
        print("QUANTUM PERFORMANCE COMPARISON")
        print("="*80)

        # Group by qubit count
        qubit_groups = {}
        for result in self.results:
            if result.success:
                if result.num_qubits not in qubit_groups:
                    qubit_groups[result.num_qubits] = []
                qubit_groups[result.num_qubits].append(result)

        for qubits in sorted(qubit_groups.keys()):
            results = qubit_groups[qubits]

            print(f"\n{qubits} Qubits:")
            print(f"{'Backend':<30} {'Time (s)':<12} {'Gates/sec':<15} {'Memory (MB)':<12}")
            print("-" * 70)

            for result in sorted(results, key=lambda r: r.execution_time):
                backend_name = f"{result.name} ({result.backend})"
                print(f"{backend_name:<30} {result.execution_time:>10.3f}  "
                      f"{result.gates_per_second:>13.1f}  {result.memory_used_mb:>10.1f}")

        print("\n" + "="*80)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Comprehensive quantum computing benchmark for Ai:oS"
    )
    parser.add_argument(
        "--qubits",
        type=int,
        nargs="+",
        default=[5, 10, 15, 20],
        help="Qubit counts to benchmark"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for results"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s"
    )

    print("\n" + "="*80)
    print("QUANTUM COMPUTING BENCHMARK FOR Ai:oS")
    print("Copyright (c) 2025 Corporation of Light")
    print("="*80)

    # Run benchmark
    suite = QuantumBenchmarkSuite(output_dir=args.output)
    report = await suite.run_comprehensive_benchmark(qubit_counts=args.qubits)

    # Print comparison
    suite.print_comparison()

    # Print summary
    print("\nSummary:")
    for backend, stats in report["summary"].items():
        print(f"  {backend}:")
        print(f"    Avg time: {stats['avg_execution_time']:.3f}s")
        print(f"    Avg gates/sec: {stats['avg_gates_per_second']:.1f}")
        print(f"    Max qubits: {stats['max_qubits']}")

    print(f"\nResults saved to: {suite.output_dir}")


if __name__ == "__main__":
    asyncio.run(main())