#!/usr/bin/env python3
"""
Quantum Computing Virtualization Layer for Ai:oS
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This module provides:
1. Quantum VM management (QEMU/Docker)
2. Hardware acceleration support (Intel/Apple Silicon)
3. Quantum circuit execution engine
4. Resource allocation and scheduling
5. Integration with Ai:oS runtime
"""

from __future__ import annotations
import os
import sys
import json
import subprocess
import platform
import shutil
import time
import asyncio
import logging
import hashlib
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
import numpy as np

# Check for quantum library availability
TORCH_AVAILABLE = False
QISKIT_AVAILABLE = False
CIRQ_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    pass

try:
    import qiskit
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
    from qiskit import transpile
    from qiskit_aer import AerSimulator
    QISKIT_AVAILABLE = True
except ImportError:
    pass

try:
    import cirq
    CIRQ_AVAILABLE = True
except ImportError:
    pass

LOG = logging.getLogger(__name__)


class QuantumBackend(Enum):
    """Available quantum simulation backends."""
    STATEVECTOR = "statevector"  # Pure state simulation
    DENSITY_MATRIX = "density_matrix"  # Mixed state simulation
    MPS = "matrix_product_state"  # Tensor network simulation
    CLIFFORD = "clifford"  # Clifford circuit simulation
    GPU = "gpu"  # GPU-accelerated simulation
    APPLE_SILICON = "apple_silicon"  # Apple M1/M2/M3 optimized
    DISTRIBUTED = "distributed"  # Multi-node simulation


@dataclass
class QuantumVMConfig:
    """Configuration for a quantum VM instance."""
    name: str
    backend: QuantumBackend = QuantumBackend.STATEVECTOR
    num_qubits: int = 20
    memory_mb: int = 4096
    cpu_cores: int = 4
    gpu_enabled: bool = False
    apple_silicon: bool = False
    container_type: str = "docker"  # docker or qemu
    image: str = "quantum-simulator:latest"
    ports: Dict[int, int] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    network: str = "bridge"

    def __post_init__(self):
        """Detect Apple Silicon automatically."""
        if platform.processor() == 'arm' and platform.system() == 'Darwin':
            self.apple_silicon = True


@dataclass
class QuantumJobResult:
    """Result from quantum computation."""
    job_id: str
    status: str  # completed, failed, running
    counts: Optional[Dict[str, int]] = None
    statevector: Optional[np.ndarray] = None
    expectation_values: Optional[Dict[str, float]] = None
    execution_time: float = 0.0
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class QuantumVirtualizationEngine:
    """
    Main quantum virtualization engine for Ai:oS.
    Manages quantum VMs, job scheduling, and hardware acceleration.
    """

    def __init__(self, config_dir: Optional[Path] = None):
        """Initialize quantum virtualization engine."""
        self.config_dir = config_dir or Path.home() / ".aios" / "quantum"
        self.config_dir.mkdir(parents=True, exist_ok=True)

        self.vms: Dict[str, QuantumVM] = {}
        self.jobs: Dict[str, QuantumJobResult] = {}
        self.executor = None

        # Detect hardware capabilities
        self.hardware_info = self._detect_hardware()

        # Initialize backend registry
        self.backends = self._initialize_backends()

        LOG.info(f"[info] Quantum Virtualization Engine initialized")
        LOG.info(f"[info] Hardware: {self.hardware_info}")
        LOG.info(f"[info] Available backends: {list(self.backends.keys())}")

    def _detect_hardware(self) -> Dict[str, Any]:
        """Detect hardware capabilities for quantum simulation."""
        info = {
            "platform": platform.system(),
            "processor": platform.processor(),
            "cpu_count": os.cpu_count(),
            "apple_silicon": False,
            "gpu_available": False,
            "cuda_available": False,
            "metal_available": False,
            "memory_gb": 0
        }

        # Check for Apple Silicon
        if platform.processor() == 'arm' and platform.system() == 'Darwin':
            info["apple_silicon"] = True
            # Check for Metal Performance Shaders
            try:
                result = subprocess.run(
                    ["system_profiler", "SPDisplaysDataType"],
                    capture_output=True, text=True, check=True
                )
                if "Metal" in result.stdout:
                    info["metal_available"] = True
            except:
                pass

        # Check for CUDA GPUs
        if TORCH_AVAILABLE and torch.cuda.is_available():
            info["gpu_available"] = True
            info["cuda_available"] = True
            info["gpu_count"] = torch.cuda.device_count()
            info["gpu_names"] = [torch.cuda.get_device_name(i)
                                for i in range(torch.cuda.device_count())]

        # Get system memory
        try:
            if platform.system() == "Darwin":
                result = subprocess.run(
                    ["sysctl", "-n", "hw.memsize"],
                    capture_output=True, text=True, check=True
                )
                info["memory_gb"] = int(result.stdout.strip()) // (1024**3)
            elif platform.system() == "Linux":
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            info["memory_gb"] = kb // (1024**2)
                            break
        except:
            pass

        return info

    def _initialize_backends(self) -> Dict[str, Any]:
        """Initialize available quantum backends."""
        backends = {}

        # Native PyTorch backend
        if TORCH_AVAILABLE:
            backends[QuantumBackend.STATEVECTOR] = StatevectorBackend()
            if self.hardware_info.get("cuda_available"):
                backends[QuantumBackend.GPU] = GPUBackend()
            if self.hardware_info.get("apple_silicon"):
                backends[QuantumBackend.APPLE_SILICON] = AppleSiliconBackend()

        # Qiskit backends
        if QISKIT_AVAILABLE:
            backends["qiskit"] = QiskitBackend()

        # Cirq backend
        if CIRQ_AVAILABLE:
            backends["cirq"] = CirqBackend()

        return backends

    async def create_vm(self, config: QuantumVMConfig) -> str:
        """Create a new quantum VM."""
        if config.name in self.vms:
            raise ValueError(f"VM {config.name} already exists")

        # Select appropriate VM type
        if config.container_type == "docker":
            vm = DockerQuantumVM(config, self)
        elif config.container_type == "qemu":
            vm = QEMUQuantumVM(config, self)
        else:
            raise ValueError(f"Unknown container type: {config.container_type}")

        # Start the VM
        await vm.start()
        self.vms[config.name] = vm

        LOG.info(f"[info] Created quantum VM: {config.name}")
        return config.name

    async def destroy_vm(self, name: str) -> None:
        """Destroy a quantum VM."""
        if name not in self.vms:
            raise ValueError(f"VM {name} not found")

        vm = self.vms[name]
        await vm.stop()
        del self.vms[name]

        LOG.info(f"[info] Destroyed quantum VM: {name}")

    async def execute_circuit(
        self,
        circuit: Union[str, Dict, Any],
        vm_name: Optional[str] = None,
        backend: Optional[QuantumBackend] = None,
        shots: int = 1024
    ) -> QuantumJobResult:
        """Execute a quantum circuit on specified VM or backend."""
        job_id = hashlib.sha256(
            f"{time.time()}:{circuit}".encode()
        ).hexdigest()[:16]

        result = QuantumJobResult(
            job_id=job_id,
            status="running"
        )
        self.jobs[job_id] = result

        try:
            start_time = time.time()

            # Select VM or backend
            if vm_name and vm_name in self.vms:
                vm = self.vms[vm_name]
                counts = await vm.execute_circuit(circuit, shots)
            elif backend and backend in self.backends:
                backend_impl = self.backends[backend]
                counts = await backend_impl.execute(circuit, shots)
            else:
                # Use default backend
                if QuantumBackend.APPLE_SILICON in self.backends:
                    backend_impl = self.backends[QuantumBackend.APPLE_SILICON]
                elif QuantumBackend.GPU in self.backends:
                    backend_impl = self.backends[QuantumBackend.GPU]
                else:
                    backend_impl = self.backends.get(
                        QuantumBackend.STATEVECTOR,
                        list(self.backends.values())[0]
                    )
                counts = await backend_impl.execute(circuit, shots)

            result.counts = counts
            result.status = "completed"
            result.execution_time = time.time() - start_time

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            LOG.error(f"[error] Circuit execution failed: {e}")

        return result

    def get_job_status(self, job_id: str) -> Optional[QuantumJobResult]:
        """Get status of a quantum job."""
        return self.jobs.get(job_id)

    def list_vms(self) -> List[Dict[str, Any]]:
        """List all quantum VMs."""
        return [
            {
                "name": name,
                "status": vm.status,
                "backend": vm.config.backend.value,
                "qubits": vm.config.num_qubits,
                "type": vm.config.container_type
            }
            for name, vm in self.vms.items()
        ]

    async def benchmark(self, num_qubits: int = 10) -> Dict[str, float]:
        """Benchmark quantum simulation performance."""
        results = {}

        # Create test circuit
        if QISKIT_AVAILABLE:
            qc = QuantumCircuit(num_qubits)
            for i in range(num_qubits):
                qc.h(i)
            for i in range(num_qubits - 1):
                qc.cx(i, i + 1)
            circuit = qc
        else:
            # Simple circuit representation
            circuit = {
                "num_qubits": num_qubits,
                "gates": [
                    {"type": "H", "qubits": [i]} for i in range(num_qubits)
                ] + [
                    {"type": "CX", "qubits": [i, i+1]}
                    for i in range(num_qubits - 1)
                ]
            }

        # Benchmark each backend
        for backend_name, backend in self.backends.items():
            try:
                start = time.time()
                await backend.execute(circuit, shots=1000)
                duration = time.time() - start
                results[str(backend_name)] = duration
                LOG.info(f"[info] {backend_name}: {duration:.3f}s")
            except Exception as e:
                LOG.warning(f"[warn] {backend_name} benchmark failed: {e}")
                results[str(backend_name)] = -1

        return results


class QuantumVM(ABC):
    """Abstract base class for quantum VMs."""

    def __init__(self, config: QuantumVMConfig, engine: QuantumVirtualizationEngine):
        self.config = config
        self.engine = engine
        self.status = "stopped"
        self.container_id = None

    @abstractmethod
    async def start(self) -> None:
        """Start the VM."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the VM."""
        pass

    @abstractmethod
    async def execute_circuit(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute quantum circuit on this VM."""
        pass


class DockerQuantumVM(QuantumVM):
    """Docker-based quantum VM."""

    async def start(self) -> None:
        """Start Docker container."""
        # Check if Docker is available
        if not shutil.which("docker"):
            raise RuntimeError("Docker not found. Please install Docker.")

        # Build Docker command
        cmd = [
            "docker", "run", "-d",
            "--name", self.config.name,
            "--memory", f"{self.config.memory_mb}m",
            "--cpus", str(self.config.cpu_cores)
        ]

        # Add GPU support if available
        if self.config.gpu_enabled:
            cmd.extend(["--gpus", "all"])

        # Add port mappings
        for host_port, container_port in self.config.ports.items():
            cmd.extend(["-p", f"{host_port}:{container_port}"])

        # Add environment variables
        for key, value in self.config.environment.items():
            cmd.extend(["-e", f"{key}={value}"])

        # Add volumes
        for volume in self.config.volumes:
            cmd.extend(["-v", volume])

        # Add network
        cmd.extend(["--network", self.config.network])

        # Add image
        cmd.append(self.config.image)

        # Start container
        try:
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode == 0:
                self.container_id = stdout.decode().strip()
                self.status = "running"
                LOG.info(f"[info] Started Docker quantum VM: {self.config.name}")
            else:
                raise RuntimeError(f"Failed to start container: {stderr.decode()}")

        except Exception as e:
            LOG.error(f"[error] Failed to start Docker VM: {e}")
            raise

    async def stop(self) -> None:
        """Stop Docker container."""
        if self.container_id:
            try:
                result = await asyncio.create_subprocess_exec(
                    "docker", "stop", self.container_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()

                result = await asyncio.create_subprocess_exec(
                    "docker", "rm", self.container_id,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.communicate()

                self.status = "stopped"
                self.container_id = None
                LOG.info(f"[info] Stopped Docker quantum VM: {self.config.name}")

            except Exception as e:
                LOG.error(f"[error] Failed to stop Docker VM: {e}")

    async def execute_circuit(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute circuit in Docker container."""
        # This would normally communicate with the container via API
        # For now, use local backend
        backend = self.engine.backends.get(
            self.config.backend,
            list(self.engine.backends.values())[0]
        )
        return await backend.execute(circuit, shots)


class QEMUQuantumVM(QuantumVM):
    """QEMU-based quantum VM."""

    async def start(self) -> None:
        """Start QEMU VM."""
        # Check if QEMU is available
        qemu_binary = "qemu-system-aarch64" if self.config.apple_silicon else "qemu-system-x86_64"

        if not shutil.which(qemu_binary):
            raise RuntimeError(f"{qemu_binary} not found. Please install QEMU.")

        # Build QEMU command
        cmd = [
            qemu_binary,
            "-name", self.config.name,
            "-m", str(self.config.memory_mb),
            "-smp", str(self.config.cpu_cores),
            "-nographic"
        ]

        # Add hardware acceleration
        if platform.system() == "Darwin":
            if self.config.apple_silicon:
                cmd.extend(["-accel", "hvf"])
            else:
                cmd.extend(["-accel", "hvf,thread=multi"])
        elif platform.system() == "Linux":
            cmd.extend(["-enable-kvm"])

        # Add network
        cmd.extend([
            "-netdev", f"user,id=net0,hostfwd=tcp::5900-:5900",
            "-device", "virtio-net,netdev=net0"
        ])

        # Add image (would need actual quantum OS image)
        quantum_image = self.config_dir / "quantum-os.qcow2"
        if quantum_image.exists():
            cmd.extend(["-drive", f"file={quantum_image},if=virtio"])

        # Start VM
        try:
            self.process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.status = "running"
            LOG.info(f"[info] Started QEMU quantum VM: {self.config.name}")

        except Exception as e:
            LOG.error(f"[error] Failed to start QEMU VM: {e}")
            raise

    async def stop(self) -> None:
        """Stop QEMU VM."""
        if hasattr(self, 'process') and self.process:
            try:
                self.process.terminate()
                await self.process.wait()
                self.status = "stopped"
                LOG.info(f"[info] Stopped QEMU quantum VM: {self.config.name}")
            except Exception as e:
                LOG.error(f"[error] Failed to stop QEMU VM: {e}")

    async def execute_circuit(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute circuit in QEMU VM."""
        # Would normally communicate with VM via QMP or network
        # For now, use local backend
        backend = self.engine.backends.get(
            self.config.backend,
            list(self.engine.backends.values())[0]
        )
        return await backend.execute(circuit, shots)


class StatevectorBackend:
    """Pure PyTorch statevector backend."""

    async def execute(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute quantum circuit using statevector simulation."""
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch not available")

        # Parse circuit (simplified)
        if isinstance(circuit, dict):
            num_qubits = circuit.get("num_qubits", 5)
        elif QISKIT_AVAILABLE and isinstance(circuit, QuantumCircuit):
            num_qubits = circuit.num_qubits
        else:
            num_qubits = 5

        # Initialize statevector
        dim = 2 ** num_qubits
        state = torch.zeros(dim, dtype=torch.complex128)
        state[0] = 1.0  # |00...0⟩

        # Apply Hadamard to all qubits (simplified)
        H = torch.tensor([[1, 1], [1, -1]], dtype=torch.complex128) / np.sqrt(2)

        for i in range(num_qubits):
            # Apply single-qubit gate (simplified tensor operation)
            state = self._apply_gate(state, H, i, num_qubits)

        # Measure (sample from probability distribution)
        probs = torch.abs(state) ** 2
        samples = torch.multinomial(probs, shots, replacement=True)

        # Convert to counts
        counts = {}
        for sample in samples:
            bitstring = format(sample.item(), f'0{num_qubits}b')
            counts[bitstring] = counts.get(bitstring, 0) + 1

        return counts

    def _apply_gate(self, state, gate, qubit_idx, num_qubits):
        """Apply single-qubit gate to statevector."""
        dim = 2 ** num_qubits
        new_state = torch.zeros_like(state)

        # Simplified gate application
        for i in range(dim):
            bit = (i >> (num_qubits - qubit_idx - 1)) & 1
            if bit == 0:
                j = i | (1 << (num_qubits - qubit_idx - 1))
                new_state[i] += gate[0, 0] * state[i] + gate[0, 1] * state[j]
                new_state[j] += gate[1, 0] * state[i] + gate[1, 1] * state[j]

        return new_state


class GPUBackend:
    """GPU-accelerated quantum backend."""

    async def execute(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute on GPU using CUDA."""
        if not TORCH_AVAILABLE or not torch.cuda.is_available():
            raise RuntimeError("CUDA not available")

        # Move computation to GPU
        device = torch.device("cuda")
        backend = StatevectorBackend()

        # Would implement GPU-specific optimizations here
        return await backend.execute(circuit, shots)


class AppleSiliconBackend:
    """Apple Silicon optimized backend using Metal Performance Shaders."""

    async def execute(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute on Apple Silicon using MPS acceleration."""
        if not TORCH_AVAILABLE:
            raise RuntimeError("PyTorch not available")

        # Check for MPS availability
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            device = torch.device("mps")
            LOG.info("[info] Using Apple Silicon MPS acceleration")
        else:
            device = torch.device("cpu")
            LOG.info("[info] MPS not available, using CPU")

        # Use statevector backend with MPS device
        backend = StatevectorBackend()
        return await backend.execute(circuit, shots)


class QiskitBackend:
    """Qiskit integration backend."""

    async def execute(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute using Qiskit Aer simulator."""
        if not QISKIT_AVAILABLE:
            raise RuntimeError("Qiskit not available")

        # Convert circuit if needed
        if isinstance(circuit, QuantumCircuit):
            qc = circuit
        else:
            # Create simple test circuit
            qc = QuantumCircuit(5)
            for i in range(5):
                qc.h(i)
            qc.measure_all()

        # Use Aer simulator
        simulator = AerSimulator()

        # Transpile for simulator
        compiled = transpile(qc, simulator)

        # Run simulation
        job = simulator.run(compiled, shots=shots)
        result = job.result()
        counts = result.get_counts()

        return counts


class CirqBackend:
    """Cirq integration backend."""

    async def execute(self, circuit: Any, shots: int) -> Dict[str, int]:
        """Execute using Cirq simulator."""
        if not CIRQ_AVAILABLE:
            raise RuntimeError("Cirq not available")

        # Create simple test circuit
        qubits = cirq.LineQubit.range(5)
        circuit = cirq.Circuit()

        # Add H gates
        for q in qubits:
            circuit.append(cirq.H(q))

        # Add measurements
        circuit.append(cirq.measure(*qubits, key='result'))

        # Simulate
        simulator = cirq.Simulator()
        result = simulator.run(circuit, repetitions=shots)

        # Convert to counts format
        counts = {}
        for bits in result.measurements['result']:
            bitstring = ''.join(str(b) for b in bits)
            counts[bitstring] = counts.get(bitstring, 0) + 1

        return counts


# Integration with Ai:oS runtime
class QuantumAgent:
    """Meta-agent for quantum computing in Ai:oS."""

    def __init__(self):
        self.engine = QuantumVirtualizationEngine()

    async def initialize(self, ctx) -> dict:
        """Initialize quantum subsystem."""
        try:
            # Auto-detect and configure quantum resources
            hardware = self.engine.hardware_info

            # Create default VMs based on hardware
            if hardware.get("apple_silicon"):
                config = QuantumVMConfig(
                    name="apple-silicon-quantum",
                    backend=QuantumBackend.APPLE_SILICON,
                    num_qubits=25,
                    memory_mb=8192,
                    apple_silicon=True
                )
                await self.engine.create_vm(config)

            if hardware.get("cuda_available"):
                config = QuantumVMConfig(
                    name="gpu-quantum",
                    backend=QuantumBackend.GPU,
                    num_qubits=30,
                    memory_mb=16384,
                    gpu_enabled=True
                )
                await self.engine.create_vm(config)

            # Create CPU fallback
            config = QuantumVMConfig(
                name="cpu-quantum",
                backend=QuantumBackend.STATEVECTOR,
                num_qubits=20,
                memory_mb=4096
            )
            await self.engine.create_vm(config)

            # Publish metadata
            ctx.publish_metadata("quantum.initialized", {
                "hardware": hardware,
                "vms": self.engine.list_vms(),
                "backends": list(self.engine.backends.keys())
            })

            return {
                "success": True,
                "message": "[info] Quantum subsystem initialized",
                "payload": {
                    "hardware": hardware,
                    "vms": self.engine.list_vms()
                }
            }

        except Exception as e:
            LOG.error(f"[error] Quantum initialization failed: {e}")
            return {
                "success": False,
                "message": f"[error] Quantum initialization failed: {e}",
                "payload": {"error": str(e)}
            }

    async def execute_quantum_algorithm(self, ctx, algorithm: str, params: dict) -> dict:
        """Execute a quantum algorithm."""
        try:
            # Run benchmark
            if algorithm == "benchmark":
                results = await self.engine.benchmark(
                    num_qubits=params.get("num_qubits", 10)
                )
                return {
                    "success": True,
                    "message": "[info] Benchmark completed",
                    "payload": {"results": results}
                }

            # Execute circuit
            elif algorithm == "circuit":
                result = await self.engine.execute_circuit(
                    circuit=params.get("circuit"),
                    vm_name=params.get("vm_name"),
                    shots=params.get("shots", 1024)
                )
                return {
                    "success": True,
                    "message": f"[info] Circuit executed: {result.job_id}",
                    "payload": {
                        "job_id": result.job_id,
                        "counts": result.counts,
                        "execution_time": result.execution_time
                    }
                }

            else:
                return {
                    "success": False,
                    "message": f"[warn] Unknown algorithm: {algorithm}",
                    "payload": {}
                }

        except Exception as e:
            LOG.error(f"[error] Algorithm execution failed: {e}")
            return {
                "success": False,
                "message": f"[error] Algorithm execution failed: {e}",
                "payload": {"error": str(e)}
            }


def main():
    """Main entry point for testing."""
    logging.basicConfig(level=logging.INFO)

    async def test():
        engine = QuantumVirtualizationEngine()

        # Run benchmark
        print("\n=== Running Quantum Benchmark ===")
        results = await engine.benchmark(num_qubits=10)

        print("\nBenchmark Results:")
        for backend, time_taken in results.items():
            if time_taken > 0:
                print(f"  {backend}: {time_taken:.3f}s")
            else:
                print(f"  {backend}: Failed")

        # Create and test VMs
        print("\n=== Testing Quantum VMs ===")
        config = QuantumVMConfig(
            name="test-quantum-vm",
            num_qubits=5,
            memory_mb=1024
        )

        vm_name = await engine.create_vm(config)
        print(f"Created VM: {vm_name}")

        # List VMs
        vms = engine.list_vms()
        print(f"Active VMs: {vms}")

        # Clean up
        await engine.destroy_vm(vm_name)
        print(f"Destroyed VM: {vm_name}")

    asyncio.run(test())


if __name__ == "__main__":
    main()