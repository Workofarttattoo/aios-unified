#!/bin/bash

# Quantum Computing VM Setup for Ai:oS
# Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
#
# This script automates the setup of quantum computing environments for Ai:oS
# Supports: Docker, QEMU, Apple Silicon optimization

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AIOS_QUANTUM_DIR="${HOME}/.aios/quantum"
DOCKER_IMAGE="quantum-simulator:latest"
QEMU_IMAGE="${AIOS_QUANTUM_DIR}/quantum-os.qcow2"
LOG_FILE="${AIOS_QUANTUM_DIR}/setup.log"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Function to check if running on Apple Silicon
is_apple_silicon() {
    if [[ "$(uname -m)" == "arm64" ]] && [[ "$(uname -s)" == "Darwin" ]]; then
        return 0
    fi
    return 1
}

# Function to check system requirements
check_requirements() {
    print_info "Checking system requirements..."

    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi

    # Check for Docker
    if command -v docker &> /dev/null; then
        print_status "Docker found: $(docker --version)"
        DOCKER_AVAILABLE=1
    else
        print_warning "Docker not found - Docker-based VMs will be unavailable"
        DOCKER_AVAILABLE=0
    fi

    # Check for QEMU
    if is_apple_silicon; then
        QEMU_BINARY="qemu-system-aarch64"
    else
        QEMU_BINARY="qemu-system-x86_64"
    fi

    if command -v $QEMU_BINARY &> /dev/null; then
        print_status "QEMU found: $($QEMU_BINARY --version | head -n1)"
        QEMU_AVAILABLE=1
    else
        print_warning "QEMU not found - QEMU-based VMs will be unavailable"
        QEMU_AVAILABLE=0
    fi

    # Check for hardware acceleration
    if is_apple_silicon; then
        print_status "Apple Silicon detected - Metal acceleration available"
        ACCELERATION="hvf"
    elif [[ "$(uname -s)" == "Darwin" ]]; then
        if sysctl -n machdep.cpu.features | grep -q "VMX"; then
            print_status "Intel Mac detected - HVF acceleration available"
            ACCELERATION="hvf"
        fi
    elif [[ "$(uname -s)" == "Linux" ]]; then
        if grep -q "vmx\|svm" /proc/cpuinfo; then
            print_status "KVM acceleration available"
            ACCELERATION="kvm"
        fi
    else
        print_warning "No hardware acceleration detected"
        ACCELERATION="none"
    fi

    # Check available memory
    if [[ "$(uname -s)" == "Darwin" ]]; then
        TOTAL_MEM=$(($(sysctl -n hw.memsize) / 1024 / 1024 / 1024))
    elif [[ "$(uname -s)" == "Linux" ]]; then
        TOTAL_MEM=$(($(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024))
    fi
    print_info "Total system memory: ${TOTAL_MEM}GB"

    if [[ $TOTAL_MEM -lt 8 ]]; then
        print_warning "Less than 8GB RAM - quantum simulations may be limited"
    fi
}

# Function to create directory structure
setup_directories() {
    print_info "Setting up quantum directory structure..."

    mkdir -p "${AIOS_QUANTUM_DIR}"/{images,configs,scripts,benchmarks,logs}

    print_status "Created directory structure at ${AIOS_QUANTUM_DIR}"
}

# Function to install Python dependencies
install_python_deps() {
    print_info "Installing Python quantum libraries..."

    # Create requirements file
    cat > "${AIOS_QUANTUM_DIR}/requirements.txt" << EOF
# Core quantum libraries
qiskit>=1.0.0
qiskit-aer>=0.13.0
cirq>=1.0.0
pennylane>=0.30.0

# Optimization and ML
torch>=2.0.0
numpy>=1.24.0
scipy>=1.10.0

# Visualization
matplotlib>=3.6.0

# Utilities
psutil>=5.9.0
pyyaml>=6.0
EOF

    # Install dependencies
    if pip3 install -r "${AIOS_QUANTUM_DIR}/requirements.txt" >> "$LOG_FILE" 2>&1; then
        print_status "Python quantum libraries installed"
    else
        print_warning "Some Python libraries failed to install - check $LOG_FILE"
    fi
}

# Function to build Docker image
build_docker_image() {
    if [[ $DOCKER_AVAILABLE -eq 0 ]]; then
        return
    fi

    print_info "Building Docker quantum simulator image..."

    # Create Dockerfile
    cat > "${AIOS_QUANTUM_DIR}/Dockerfile" << 'EOF'
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install quantum libraries
RUN pip install --no-cache-dir \
    qiskit>=1.0.0 \
    qiskit-aer>=0.13.0 \
    cirq>=1.0.0 \
    pennylane>=0.30.0 \
    torch>=2.0.0 \
    numpy>=1.24.0 \
    scipy>=1.10.0 \
    flask>=2.3.0

# Create working directory
WORKDIR /quantum

# Copy quantum server
COPY quantum_server.py /quantum/

# Expose API port
EXPOSE 5000

# Run quantum server
CMD ["python", "quantum_server.py"]
EOF

    # Create quantum server
    cat > "${AIOS_QUANTUM_DIR}/quantum_server.py" << 'EOF'
#!/usr/bin/env python3
"""Quantum computation server for Docker VM."""

from flask import Flask, request, jsonify
import json
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

app = Flask(__name__)
simulator = AerSimulator()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "backend": "Aer"})

@app.route('/execute', methods=['POST'])
def execute():
    try:
        data = request.json
        num_qubits = data.get('num_qubits', 5)
        shots = data.get('shots', 1024)

        # Create test circuit
        qc = QuantumCircuit(num_qubits)
        for i in range(num_qubits):
            qc.h(i)
        qc.measure_all()

        # Execute
        compiled = transpile(qc, simulator)
        job = simulator.run(compiled, shots=shots)
        result = job.result()
        counts = result.get_counts()

        return jsonify({
            "success": True,
            "counts": counts
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

    # Build image
    cd "${AIOS_QUANTUM_DIR}"
    if docker build -t "$DOCKER_IMAGE" . >> "$LOG_FILE" 2>&1; then
        print_status "Docker image built: $DOCKER_IMAGE"
    else
        print_error "Docker image build failed - check $LOG_FILE"
    fi
}

# Function to create QEMU quantum OS image
create_qemu_image() {
    if [[ $QEMU_AVAILABLE -eq 0 ]]; then
        return
    fi

    print_info "Creating QEMU quantum OS image..."

    # Create a minimal quantum OS image (10GB)
    if command -v qemu-img &> /dev/null; then
        qemu-img create -f qcow2 "$QEMU_IMAGE" 10G >> "$LOG_FILE" 2>&1
        print_status "QEMU image created: $QEMU_IMAGE"
    else
        print_warning "qemu-img not found - skipping QEMU image creation"
    fi
}

# Function to create launch scripts
create_launch_scripts() {
    print_info "Creating quantum VM launch scripts..."

    # Docker launch script
    cat > "${AIOS_QUANTUM_DIR}/scripts/launch_docker_quantum.sh" << 'EOF'
#!/bin/bash
docker run -d \
    --name quantum-vm \
    --memory 4g \
    --cpus 2 \
    -p 5000:5000 \
    quantum-simulator:latest
echo "Quantum Docker VM started on port 5000"
EOF

    # QEMU launch script
    if is_apple_silicon; then
        QEMU_CMD="qemu-system-aarch64"
        QEMU_ACCEL="-accel hvf"
        QEMU_CPU="-cpu host"
    else
        QEMU_CMD="qemu-system-x86_64"
        if [[ "$ACCELERATION" == "hvf" ]]; then
            QEMU_ACCEL="-accel hvf"
            QEMU_CPU="-cpu host"
        elif [[ "$ACCELERATION" == "kvm" ]]; then
            QEMU_ACCEL="-enable-kvm"
            QEMU_CPU="-cpu host"
        else
            QEMU_ACCEL=""
            QEMU_CPU=""
        fi
    fi

    cat > "${AIOS_QUANTUM_DIR}/scripts/launch_qemu_quantum.sh" << EOF
#!/bin/bash
$QEMU_CMD \\
    -name quantum-vm \\
    -m 4096 \\
    -smp 4 \\
    $QEMU_ACCEL \\
    $QEMU_CPU \\
    -nographic \\
    -netdev user,id=net0,hostfwd=tcp::5901-:5901 \\
    -device virtio-net,netdev=net0 \\
    -drive file=${QEMU_IMAGE},if=virtio
echo "Quantum QEMU VM started"
EOF

    chmod +x "${AIOS_QUANTUM_DIR}/scripts/"*.sh
    print_status "Launch scripts created"
}

# Function to create benchmark script
create_benchmark_script() {
    print_info "Creating quantum benchmark script..."

    cat > "${AIOS_QUANTUM_DIR}/benchmarks/benchmark.py" << 'EOF'
#!/usr/bin/env python3
"""Quantum performance benchmark for Ai:oS."""

import time
import json
import platform
import torch
import numpy as np

def detect_hardware():
    """Detect hardware capabilities."""
    info = {
        "platform": platform.system(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
    }

    # Check for Apple Silicon
    if platform.machine() == "arm64" and platform.system() == "Darwin":
        info["apple_silicon"] = True
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            info["mps_available"] = True
    else:
        info["apple_silicon"] = False

    # Check for CUDA
    info["cuda_available"] = torch.cuda.is_available()
    if info["cuda_available"]:
        info["cuda_device_count"] = torch.cuda.device_count()

    return info

def benchmark_statevector(num_qubits, shots=1000):
    """Benchmark statevector simulation."""
    dim = 2 ** num_qubits

    # Use appropriate device
    if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        device = torch.device("mps")
        backend = "Apple Silicon (MPS)"
    elif torch.cuda.is_available():
        device = torch.device("cuda")
        backend = "NVIDIA GPU (CUDA)"
    else:
        device = torch.device("cpu")
        backend = "CPU"

    start = time.time()

    # Initialize statevector
    state = torch.zeros(dim, dtype=torch.complex128, device=device)
    state[0] = 1.0

    # Apply Hadamard to all qubits (simplified)
    H = torch.tensor([[1, 1], [1, -1]], dtype=torch.complex128, device=device) / np.sqrt(2)

    # Simulate quantum gates (simplified)
    for _ in range(num_qubits):
        state = torch.fft.fft(state)
        state = state / torch.sqrt(torch.tensor(dim, dtype=torch.float64, device=device))

    # Measure
    probs = torch.abs(state) ** 2
    samples = torch.multinomial(probs, shots, replacement=True)

    duration = time.time() - start

    return {
        "backend": backend,
        "num_qubits": num_qubits,
        "shots": shots,
        "time_seconds": duration,
        "qubits_per_second": num_qubits / duration
    }

def run_benchmarks():
    """Run comprehensive benchmarks."""
    hardware = detect_hardware()
    print("Hardware Info:", json.dumps(hardware, indent=2))

    results = []
    qubit_counts = [5, 10, 15, 20, 25]

    for num_qubits in qubit_counts:
        try:
            print(f"\nBenchmarking {num_qubits} qubits...")
            result = benchmark_statevector(num_qubits)
            results.append(result)
            print(f"  Backend: {result['backend']}")
            print(f"  Time: {result['time_seconds']:.3f}s")
            print(f"  Performance: {result['qubits_per_second']:.1f} qubits/s")
        except Exception as e:
            print(f"  Failed: {e}")

    # Save results
    output = {
        "hardware": hardware,
        "benchmarks": results,
        "timestamp": time.time()
    }

    with open("benchmark_results.json", "w") as f:
        json.dump(output, f, indent=2)

    print("\nResults saved to benchmark_results.json")

if __name__ == "__main__":
    run_benchmarks()
EOF

    chmod +x "${AIOS_QUANTUM_DIR}/benchmarks/benchmark.py"
    print_status "Benchmark script created"
}

# Function to integrate with Ai:oS
integrate_aios() {
    print_info "Integrating with Ai:oS runtime..."

    # Create integration module
    cat > "${AIOS_QUANTUM_DIR}/aios_quantum_integration.py" << 'EOF'
#!/usr/bin/env python3
"""Integration module for Ai:oS quantum virtualization."""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aios.quantum_virtualization import (
    QuantumVirtualizationEngine,
    QuantumVMConfig,
    QuantumBackend,
    QuantumAgent
)

async def register_quantum_agent(runtime):
    """Register quantum agent with Ai:oS runtime."""
    agent = QuantumAgent()

    # Register actions
    runtime.register_agent("quantum", agent)
    runtime.register_action("quantum.initialize", agent.initialize)
    runtime.register_action("quantum.execute", agent.execute_quantum_algorithm)
    runtime.register_action("quantum.benchmark",
                          lambda ctx: agent.execute_quantum_algorithm(ctx, "benchmark", {}))

    print("[info] Quantum agent registered with Ai:oS")

def update_manifest():
    """Update Ai:oS manifest to include quantum agent."""
    manifest_addition = {
        "quantum": {
            "description": "Quantum computing virtualization and simulation",
            "actions": [
                {
                    "key": "initialize",
                    "description": "Initialize quantum VMs and backends",
                    "critical": False
                },
                {
                    "key": "execute",
                    "description": "Execute quantum circuits",
                    "critical": False
                },
                {
                    "key": "benchmark",
                    "description": "Run quantum performance benchmarks",
                    "critical": False
                }
            ]
        }
    }

    print("[info] Quantum agent manifest prepared")
    return manifest_addition

if __name__ == "__main__":
    import asyncio

    async def test():
        engine = QuantumVirtualizationEngine()
        results = await engine.benchmark(num_qubits=10)
        print("Benchmark results:", results)

    asyncio.run(test())
EOF

    print_status "Ai:oS integration module created"
}

# Function to run initial tests
run_tests() {
    print_info "Running quantum system tests..."

    python3 -c "
import sys
sys.path.append('${AIOS_QUANTUM_DIR}/..')
try:
    from aios.quantum_virtualization import QuantumVirtualizationEngine
    print('✓ Quantum virtualization module loads successfully')
except Exception as e:
    print(f'✗ Module load failed: {e}')

try:
    import torch
    print(f'✓ PyTorch available: {torch.__version__}')
    if torch.cuda.is_available():
        print(f'  - CUDA devices: {torch.cuda.device_count()}')
    if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        print('  - Apple Silicon MPS available')
except:
    print('✗ PyTorch not available')

try:
    import qiskit
    print(f'✓ Qiskit available: {qiskit.__version__}')
except:
    print('✗ Qiskit not available')

try:
    import cirq
    print(f'✓ Cirq available')
except:
    print('✗ Cirq not available')
"
}

# Main setup flow
main() {
    echo "═══════════════════════════════════════════════════════════"
    echo "     Quantum Computing VM Setup for Ai:oS"
    echo "     Copyright (c) 2025 Corporation of Light"
    echo "═══════════════════════════════════════════════════════════"
    echo

    # Create log file
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "Setup started at $(date)" > "$LOG_FILE"

    # Run setup steps
    check_requirements
    setup_directories
    install_python_deps
    build_docker_image
    create_qemu_image
    create_launch_scripts
    create_benchmark_script
    integrate_aios
    run_tests

    echo
    print_status "Quantum VM setup completed!"
    print_info "Quantum directory: ${AIOS_QUANTUM_DIR}"
    print_info "Launch scripts: ${AIOS_QUANTUM_DIR}/scripts/"
    print_info "Run benchmark: python3 ${AIOS_QUANTUM_DIR}/benchmarks/benchmark.py"
    print_info "Log file: ${LOG_FILE}"
    echo

    # Provide next steps
    echo "Next steps:"
    echo "1. Test quantum virtualization:"
    echo "   python3 ${AIOS_QUANTUM_DIR}/../aios/quantum_virtualization.py"
    echo
    echo "2. Launch Docker quantum VM:"
    echo "   ${AIOS_QUANTUM_DIR}/scripts/launch_docker_quantum.sh"
    echo
    echo "3. Run performance benchmark:"
    echo "   python3 ${AIOS_QUANTUM_DIR}/benchmarks/benchmark.py"
    echo
}

# Run main function
main "$@"