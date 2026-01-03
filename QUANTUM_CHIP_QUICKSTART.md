# Ai:oS Quantum Chip Quick Start Guide

**Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.**

Get started with the 100-qubit quantum chip simulator in 5 minutes.

---

## Installation

The quantum chip is already integrated with Ai:oS. No additional installation required!

**Dependencies**:
- Python 3.9+
- NumPy
- SciPy (optional, for VQE optimization)
- PyTorch (optional, for GPU acceleration)

---

## Quick Start: 3 Lines of Code

```python
from aios.quantum_chip import QuantumChip100

chip = QuantumChip100(num_qubits=10)
chip.hadamard(0)
chip.cnot(0, 1)
measurements = chip.measure_all()
print(measurements)  # [0, 0, 0, ...] or [1, 1, 0, ...]
```

Congratulations! You just created quantum entanglement.

---

## 30-Second Examples

### Create a Bell State (Quantum Entanglement)

```python
from aios.quantum_chip import QuantumChip100

chip = QuantumChip100(num_qubits=2)
chip.hadamard(0)     # Superposition
chip.cnot(0, 1)      # Entanglement

# Measure both qubits - they'll always be the same!
m0 = chip.measure(0)
m1 = chip.measure(1)
print(f"Measurements: {m0}, {m1}")  # Both 0 or both 1
```

### Create a GHZ State (Multi-Qubit Entanglement)

```python
from aios.quantum_chip import QuantumChip100

chip = QuantumChip100(num_qubits=10)
chip.hadamard(0)
for i in range(1, 10):
    chip.cnot(0, i)

measurements = chip.measure_all()
print(measurements)  # All 0s or all 1s!
```

### Run a Quantum Circuit

```python
from aios.quantum_chip import QuantumChip100
import numpy as np

chip = QuantumChip100(num_qubits=5)

# Define circuit as list of operations
circuit = [
    ("H", 0),              # Hadamard on qubit 0
    ("CNOT", 0, 1),        # Entangle qubits 0 and 1
    ("RY", 2, np.pi/4),    # Rotate qubit 2
    ("CZ", 1, 2),          # Controlled-Z
]

# Execute circuit
result = chip.run_circuit(circuit)
print(f"Measurements: {result['measurements']}")
print(f"Execution time: {result['execution_time']:.3f}s")
```

---

## Common Tasks

### Choose Chip Topology

```python
from aios.quantum_chip import QuantumChip100, ChipTopology

# Google Sycamore-style 2D grid
chip = QuantumChip100(num_qubits=50, topology=ChipTopology.GRID_2D)

# IBM-style heavy hexagon
chip = QuantumChip100(num_qubits=50, topology=ChipTopology.HEAVY_HEX)

# Fully connected (ideal but unrealistic)
chip = QuantumChip100(num_qubits=20, topology=ChipTopology.ALL_TO_ALL)
```

### Enable Error Modeling

```python
# Realistic quantum noise
chip = QuantumChip100(
    num_qubits=25,
    topology=ChipTopology.GRID_2D,
    error_model=True  # Enable noise
)

# Apply error correction
chip.apply_error_correction("surface")
```

### Use Distributed Simulation (60-100 qubits)

```python
# Automatically uses distributed backend
chip = QuantumChip100(
    num_qubits=80,
    distributed=True
)

# Build and run circuit
circuit = [("H", i) for i in range(80)]
result = chip.run_circuit(circuit)
```

### Quantum Optimization (VQE)

```python
from aios.quantum_chip import create_quantum_vqe_optimizer
import numpy as np

# Define optimization problem (Hamiltonian matrix)
H = np.array([
    [1, 0, 0, 0],
    [0, -1, 0.5, 0],
    [0, 0.5, -1, 0],
    [0, 0, 0, 1]
])

# Create VQE optimizer
vqe = create_quantum_vqe_optimizer(num_qubits=2)

# Find ground state
energy, params = vqe(H, max_iter=50)
print(f"Ground state energy: {energy}")
```

---

## Ai:oS Integration

### Use Through QuantumAgent

```python
from aios.agents.quantum_agent import QuantumAgent

# Create agent
agent = QuantumAgent()

# Mock execution context
class Context:
    environment = {
        "AGENTA_QUANTUM_QUBITS": 20,
        "AGENTA_QUANTUM_TOPOLOGY": "heavy_hex",
        "AGENTA_QUANTUM_CIRCUIT": [
            ("H", 0),
            ("CNOT", 0, 1),
        ]
    }
    metadata = {}
    def publish_metadata(self, key, value):
        self.metadata[key] = value

ctx = Context()

# Initialize chip
result = agent.quantum_chip_init(ctx)
print(result['message'])

# Execute circuit
result = agent.quantum_circuit_execute(ctx)
print(result['payload']['measurements'])
```

### Environment Variables

```bash
# Configure quantum chip
export AGENTA_QUANTUM_QUBITS=100
export AGENTA_QUANTUM_TOPOLOGY=heavy_hex
export AGENTA_QUANTUM_ERROR_MODEL=1
```

---

## Gate Library Reference

### Single-Qubit Gates

```python
chip.hadamard(0)              # H gate - superposition
chip.pauli_x(0)               # X gate - bit flip
chip.pauli_y(0)               # Y gate
chip.pauli_z(0)               # Z gate - phase flip

chip.rx(0, theta)             # Rotation around X axis
chip.ry(0, theta)             # Rotation around Y axis
chip.rz(0, theta)             # Rotation around Z axis

chip.phase(0, phi)            # Phase gate
```

### Two-Qubit Gates

```python
chip.cnot(0, 1)               # Controlled-NOT
chip.cz(0, 1)                 # Controlled-Z
chip.swap(0, 1)               # SWAP states
```

### Three-Qubit Gates

```python
chip.toffoli(0, 1, 2)         # Toffoli (CCNOT)
```

### Measurement

```python
m = chip.measure(0)           # Measure single qubit
measurements = chip.measure_all()  # Measure all qubits
```

### Expectation Values

```python
exp = chip.expectation_value("Z0")      # <Z₀>
exp = chip.expectation_value("Z0 Z1")   # <Z₀ Z₁>
```

---

## Demos and Examples

### Run Interactive Demo

```bash
cd /Users/noone/aios
python quantum_chip_demo.py
```

Interactive menu with 8 quantum computing demonstrations.

### Run Test Suite

```bash
python test_quantum_100.py
```

Comprehensive tests across all qubit ranges (5, 10, 20, 50, 100).

### Run Integration Examples

```bash
python examples/quantum_chip_integration.py
```

6 examples showing Ai:oS integration patterns.

---

## Performance Tips

### For Speed

1. **Use smaller circuits**: 5-20 qubits are fastest (statevector backend)
2. **Disable error model**: `error_model=False` for clean simulation
3. **Limit circuit depth**: Fewer gates = faster execution

### For Large Circuits

1. **Use distributed mode**: `distributed=True` for 60+ qubits
2. **Optimize topology**: Match your circuit to chip connectivity
3. **Use sparse mode**: Automatically enabled for 30+ qubits

### For Accuracy

1. **Enable error model**: `error_model=True` for realistic simulation
2. **Apply error correction**: Use surface or toric codes
3. **Statevector backend**: Most accurate (up to 20 qubits)

---

## Troubleshooting

### Problem: "Maximum allowed dimension exceeded"

**Solution**: You're trying to allocate too much memory. Use distributed mode or reduce qubits.

```python
chip = QuantumChip100(num_qubits=80, distributed=True)
```

### Problem: "AttributeError: 'QuantumChip100' object has no attribute 'metrics'"

**Solution**: This is a known initialization order issue. The fix is in the latest version. Update your code or re-import.

### Problem: Gates between non-adjacent qubits are slow

**Solution**: This is expected - SWAP networks are being inserted. Use topologies that match your circuit or choose `ALL_TO_ALL` topology.

```python
chip = QuantumChip100(num_qubits=10, topology=ChipTopology.ALL_TO_ALL)
```

---

## Next Steps

1. **Read the full documentation**: `QUANTUM_CHIP_100_README.md`
2. **Explore examples**: `examples/quantum_chip_integration.py`
3. **Run demos**: `quantum_chip_demo.py`
4. **Build quantum algorithms**: VQE, QAOA, Grover, etc.
5. **Integrate with your Ai:oS agents**: Quantum-enhance your AI!

---

## Support & Community

**Documentation**: `/Users/noone/aios/QUANTUM_CHIP_100_README.md`
**Examples**: `/Users/noone/aios/examples/quantum_chip_integration.py`
**Tests**: `/Users/noone/aios/test_quantum_100.py`

**Websites**:
- https://aios.is - Ai:oS Project
- https://thegavl.com - Corporation of Light
- https://red-team-tools.aios.is - Security Tools

---

## License

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

---

**You now have access to 100-qubit quantum computing. Build the future!** 🚀