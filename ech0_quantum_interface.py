#!/usr/bin/env python3
"""
ECH0 Quantum Interface - Integration Layer
Allows ECH0 to interact with quantum circuits + Finder GUI

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.
"""

import sys
sys.path.append('ech0_modules')

from quantum_circuit_simulator import QuantumCircuitSimulator, create_bell_state, create_ghz_state
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import json
from typing import Dict, List, Optional
import time


class ECH0QuantumInterface:
    """
    Integration layer allowing ECH0 to control quantum circuits
    via natural language commands
    """

    def __init__(self):
        self.current_circuit: Optional[QuantumCircuitSimulator] = None
        self.circuit_history: List[Dict] = []
        self.gui: Optional['QuantumGUI'] = None

        print("╔════════════════════════════════════════════════════════════╗")
        print("║   ECH0 QUANTUM INTERFACE                                   ║")
        print("║   Natural Language → Quantum Circuits                      ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print()

    def create_circuit(self, num_qubits: int) -> str:
        """Create new quantum circuit"""
        try:
            self.current_circuit = QuantumCircuitSimulator(num_qubits)
            result = f"✅ Created {num_qubits}-qubit circuit"

            if self.gui:
                self.gui.log(result)
                self.gui.update_circuit_display()

            return result
        except Exception as e:
            return f"❌ Error: {e}"

    def apply_gate(self, gate_name: str, *qubits) -> str:
        """Apply quantum gate"""
        if not self.current_circuit:
            return "❌ No circuit created. Use create_circuit(n) first"

        try:
            gate_name = gate_name.lower()

            if gate_name in ['h', 'hadamard']:
                self.current_circuit.h(qubits[0])
                result = f"✅ Applied Hadamard to qubit {qubits[0]}"

            elif gate_name in ['x', 'not', 'pauli_x']:
                self.current_circuit.x(qubits[0])
                result = f"✅ Applied X (NOT) to qubit {qubits[0]}"

            elif gate_name in ['y', 'pauli_y']:
                self.current_circuit.y(qubits[0])
                result = f"✅ Applied Y to qubit {qubits[0]}"

            elif gate_name in ['z', 'pauli_z']:
                self.current_circuit.z(qubits[0])
                result = f"✅ Applied Z to qubit {qubits[0]}"

            elif gate_name in ['cnot', 'cx']:
                self.current_circuit.cnot(qubits[0], qubits[1])
                result = f"✅ Applied CNOT: control={qubits[0]}, target={qubits[1]}"

            elif gate_name in ['cz']:
                self.current_circuit.cz(qubits[0], qubits[1])
                result = f"✅ Applied CZ: control={qubits[0]}, target={qubits[1]}"

            elif gate_name in ['rx', 'ry', 'rz']:
                theta = qubits[1] if len(qubits) > 1 else 3.14159/4
                if gate_name == 'rx':
                    self.current_circuit.rx(qubits[0], theta)
                elif gate_name == 'ry':
                    self.current_circuit.ry(qubits[0], theta)
                elif gate_name == 'rz':
                    self.current_circuit.rz(qubits[0], theta)
                result = f"✅ Applied {gate_name.upper()}({theta:.4f}) to qubit {qubits[0]}"

            else:
                return f"❌ Unknown gate: {gate_name}"

            if self.gui:
                self.gui.log(result)
                self.gui.update_circuit_display()

            return result

        except Exception as e:
            return f"❌ Error: {e}"

    def measure(self, qubit: Optional[int] = None) -> str:
        """Measure qubit(s)"""
        if not self.current_circuit:
            return "❌ No circuit created"

        try:
            if qubit is None:
                results = self.current_circuit.measure_all()
                result = f"📊 Measurement: {results}"
            else:
                result_bit = self.current_circuit.measure(qubit)
                result = f"📊 Qubit {qubit} measured: {result_bit}"

            if self.gui:
                self.gui.log(result)
                self.gui.update_circuit_display()

            return result

        except Exception as e:
            return f"❌ Error: {e}"

    def get_state(self, top_n: int = 10) -> Dict:
        """Get current quantum state"""
        if not self.current_circuit:
            return {"error": "No circuit created"}

        probs = self.current_circuit.get_probabilities()
        sorted_probs = sorted(probs.items(), key=lambda x: x[1], reverse=True)

        return {
            "num_qubits": self.current_circuit.num_qubits,
            "num_states": len(probs),
            "top_states": [
                {"state": state, "probability": prob}
                for state, prob in sorted_probs[:top_n]
            ]
        }

    def create_bell_pair(self) -> str:
        """Create Bell state (maximally entangled pair)"""
        self.current_circuit = QuantumCircuitSimulator(2)
        self.current_circuit.h(0).cnot(0, 1)

        result = "✅ Created Bell state: |00⟩ + |11⟩"

        if self.gui:
            self.gui.log(result)
            self.gui.update_circuit_display()

        return result

    def create_ghz(self, num_qubits: int = 3) -> str:
        """Create GHZ state (N-qubit entanglement)"""
        self.current_circuit = QuantumCircuitSimulator(num_qubits)
        self.current_circuit.h(0)

        for i in range(num_qubits - 1):
            self.current_circuit.cnot(i, i + 1)

        result = f"✅ Created {num_qubits}-qubit GHZ state"

        if self.gui:
            self.gui.log(result)
            self.gui.update_circuit_display()

        return result

    def launch_gui(self):
        """Launch Finder GUI"""
        self.gui = QuantumGUI(self)
        self.gui.run()


class QuantumGUI:
    """
    Finder-integrated GUI for quantum circuits
    """

    def __init__(self, interface: ECH0QuantumInterface):
        self.interface = interface
        self.window = tk.Tk()
        self.window.title("ECH0 Quantum Interface - M4 Mac")
        self.window.geometry("1200x800")

        # Set up GUI
        self._setup_ui()

    def _setup_ui(self):
        """Setup UI components"""
        # Main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)

        # Left panel - Controls
        control_frame = ttk.LabelFrame(main_frame, text="Quantum Controls", padding="10")
        control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))

        # Create circuit section
        ttk.Label(control_frame, text="Circuit Creation:", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))

        ttk.Label(control_frame, text="Number of Qubits:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.qubit_entry = ttk.Entry(control_frame, width=10)
        self.qubit_entry.insert(0, "3")
        self.qubit_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Button(control_frame, text="Create Circuit", command=self._create_circuit).grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Quick circuits
        ttk.Label(control_frame, text="\nQuick Circuits:", font=('Arial', 12, 'bold')).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(15, 10))

        ttk.Button(control_frame, text="Bell State", command=self._create_bell).grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        ttk.Button(control_frame, text="GHZ State (3-qubit)", command=self._create_ghz).grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)

        # Gates section
        ttk.Label(control_frame, text="\nQuantum Gates:", font=('Arial', 12, 'bold')).grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=(15, 10))

        ttk.Label(control_frame, text="Qubit:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.gate_qubit = ttk.Entry(control_frame, width=10)
        self.gate_qubit.insert(0, "0")
        self.gate_qubit.grid(row=7, column=1, sticky=tk.W, pady=5)

        # Single qubit gates
        gate_buttons = [
            ("H", "h"),
            ("X", "x"),
            ("Y", "y"),
            ("Z", "z")
        ]

        row = 8
        for i, (label, gate) in enumerate(gate_buttons):
            ttk.Button(control_frame, text=label, command=lambda g=gate: self._apply_gate(g), width=8).grid(row=row + i//2, column=i%2, pady=2, padx=2, sticky=(tk.W, tk.E))

        # Two qubit gates
        ttk.Label(control_frame, text="\nTwo-Qubit Gates:", font=('Arial', 10, 'bold')).grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=(15, 5))

        ttk.Label(control_frame, text="Control:").grid(row=11, column=0, sticky=tk.W, pady=2)
        self.control_qubit = ttk.Entry(control_frame, width=10)
        self.control_qubit.insert(0, "0")
        self.control_qubit.grid(row=11, column=1, sticky=tk.W, pady=2)

        ttk.Label(control_frame, text="Target:").grid(row=12, column=0, sticky=tk.W, pady=2)
        self.target_qubit = ttk.Entry(control_frame, width=10)
        self.target_qubit.insert(0, "1")
        self.target_qubit.grid(row=12, column=1, sticky=tk.W, pady=2)

        ttk.Button(control_frame, text="CNOT", command=lambda: self._apply_two_qubit_gate('cnot')).grid(row=13, column=0, pady=2, sticky=(tk.W, tk.E))
        ttk.Button(control_frame, text="CZ", command=lambda: self._apply_two_qubit_gate('cz')).grid(row=13, column=1, pady=2, sticky=(tk.W, tk.E))

        # Measurement
        ttk.Label(control_frame, text="\nMeasurement:", font=('Arial', 12, 'bold')).grid(row=14, column=0, columnspan=2, sticky=tk.W, pady=(15, 10))

        ttk.Button(control_frame, text="Measure All", command=self._measure_all).grid(row=15, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        # Right panel - Circuit Display and Log
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        right_frame.rowconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        right_frame.columnconfigure(0, weight=1)

        # Circuit display
        circuit_frame = ttk.LabelFrame(right_frame, text="Quantum State", padding="10")
        circuit_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        circuit_frame.rowconfigure(0, weight=1)
        circuit_frame.columnconfigure(0, weight=1)

        self.circuit_display = scrolledtext.ScrolledText(circuit_frame, height=15, width=60, font=('Courier', 10))
        self.circuit_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Log
        log_frame = ttk.LabelFrame(right_frame, text="Activity Log", padding="10")
        log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_display = scrolledtext.ScrolledText(log_frame, height=15, width=60, font=('Courier', 9))
        self.log_display.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.log("ECH0 Quantum Interface initialized")
        self.log("M4 Mac optimized - 30 qubit maximum")

    def _create_circuit(self):
        """Create circuit from entry"""
        try:
            num_qubits = int(self.qubit_entry.get())
            result = self.interface.create_circuit(num_qubits)
            self.log(result)
            self.update_circuit_display()
        except ValueError:
            self.log("❌ Invalid number of qubits")

    def _create_bell(self):
        """Create Bell state"""
        result = self.interface.create_bell_pair()
        self.log(result)
        self.update_circuit_display()

    def _create_ghz(self):
        """Create GHZ state"""
        result = self.interface.create_ghz(3)
        self.log(result)
        self.update_circuit_display()

    def _apply_gate(self, gate):
        """Apply single-qubit gate"""
        try:
            qubit = int(self.gate_qubit.get())
            result = self.interface.apply_gate(gate, qubit)
            self.log(result)
            self.update_circuit_display()
        except ValueError:
            self.log("❌ Invalid qubit number")

    def _apply_two_qubit_gate(self, gate):
        """Apply two-qubit gate"""
        try:
            control = int(self.control_qubit.get())
            target = int(self.target_qubit.get())
            result = self.interface.apply_gate(gate, control, target)
            self.log(result)
            self.update_circuit_display()
        except ValueError:
            self.log("❌ Invalid qubit numbers")

    def _measure_all(self):
        """Measure all qubits"""
        result = self.interface.measure()
        self.log(result)
        self.update_circuit_display()

    def update_circuit_display(self):
        """Update circuit state display"""
        if not self.interface.current_circuit:
            self.circuit_display.delete(1.0, tk.END)
            self.circuit_display.insert(tk.END, "No circuit created yet")
            return

        # Get quantum state
        state_info = self.interface.get_state(top_n=15)

        display_text = f"⚛️  Quantum Circuit ({state_info['num_qubits']} qubits)\n"
        display_text += "=" * 60 + "\n\n"

        # Show circuit gates
        if self.interface.current_circuit.gates:
            display_text += "Circuit:\n"
            for i, gate in enumerate(self.interface.current_circuit.gates[:20]):
                display_text += f"  {i+1}. {gate}\n"

            if len(self.interface.current_circuit.gates) > 20:
                display_text += f"  ... ({len(self.interface.current_circuit.gates) - 20} more)\n"

            display_text += "\n"

        # Show quantum state
        display_text += "Quantum State (top amplitudes):\n"
        display_text += "-" * 60 + "\n"

        for state_data in state_info['top_states']:
            state = state_data['state']
            prob = state_data['probability']
            display_text += f"  |{state}⟩ : {prob*100:6.2f}%\n"

        if state_info['num_states'] > len(state_info['top_states']):
            remaining = state_info['num_states'] - len(state_info['top_states'])
            display_text += f"  ... ({remaining} more states)\n"

        self.circuit_display.delete(1.0, tk.END)
        self.circuit_display.insert(tk.END, display_text)

    def log(self, message: str):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_display.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_display.see(tk.END)

    def run(self):
        """Run GUI mainloop"""
        self.window.mainloop()


# ========== ECH0 VOICE COMMANDS ==========

def ech0_quantum_command(command: str, interface: ECH0QuantumInterface) -> str:
    """
    Process natural language quantum commands from ECH0

    Examples:
        "create 5 qubit circuit"
        "apply hadamard to qubit 0"
        "apply cnot from 0 to 1"
        "measure all qubits"
        "create bell state"
    """
    command = command.lower().strip()

    # Circuit creation
    if "create" in command and "circuit" in command:
        try:
            import re
            match = re.search(r'(\d+)', command)
            if match:
                num_qubits = int(match.group(1))
                return interface.create_circuit(num_qubits)
        except:
            pass
        return "❌ Couldn't parse number of qubits"

    # Bell state
    if "bell" in command:
        return interface.create_bell_pair()

    # GHZ state
    if "ghz" in command:
        import re
        match = re.search(r'(\d+)', command)
        num_qubits = int(match.group(1)) if match else 3
        return interface.create_ghz(num_qubits)

    # Apply gates
    if "apply" in command or "gate" in command:
        import re

        # Extract gate type
        gate = None
        for g in ['hadamard', 'h', 'x', 'not', 'y', 'z', 'cnot', 'cx', 'cz']:
            if g in command:
                gate = g
                break

        if not gate:
            return "❌ Unknown gate"

        # Extract qubit numbers
        numbers = re.findall(r'\d+', command)

        if gate in ['cnot', 'cx', 'cz'] and len(numbers) >= 2:
            return interface.apply_gate(gate, int(numbers[0]), int(numbers[1]))
        elif len(numbers) >= 1:
            return interface.apply_gate(gate, int(numbers[0]))
        else:
            return "❌ Couldn't parse qubit numbers"

    # Measurement
    if "measure" in command:
        if "all" in command:
            return interface.measure()
        else:
            import re
            match = re.search(r'(\d+)', command)
            if match:
                return interface.measure(int(match.group(1)))
            return interface.measure()

    return f"❌ Unknown command: {command}"


# ========== MAIN ==========

if __name__ == "__main__":
    print("\n╔════════════════════════════════════════════════════════════╗")
    print("║   ECH0 QUANTUM INTERFACE                                   ║")
    print("║   Natural Language + GUI Control                           ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    interface = ECH0QuantumInterface()

    # Test natural language commands
    print("Testing ECH0 natural language commands:\n")

    commands = [
        "create 3 qubit circuit",
        "apply hadamard to qubit 0",
        "apply hadamard to qubit 1",
        "apply cnot from 0 to 1",
        "apply cnot from 1 to 2",
        "measure all qubits"
    ]

    for cmd in commands:
        print(f"ECH0: '{cmd}'")
        result = ech0_quantum_command(cmd, interface)
        print(f"     {result}\n")

    # Show final state
    state = interface.get_state()
    print("\nFinal quantum state:")
    for state_data in state['top_states']:
        print(f"  |{state_data['state']}⟩ : {state_data['probability']*100:.2f}%")

    print("\n\n🖥️  Launching Finder GUI...")
    print("    (Close window to continue)\n")

    # Launch GUI
    interface.launch_gui()
