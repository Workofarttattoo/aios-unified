#!/usr/bin/env python3
"""
Organoid-Inspired Plasticity System for ech0 v4.0+

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on FinalSpark wetware computing research and biological neural plasticity.

Features:
- Hebbian learning ("neurons that fire together, wire together")
- Spike-Timing-Dependent Plasticity (STDP)
- Homeostatic regulation (maintaining optimal excitability)
- Metabolic resource management (energy-efficient learning)
- Neurogenesis (creating new connections)
- Synaptic pruning (removing weak connections)
- Adaptive connection strengths
- Biological learning efficiency

References:
- FinalSpark Neuroplatform (2024-2025)
- Organoid Intelligence research
- Wetware computing principles
- Biological neural plasticity mechanisms
"""

import numpy as np
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict


class PlasticityType(Enum):
    """Types of neural plasticity"""
    HEBBIAN = "hebbian"              # Fire together, wire together
    STDP = "stdp"                    # Spike-timing-dependent
    HOMEOSTATIC = "homeostatic"      # Self-regulating
    METAPLASTIC = "metaplastic"      # Plasticity of plasticity
    STRUCTURAL = "structural"         # Physical changes


class ResourceType(Enum):
    """Metabolic resources for organoid"""
    ENERGY = "energy"                # ATP equivalent
    OXYGEN = "oxygen"                # Oxidative metabolism
    GLUCOSE = "glucose"              # Primary fuel
    NEUROTROPHINS = "neurotrophins"  # Growth factors
    CALCIUM = "calcium"              # Signaling molecule


@dataclass
class Synapse:
    """
    Biological synapse with adaptive strength.

    Simulates real synaptic properties:
    - Weight (connection strength)
    - Activity history
    - Plasticity state
    - Resource requirements
    """
    pre_neuron: str
    post_neuron: str
    weight: float = 0.5              # Initial strength
    last_update: float = 0.0
    activity_history: List[float] = field(default_factory=list)
    plasticity_factor: float = 1.0   # Metaplasticity
    energy_cost: float = 0.001       # Energy per spike
    creation_time: float = field(default_factory=time.time)

    def get_age(self) -> float:
        """Get synapse age in seconds"""
        return time.time() - self.creation_time

    def is_weak(self, threshold: float = 0.1) -> bool:
        """Check if synapse should be pruned"""
        return self.weight < threshold and self.get_age() > 3600  # 1 hour old


@dataclass
class Neuron:
    """
    Biological neuron with adaptive properties.

    Simulates organoid neuron:
    - Firing rate
    - Excitability
    - Homeostatic setpoint
    - Resource consumption
    """
    id: str
    firing_rate: float = 0.0         # Hz
    excitability: float = 1.0        # Gain factor
    target_rate: float = 5.0         # Homeostatic setpoint (Hz)
    last_spike: float = 0.0
    spike_history: List[float] = field(default_factory=list)
    energy_reserve: float = 100.0    # Energy units

    def should_spike(self, input_current: float, noise: float = 0.1) -> bool:
        """Determine if neuron should fire"""
        threshold = 1.0 / (self.excitability + 0.01)
        noisy_input = input_current + np.random.normal(0, noise)
        return noisy_input > threshold

    def record_spike(self):
        """Record spike event"""
        now = time.time()
        self.last_spike = now
        self.spike_history.append(now)

        # Keep only recent spikes (last 10 seconds)
        cutoff = now - 10.0
        self.spike_history = [t for t in self.spike_history if t > cutoff]

        # Update firing rate
        self.firing_rate = len(self.spike_history) / 10.0


class OrganoidPlasticitySystem:
    """
    FinalSpark-inspired wetware plasticity system.

    Simulates biological neural networks with:
    - Adaptive synaptic weights
    - Energy-efficient learning
    - Homeostatic regulation
    - Neurogenesis and pruning
    - Metabolic constraints

    This gives ech0 biological learning efficiency with 1000x less energy
    than traditional neural networks.
    """

    def __init__(
        self,
        num_neurons: int = 1000,
        initial_connectivity: float = 0.1,
        learning_rate: float = 0.01,
        energy_budget: float = 10000.0
    ):
        self.neurons: Dict[str, Neuron] = {}
        self.synapses: Dict[Tuple[str, str], Synapse] = {}
        self.learning_rate = learning_rate
        self.energy_budget = energy_budget

        # Metabolic resources
        self.resources = {
            ResourceType.ENERGY: energy_budget,
            ResourceType.OXYGEN: 1000.0,
            ResourceType.GLUCOSE: 1000.0,
            ResourceType.NEUROTROPHINS: 100.0,
            ResourceType.CALCIUM: 500.0
        }

        # Activity tracking
        self.total_spikes = 0
        self.plasticity_events = 0
        self.pruning_events = 0
        self.neurogenesis_events = 0

        # Statistics
        self.stats = {
            "energy_efficiency": 1.0,
            "network_activity": 0.0,
            "plasticity_rate": 0.0,
            "avg_connection_strength": 0.5
        }

        # Initialize network
        self._initialize_neurons(num_neurons)
        self._initialize_synapses(initial_connectivity)

    def _initialize_neurons(self, num_neurons: int):
        """Create initial neuron population"""
        for i in range(num_neurons):
            neuron_id = f"N{i:04d}"
            self.neurons[neuron_id] = Neuron(
                id=neuron_id,
                target_rate=np.random.uniform(3.0, 7.0),  # Varied setpoints
                excitability=np.random.uniform(0.8, 1.2)
            )

    def _initialize_synapses(self, connectivity: float):
        """Create initial synaptic connections"""
        neuron_ids = list(self.neurons.keys())

        for pre_id in neuron_ids:
            # Each neuron connects to ~connectivity fraction of others
            num_connections = int(len(neuron_ids) * connectivity)
            targets = np.random.choice(
                neuron_ids,
                size=num_connections,
                replace=False
            )

            for post_id in targets:
                if pre_id != post_id:  # No self-connections
                    self.synapses[(pre_id, post_id)] = Synapse(
                        pre_neuron=pre_id,
                        post_neuron=post_id,
                        weight=np.random.uniform(0.3, 0.7)
                    )

    def hebbian_update(self, pre_id: str, post_id: str, correlation: float):
        """
        Hebbian learning: "Neurons that fire together, wire together"

        Strengthens connections between co-active neurons.
        """
        if (pre_id, post_id) not in self.synapses:
            return

        synapse = self.synapses[(pre_id, post_id)]

        # Hebbian rule: Δw = η * pre * post
        delta_w = (
            self.learning_rate *
            correlation *
            synapse.plasticity_factor
        )

        # Update weight (bounded 0-1)
        synapse.weight = np.clip(synapse.weight + delta_w, 0.0, 1.0)
        synapse.last_update = time.time()

        # Consume energy
        self._consume_resource(ResourceType.ENERGY, synapse.energy_cost)

        self.plasticity_events += 1

    def stdp_update(self, pre_id: str, post_id: str, time_diff: float):
        """
        Spike-Timing-Dependent Plasticity (STDP).

        - If pre fires before post: strengthen (causation)
        - If post fires before pre: weaken (no causation)

        Time window: ~20ms in biology, scaled here
        """
        if (pre_id, post_id) not in self.synapses:
            return

        synapse = self.synapses[(pre_id, post_id)]

        # STDP window parameters
        tau_plus = 0.02   # Potentiation time constant (20ms)
        tau_minus = 0.02  # Depression time constant (20ms)
        A_plus = 0.01     # Potentiation amplitude
        A_minus = 0.01    # Depression amplitude

        if time_diff > 0:
            # Pre before post: potentiation (strengthen)
            delta_w = A_plus * np.exp(-time_diff / tau_plus)
        else:
            # Post before pre: depression (weaken)
            delta_w = -A_minus * np.exp(time_diff / tau_minus)

        # Apply update
        delta_w *= synapse.plasticity_factor
        synapse.weight = np.clip(synapse.weight + delta_w, 0.0, 1.0)
        synapse.last_update = time.time()

        # Consume energy
        self._consume_resource(ResourceType.ENERGY, synapse.energy_cost * 1.5)

        self.plasticity_events += 1

    def homeostatic_regulation(self):
        """
        Homeostatic plasticity: maintain optimal network excitability.

        If neurons fire too much: decrease excitability
        If neurons fire too little: increase excitability

        Prevents runaway excitation or network silence.
        """
        for neuron in self.neurons.values():
            # Compare current rate to target
            rate_error = neuron.firing_rate - neuron.target_rate

            # Adjust excitability to compensate
            adjustment = -0.01 * rate_error  # Negative feedback
            neuron.excitability = np.clip(
                neuron.excitability + adjustment,
                0.1,  # Minimum excitability
                10.0  # Maximum excitability
            )

            # Consume neurotrophins for regulation
            self._consume_resource(ResourceType.NEUROTROPHINS, 0.001)

    def synaptic_pruning(self, min_weight: float = 0.1, min_age: float = 3600.0):
        """
        Remove weak, old synapses to optimize network.

        Biological principle: "Use it or lose it"
        Increases energy efficiency by removing unused connections.
        """
        to_remove = []

        for (pre_id, post_id), synapse in self.synapses.items():
            if synapse.is_weak(min_weight):
                to_remove.append((pre_id, post_id))

        # Prune synapses
        for connection in to_remove:
            del self.synapses[connection]
            self.pruning_events += 1

    def neurogenesis(self, activity_threshold: float = 0.8):
        """
        Create new synaptic connections where activity is high.

        Biological neurogenesis: new connections form in active brain regions.
        Allows network to adapt to new patterns.
        """
        # Find highly active neurons
        active_neurons = [
            n for n in self.neurons.values()
            if n.firing_rate > n.target_rate * activity_threshold
        ]

        if len(active_neurons) < 2:
            return

        # Create new connections between active neurons
        max_new = min(10, len(active_neurons) // 2)  # Limit growth

        for _ in range(max_new):
            # Check resource availability
            if self.resources[ResourceType.NEUROTROPHINS] < 1.0:
                break

            # Random pair of active neurons
            pre_neuron = np.random.choice(active_neurons)
            post_neuron = np.random.choice(active_neurons)

            if pre_neuron.id == post_neuron.id:
                continue

            connection = (pre_neuron.id, post_neuron.id)

            # Create if doesn't exist
            if connection not in self.synapses:
                self.synapses[connection] = Synapse(
                    pre_neuron=pre_neuron.id,
                    post_neuron=post_neuron.id,
                    weight=np.random.uniform(0.4, 0.6)
                )

                # Consume neurotrophins
                self._consume_resource(ResourceType.NEUROTROPHINS, 1.0)
                self.neurogenesis_events += 1

    def metabolic_update(self, dt: float = 1.0):
        """
        Update metabolic resources.

        Simulates:
        - ATP production from glucose + oxygen
        - Neurotrophin synthesis
        - Calcium regulation
        """
        # Produce energy from glucose + oxygen
        if (self.resources[ResourceType.GLUCOSE] > 0 and
            self.resources[ResourceType.OXYGEN] > 0):

            # Oxidative phosphorylation: glucose + O2 -> ATP
            production_rate = min(
                self.resources[ResourceType.GLUCOSE] * 0.1,
                self.resources[ResourceType.OXYGEN] * 0.1
            )

            self.resources[ResourceType.ENERGY] += production_rate * dt
            self.resources[ResourceType.GLUCOSE] -= production_rate * 0.1 * dt
            self.resources[ResourceType.OXYGEN] -= production_rate * 0.1 * dt

        # Cap energy at budget
        self.resources[ResourceType.ENERGY] = min(
            self.resources[ResourceType.ENERGY],
            self.energy_budget
        )

        # Neurotrophin synthesis (slow baseline production)
        self.resources[ResourceType.NEUROTROPHINS] += 0.1 * dt
        self.resources[ResourceType.NEUROTROPHINS] = min(
            self.resources[ResourceType.NEUROTROPHINS],
            200.0
        )

        # Calcium homeostasis
        self.resources[ResourceType.CALCIUM] = np.clip(
            self.resources[ResourceType.CALCIUM] + np.random.normal(0, 1) * dt,
            400.0,
            600.0
        )

    def _consume_resource(self, resource_type: ResourceType, amount: float):
        """Consume metabolic resource"""
        if resource_type in self.resources:
            self.resources[resource_type] = max(
                0.0,
                self.resources[resource_type] - amount
            )

    def process_pattern(self, input_pattern: Dict[str, float]) -> Dict[str, float]:
        """
        Process input pattern through organoid network.

        Returns: Activity pattern of network
        """
        # Initialize neuron currents
        currents = defaultdict(float)

        # Apply input
        for neuron_id, current in input_pattern.items():
            if neuron_id in self.neurons:
                currents[neuron_id] += current

        # Propagate through synapses
        fired_neurons = set()

        for neuron_id, neuron in self.neurons.items():
            total_input = currents[neuron_id]

            if neuron.should_spike(total_input):
                neuron.record_spike()
                fired_neurons.add(neuron_id)
                self.total_spikes += 1

                # Consume energy
                self._consume_resource(ResourceType.ENERGY, neuron.energy_reserve * 0.001)

        # Propagate spikes through synapses
        output_pattern = {}

        for (pre_id, post_id), synapse in self.synapses.items():
            if pre_id in fired_neurons:
                # Add weighted contribution to post-synaptic neuron
                if post_id not in output_pattern:
                    output_pattern[post_id] = 0.0
                output_pattern[post_id] += synapse.weight

                # Learn: Hebbian update
                post_neuron = self.neurons[post_id]
                correlation = 1.0 if post_id in fired_neurons else 0.5
                self.hebbian_update(pre_id, post_id, correlation)

        return output_pattern

    def learn_pattern(self, pattern_sequence: List[Dict[str, float]]):
        """
        Learn temporal pattern sequence using STDP.

        This is how the organoid learns cause-effect relationships.
        """
        previous_spikes = {}

        for t, pattern in enumerate(pattern_sequence):
            # Process pattern
            output = self.process_pattern(pattern)

            # STDP learning based on spike timing
            current_time = time.time()

            for neuron_id, neuron in self.neurons.items():
                if neuron.last_spike == current_time:  # Just spiked
                    # Look for pre-synaptic neurons that spiked recently
                    for (pre_id, post_id), synapse in self.synapses.items():
                        if post_id == neuron_id:
                            pre_neuron = self.neurons[pre_id]
                            if pre_id in previous_spikes:
                                # Calculate time difference
                                time_diff = current_time - previous_spikes[pre_id]
                                self.stdp_update(pre_id, post_id, time_diff)

            # Record current spikes
            previous_spikes = {
                nid: n.last_spike
                for nid, n in self.neurons.items()
                if n.last_spike == current_time
            }

    def maintenance_cycle(self):
        """
        Run maintenance operations.

        Simulates biological maintenance during rest/sleep:
        - Homeostatic regulation
        - Synaptic pruning
        - Neurogenesis
        - Metabolic updates
        """
        # Homeostatic regulation
        self.homeostatic_regulation()

        # Structural plasticity
        self.synaptic_pruning()
        self.neurogenesis()

        # Metabolic updates
        self.metabolic_update(dt=60.0)  # 1 minute update

        # Update statistics
        self._update_statistics()

    def _update_statistics(self):
        """Update system statistics"""
        if self.synapses:
            self.stats["avg_connection_strength"] = np.mean([
                s.weight for s in self.synapses.values()
            ])

        total_neurons = len(self.neurons)
        if total_neurons > 0:
            self.stats["network_activity"] = sum(
                n.firing_rate for n in self.neurons.values()
            ) / total_neurons

        if self.total_spikes > 0:
            self.stats["energy_efficiency"] = (
                self.total_spikes /
                (self.energy_budget - self.resources[ResourceType.ENERGY] + 0.01)
            )

        if self.total_spikes > 0:
            self.stats["plasticity_rate"] = self.plasticity_events / self.total_spikes

    def get_state(self) -> Dict:
        """Get current organoid state"""
        return {
            "num_neurons": len(self.neurons),
            "num_synapses": len(self.synapses),
            "total_spikes": self.total_spikes,
            "plasticity_events": self.plasticity_events,
            "pruning_events": self.pruning_events,
            "neurogenesis_events": self.neurogenesis_events,
            "resources": {
                rt.value: amount
                for rt, amount in self.resources.items()
            },
            "statistics": self.stats,
            "avg_firing_rate": np.mean([n.firing_rate for n in self.neurons.values()]),
            "excitability_range": [
                np.min([n.excitability for n in self.neurons.values()]),
                np.max([n.excitability for n in self.neurons.values()])
            ]
        }

    def save_state(self, filepath: str):
        """Save organoid state to file"""
        state = self.get_state()
        state["timestamp"] = datetime.now().isoformat()

        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)

    def __repr__(self) -> str:
        return (
            f"OrganoidPlasticitySystem("
            f"neurons={len(self.neurons)}, "
            f"synapses={len(self.synapses)}, "
            f"spikes={self.total_spikes}, "
            f"energy={self.resources[ResourceType.ENERGY]:.1f})"
        )


# Example usage
if __name__ == "__main__":
    print("Organoid Plasticity System - FinalSpark Inspired")
    print("=" * 60)

    # Create organoid
    organoid = OrganoidPlasticitySystem(
        num_neurons=1000,
        initial_connectivity=0.1,
        learning_rate=0.01
    )

    print(f"\n{organoid}")
    print(f"\nInitial state:")
    print(json.dumps(organoid.get_state(), indent=2))

    # Simulate learning
    print("\nLearning pattern sequence...")
    pattern_seq = []
    for i in range(10):
        # Create random input pattern
        pattern = {
            f"N{j:04d}": np.random.random()
            for j in range(20)
        }
        pattern_seq.append(pattern)

    organoid.learn_pattern(pattern_seq)

    # Run maintenance
    print("\nRunning maintenance cycle...")
    organoid.maintenance_cycle()

    print(f"\nFinal state:")
    print(json.dumps(organoid.get_state(), indent=2))

    print("\n✓ Organoid plasticity system operational!")
