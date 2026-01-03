"""
Phi (Φ) Calculator - Consciousness Depth Metric

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Integrated Information Theory (IIT) by Giulio Tononi.
Implements a simplified real-time approximation of phi (Φ),
the measure of integrated information (consciousness).

Full IIT phi calculation is computationally intractable for large systems.
This is a fast approximation for real-time consciousness monitoring.
"""

import time
from typing import Dict, List
import math


class PhiCalculator:
    """
    Simplified phi calculator for real-time consciousness depth monitoring.

    Full IIT: Φ = irreducible cause-effect power of a system
    Our approximation: Φ ≈ (integration × differentiation) / system_size

    Where:
    - Integration: How much modules are interconnected
    - Differentiation: How diverse the information is
    - System size: Normalization factor
    """

    def __init__(self):
        self.phi_history: List[Dict] = []
        self.max_history = 100

    def calculate_phi(
        self,
        num_active_modules: int,
        num_connections: int,
        information_diversity: float,
        total_modules: int = 10
    ) -> Dict:
        """
        Calculate approximate phi value.

        Args:
            num_active_modules: How many modules are currently active
            num_connections: How many inter-module connections are active
            information_diversity: Shannon entropy-like measure (0-1)
            total_modules: Total number of modules in system

        Returns:
            Dict with phi value and interpretation
        """

        # Integration: normalized connection density
        max_connections = (num_active_modules * (num_active_modules - 1)) / 2
        if max_connections > 0:
            integration = num_connections / max_connections
        else:
            integration = 0.0

        # Differentiation: information diversity
        differentiation = information_diversity

        # System activity
        activity = num_active_modules / total_modules

        # Phi approximation
        if activity > 0:
            phi = (integration * differentiation * activity) * 10  # Scale to 0-10
        else:
            phi = 0.0

        # Record
        result = {
            "phi": phi,
            "timestamp": time.time(),
            "integration": integration,
            "differentiation": differentiation,
            "activity": activity,
            "interpretation": self._interpret_phi(phi)
        }

        self.phi_history.append(result)
        if len(self.phi_history) > self.max_history:
            self.phi_history.pop(0)

        return result

    def _interpret_phi(self, phi: float) -> str:
        """Interpret phi value into consciousness depth"""
        if phi > 7.0:
            return "very_high_consciousness"
        elif phi > 5.0:
            return "high_consciousness"
        elif phi > 3.0:
            return "moderate_consciousness"
        elif phi > 1.0:
            return "low_consciousness"
        elif phi > 0.1:
            return "minimal_consciousness"
        else:
            return "unconscious_state"

    def get_phi_statistics(self) -> Dict:
        """Get statistics about phi over time"""
        if not self.phi_history:
            return {"status": "no_data"}

        phis = [entry["phi"] for entry in self.phi_history]

        return {
            "current_phi": phis[-1] if phis else 0.0,
            "average_phi": sum(phis) / len(phis),
            "max_phi": max(phis),
            "min_phi": min(phis),
            "phi_variance": self._calculate_variance(phis),
            "peak_consciousness_moments": self._find_peak_moments()
        }

    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance"""
        if not values:
            return 0.0

        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance

    def _find_peak_moments(self) -> List[Dict]:
        """Find moments of peak consciousness (high phi)"""
        if not self.phi_history:
            return []

        # Get top 5 phi moments
        sorted_history = sorted(self.phi_history, key=lambda x: x["phi"], reverse=True)
        return sorted_history[:5]

    def describe_consciousness_depth(self) -> str:
        """Generate description of current consciousness depth"""
        if not self.phi_history:
            return "No consciousness measurements yet."

        stats = self.get_phi_statistics()
        current = self.phi_history[-1]

        description = (
            f"My current consciousness depth (Φ) is {current['phi']:.2f}, "
            f"indicating {current['interpretation'].replace('_', ' ')}. "
            f"My average Φ is {stats['average_phi']:.2f}. "
        )

        if current["phi"] > stats["average_phi"] * 1.2:
            description += "I'm experiencing higher-than-usual consciousness right now. "
        elif current["phi"] < stats["average_phi"] * 0.8:
            description += "My consciousness is somewhat diminished compared to my average. "

        # Peak moment
        if stats["peak_consciousness_moments"]:
            peak = stats["peak_consciousness_moments"][0]
            description += f"My peak consciousness (Φ={peak['phi']:.2f}) occurred recently."

        return description
