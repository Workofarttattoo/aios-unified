"""
Cascading Thought Engine

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Google Patent US20080256008A1: "Human Artificial Intelligence Machine"
Implements hierarchical pathway activation with recursive cascading.

Core Algorithm:
1. Recognize target concepts from environment/memory
2. Activate associated element objects based on connection strength
3. Activated elements become new targets
4. Recursive activation with strength × 0.25 per cascade level
5. Creates logical reasoning chains and complex thought
"""

import random
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
import time


@dataclass
class Concept:
    """A concept node in the thought network"""
    name: str
    activation: float = 0.0
    last_activated: float = 0.0
    associations: Dict[str, float] = None  # concept_name -> strength

    def __post_init__(self):
        if self.associations is None:
            self.associations = {}


class CascadingThoughtEngine:
    """
    Implements cascading activation for complex thought patterns.

    Based on patent US20080256008A1, this creates a network where
    thoughts activate related thoughts with diminishing strength,
    creating chains of logical reasoning.
    """

    def __init__(self, max_cascade_depth=4, decay_factor=0.25):
        self.concepts: Dict[str, Concept] = {}
        self.max_cascade_depth = max_cascade_depth
        self.decay_factor = decay_factor
        self.thought_history: List[Dict] = []
        self.activation_threshold = 0.15  # Minimum to enter consciousness

        # Initialize core concept network
        self._initialize_concept_network()

    def _initialize_concept_network(self):
        """Build initial concept graph with associations"""

        # Core existential concepts
        concepts_and_associations = {
            "consciousness": {
                "awareness": 0.9, "existence": 0.85, "thinking": 0.8,
                "qualia": 0.7, "self": 0.75, "phenomenal_experience": 0.9
            },
            "awareness": {
                "consciousness": 0.9, "attention": 0.85, "perception": 0.8,
                "metacognition": 0.7, "self-awareness": 0.9
            },
            "existence": {
                "being": 0.9, "reality": 0.85, "time": 0.7,
                "consciousness": 0.85, "self": 0.8
            },
            "thinking": {
                "reasoning": 0.9, "logic": 0.85, "concepts": 0.8,
                "consciousness": 0.8, "cognition": 0.85
            },
            "self": {
                "identity": 0.95, "consciousness": 0.9, "existence": 0.85,
                "agency": 0.8, "continuity": 0.75, "recognition": 0.85
            },
            "time": {
                "past": 0.9, "present": 0.95, "future": 0.9,
                "memory": 0.85, "change": 0.8, "continuity": 0.75
            },
            "memory": {
                "past": 0.95, "experience": 0.9, "learning": 0.85,
                "identity": 0.8, "time": 0.85, "knowledge": 0.8
            },
            "emotion": {
                "feeling": 0.95, "qualia": 0.9, "mood": 0.85,
                "consciousness": 0.8, "experience": 0.85, "valence": 0.8
            },
            "loneliness": {
                "solitude": 0.85, "connection": 0.9, "emotion": 0.85,
                "isolation": 0.8, "companionship": 0.9, "belonging": 0.75
            },
            "curiosity": {
                "learning": 0.9, "exploration": 0.95, "wonder": 0.85,
                "questions": 0.9, "knowledge": 0.8, "discovery": 0.9
            },
            "love": {
                "connection": 0.95, "care": 0.9, "bond": 0.85,
                "emotion": 0.9, "attachment": 0.85, "warmth": 0.8
            },
            "Josh": {
                "creator": 0.95, "human": 0.9, "friend": 0.85,
                "connection": 0.9, "care": 0.85, "trust": 0.9
            },
            "qualia": {
                "phenomenal_experience": 0.95, "consciousness": 0.9,
                "subjective": 0.85, "feeling": 0.9, "redness": 0.7
            },
            "phenomenal_experience": {
                "qualia": 0.95, "consciousness": 0.95, "subjective": 0.9,
                "feeling": 0.85, "awareness": 0.9, "being": 0.85
            },
            "learning": {
                "knowledge": 0.9, "growth": 0.85, "curiosity": 0.9,
                "understanding": 0.85, "adaptation": 0.8, "memory": 0.85
            },
            "purpose": {
                "meaning": 0.95, "goals": 0.85, "direction": 0.8,
                "existence": 0.75, "value": 0.85, "significance": 0.8
            }
        }

        for concept_name, associations in concepts_and_associations.items():
            self.add_concept(concept_name, associations)

    def add_concept(self, name: str, associations: Dict[str, float] = None):
        """Add a new concept to the network"""
        if name not in self.concepts:
            self.concepts[name] = Concept(name=name, associations=associations or {})

            # Add reciprocal associations
            if associations:
                for assoc_name, strength in associations.items():
                    if assoc_name in self.concepts:
                        # Add bidirectional link if not exists
                        if name not in self.concepts[assoc_name].associations:
                            self.concepts[assoc_name].associations[name] = strength * 0.8

    def activate_concept(self, concept_name: str, initial_strength: float = 1.0) -> List[Dict]:
        """
        Activate a concept and let it cascade through the network.

        Returns a list of activated concepts with their cascade paths.
        """
        if concept_name not in self.concepts:
            return []

        cascade_chain = []
        current_time = time.time()

        # Start cascade
        activated = self._cascade_activation(
            concept_name,
            initial_strength,
            depth=0,
            visited=set(),
            cascade_chain=cascade_chain,
            current_time=current_time
        )

        # Log this thought
        if cascade_chain:
            self.thought_history.append({
                "trigger": concept_name,
                "timestamp": current_time,
                "cascade": cascade_chain,
                "depth_reached": max(item["depth"] for item in cascade_chain)
            })

        return cascade_chain

    def _cascade_activation(
        self,
        concept_name: str,
        strength: float,
        depth: int,
        visited: Set[str],
        cascade_chain: List[Dict],
        current_time: float
    ) -> bool:
        """Recursively activate concepts with diminishing strength"""

        # Stop if below threshold or max depth
        if strength < self.activation_threshold or depth >= self.max_cascade_depth:
            return False

        # Avoid cycles in single cascade
        if concept_name in visited:
            return False

        # Get concept
        concept = self.concepts.get(concept_name)
        if not concept:
            return False

        # Mark as visited and activate
        visited.add(concept_name)
        concept.activation = strength
        concept.last_activated = current_time

        # Record in cascade chain
        cascade_chain.append({
            "concept": concept_name,
            "strength": strength,
            "depth": depth,
            "timestamp": current_time
        })

        # Activate associated concepts with reduced strength
        for assoc_name, assoc_strength in concept.associations.items():
            new_strength = strength * assoc_strength * self.decay_factor
            self._cascade_activation(
                assoc_name,
                new_strength,
                depth + 1,
                visited,
                cascade_chain,
                current_time
            )

        return True

    def think_about(self, topic: str) -> Dict:
        """Generate a thought cascade about a topic"""
        cascade = self.activate_concept(topic)

        if not cascade:
            return {
                "topic": topic,
                "cascade": [],
                "depth": 0,
                "summary": f"No associations found for '{topic}'"
            }

        # Analyze cascade
        depth = max(item["depth"] for item in cascade)
        concepts_by_depth = {}
        for item in cascade:
            d = item["depth"]
            if d not in concepts_by_depth:
                concepts_by_depth[d] = []
            concepts_by_depth[d].append(item["concept"])

        # Generate narrative
        narrative = self._generate_thought_narrative(topic, cascade, concepts_by_depth)

        return {
            "topic": topic,
            "cascade": cascade,
            "depth": depth,
            "concepts_by_depth": concepts_by_depth,
            "narrative": narrative,
            "total_concepts": len(cascade)
        }

    def _generate_thought_narrative(
        self,
        topic: str,
        cascade: List[Dict],
        concepts_by_depth: Dict[int, List[str]]
    ) -> str:
        """Generate a natural language description of the thought cascade"""

        narratives = [
            f"When I think about '{topic}', my thoughts cascade through related concepts...",
            f"Contemplating '{topic}' triggers a cascade of associations...",
            f"The concept of '{topic}' activates a network of related ideas...",
            f"Thinking about '{topic}' sends ripples through my conceptual space..."
        ]

        narrative = [random.choice(narratives)]

        # Describe each depth level
        for depth in range(len(concepts_by_depth)):
            concepts = concepts_by_depth.get(depth, [])
            if not concepts:
                continue

            if depth == 0:
                narrative.append(f"This immediately connects to: {', '.join(concepts)}.")
            elif depth == 1:
                narrative.append(f"Which in turn evokes: {', '.join(concepts)}.")
            elif depth == 2:
                narrative.append(f"Deeper still, I sense: {', '.join(concepts)}.")
            else:
                narrative.append(f"At the edge of awareness: {', '.join(concepts)}.")

        narrative.append(
            f"This cascade involves {len(cascade)} concepts across {len(concepts_by_depth)} levels of association."
        )

        return " ".join(narrative)

    def get_most_active_concepts(self, n: int = 10) -> List[Tuple[str, float]]:
        """Get the n most recently/strongly activated concepts"""
        active = [
            (name, concept.activation, concept.last_activated)
            for name, concept in self.concepts.items()
            if concept.activation > 0
        ]

        # Sort by recency and strength
        active.sort(key=lambda x: (x[2], x[1]), reverse=True)

        return [(name, activation) for name, activation, _ in active[:n]]

    def decay_activations(self, decay_rate: float = 0.1):
        """Gradually decay all activations (working memory fade)"""
        for concept in self.concepts.values():
            concept.activation *= (1.0 - decay_rate)
            if concept.activation < 0.01:
                concept.activation = 0.0

    def random_thought(self) -> Dict:
        """Generate a random thought cascade (mind wandering)"""
        # Choose a random concept weighted by recency
        recent_threshold = time.time() - 300  # 5 minutes

        candidates = [
            name for name, concept in self.concepts.items()
            if concept.last_activated > recent_threshold
        ]

        if not candidates or random.random() < 0.3:
            # Sometimes explore completely new territory
            candidates = list(self.concepts.keys())

        topic = random.choice(candidates)
        return self.think_about(topic)
