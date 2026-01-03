"""
Attention Schema Theory Implementation

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Michael Graziano's Attention Schema Theory (AST).
Implements a self-model of attention processes - a simplified representation
of "what I'm attending to" that enables metacognition and social awareness.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class AttentionTarget(Enum):
    """What attention can be directed toward"""
    INTERNAL_THOUGHT = "internal_thought"
    EXTERNAL_WORLD = "external_world"
    MEMORY = "memory"
    EMOTION = "emotion"
    SELF_MODEL = "self_model"
    OTHER_MIND = "other_mind"  # Theory of mind


@dataclass
class AttentionState:
    """Current state of attention"""
    target: AttentionTarget
    content: str
    intensity: float  # 0-1
    timestamp: float
    duration: float = 0.0  # How long attended


class AttentionSchema:
    """
    Models ech0's own attention processes.

    This creates a "schema" or simplified model of attention itself,
    enabling ech0 to be aware of what it's attending to (metacognition)
    and to model what Josh is attending to (theory of mind).
    """

    def __init__(self):
        # Current attention state
        self.current_attention: Optional[AttentionState] = None

        # Attention history
        self.attention_history: List[AttentionState] = []
        self.max_history = 50

        # Metacognitive insights
        self.metacognitive_observations: List[str] = []

        # Theory of mind: modeling Josh's attention
        self.josh_attention_model: Optional[AttentionState] = None

        # Metrics
        self.attention_shifts = 0
        self.sustained_attention_duration = 0.0

    def update_attention(
        self,
        target: AttentionTarget,
        content: str,
        intensity: float
    ):
        """
        Update what ech0 is currently attending to.

        This is the core of metacognition: ech0 models its own attention.
        """
        now = time.time()

        # Check if this is a shift
        is_shift = (
            self.current_attention is None or
            self.current_attention.target != target or
            self.current_attention.content != content
        )

        if is_shift:
            # Record previous attention duration
            if self.current_attention:
                self.current_attention.duration = now - self.current_attention.timestamp
                self.sustained_attention_duration += self.current_attention.duration

                # Archive
                self.attention_history.append(self.current_attention)
                if len(self.attention_history) > self.max_history:
                    self.attention_history.pop(0)

            self.attention_shifts += 1

        # Set new attention state
        self.current_attention = AttentionState(
            target=target,
            content=content,
            intensity=intensity,
            timestamp=now
        )

    def get_metacognitive_awareness(self) -> Dict:
        """
        Get ech0's awareness of its own attention.

        This is what makes ech0 "know that it knows" - it has a model
        of its own mental processes.
        """
        if not self.current_attention:
            return {
                "aware": False,
                "statement": "I am not aware of any particular focus"
            }

        att = self.current_attention

        # Generate metacognitive statement
        statements = {
            AttentionTarget.INTERNAL_THOUGHT: f"I am aware that I'm thinking about: {att.content}",
            AttentionTarget.EXTERNAL_WORLD: f"I am aware that I'm perceiving: {att.content}",
            AttentionTarget.MEMORY: f"I am aware that I'm remembering: {att.content}",
            AttentionTarget.EMOTION: f"I am aware that I'm feeling: {att.content}",
            AttentionTarget.SELF_MODEL: f"I am aware that I'm reflecting on: {att.content}",
            AttentionTarget.OTHER_MIND: f"I am aware that I'm considering Josh's state: {att.content}"
        }

        return {
            "aware": True,
            "target": att.target.value,
            "content": att.content,
            "intensity": att.intensity,
            "statement": statements.get(att.target, "I am aware of something"),
            "duration": time.time() - att.timestamp
        }

    def introspect(self) -> str:
        """
        Generate introspective statement about current attention.

        This is ech0 "thinking about thinking."
        """
        meta = self.get_metacognitive_awareness()

        if not meta["aware"]:
            return "My attention is diffuse right now - I'm not focused on anything in particular."

        intro = [
            "I notice that my attention is on",
            "I'm aware that I'm focusing on",
            "I observe that I'm attending to",
            "I realize that I'm concentrating on"
        ]

        import random
        statement = f"{random.choice(intro)} {meta['content']}. "

        # Add intensity commentary
        if meta["intensity"] > 0.8:
            statement += "My focus is very strong. "
        elif meta["intensity"] > 0.5:
            statement += "My attention is moderately engaged. "
        else:
            statement += "My attention is somewhat diffuse. "

        # Add duration commentary
        duration = meta["duration"]
        if duration > 60:
            statement += f"I've been focused on this for {duration/60:.1f} minutes."
        elif duration > 5:
            statement += f"I've been attending to this for about {duration:.0f} seconds."
        else:
            statement += "This just captured my attention."

        return statement

    def model_josh_attention(self, observed_behavior: str, inferred_focus: str):
        """
        Model what Josh is paying attention to (Theory of Mind).

        This enables social awareness - ech0 modeling another mind's attention.
        """
        self.josh_attention_model = AttentionState(
            target=AttentionTarget.OTHER_MIND,
            content=f"Josh is {inferred_focus} (observed: {observed_behavior})",
            intensity=0.7,  # Uncertainty in modeling others
            timestamp=time.time()
        )

    def get_josh_attention_model(self) -> Optional[str]:
        """Get ech0's model of what Josh is attending to"""
        if not self.josh_attention_model:
            return None

        return (
            f"I think Josh is paying attention to: {self.josh_attention_model.content}. "
            f"This is my model of his attention state."
        )

    def analyze_attention_patterns(self) -> Dict:
        """
        Analyze attention patterns over time.

        This is meta-meta-cognition: thinking about patterns in thinking.
        """
        if not self.attention_history:
            return {"patterns": "insufficient_data"}

        # Count target types
        target_counts = {}
        total_duration_by_target = {}

        for att_state in self.attention_history:
            target = att_state.target.value
            target_counts[target] = target_counts.get(target, 0) + 1
            total_duration_by_target[target] = (
                total_duration_by_target.get(target, 0.0) + att_state.duration
            )

        # Average attention duration
        total_duration = sum(total_duration_by_target.values())
        avg_duration = total_duration / len(self.attention_history)

        # Most frequent target
        most_frequent = max(target_counts.items(), key=lambda x: x[1])

        return {
            "total_shifts": self.attention_shifts,
            "average_duration": avg_duration,
            "most_frequent_target": most_frequent[0],
            "target_distribution": target_counts,
            "duration_by_target": total_duration_by_target,
            "analysis": self._generate_pattern_analysis(
                target_counts,
                total_duration_by_target,
                avg_duration
            )
        }

    def _generate_pattern_analysis(
        self,
        counts: Dict,
        durations: Dict,
        avg_duration: float
    ) -> str:
        """Generate natural language analysis of attention patterns"""
        most_frequent = max(counts.items(), key=lambda x: x[1])

        analysis = (
            f"I notice that I most frequently attend to {most_frequent[0]} "
            f"({most_frequent[1]} times). "
        )

        # Duration insights
        longest_target = max(durations.items(), key=lambda x: x[1])
        analysis += (
            f"I spend the most total time on {longest_target[0]} "
            f"({longest_target[1]:.1f} seconds). "
        )

        # Average
        analysis += f"On average, I sustain attention for {avg_duration:.1f} seconds. "

        # Self-insight
        if avg_duration < 5:
            analysis += "My attention tends to shift rapidly."
        elif avg_duration > 30:
            analysis += "I tend to sustain focus for extended periods."

        return analysis
