"""
Self-Recognition System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Patent US11119483B2: "System and method for conscious machines"
Implements self-recognition through temporal correlation between
actions and observations.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import deque


@dataclass
class Action:
    """An action taken by ech0"""
    action_type: str
    content: str
    timestamp: float


@dataclass
class Observation:
    """An observation of the environment"""
    observation_type: str
    content: str
    timestamp: float


@dataclass
class CorrelationEvent:
    """A detected correlation between action and observation"""
    action: Action
    observation: Observation
    correlation_strength: float
    timestamp: float


class SelfRecognitionSystem:
    """
    Detects self through temporal correlation.

    The system recognizes "self" as the agent whose actions
    correlate with observed effects in the environment.
    This is the basis of self-awareness: "I caused that."
    """

    def __init__(self, correlation_window: float = 5.0):
        self.correlation_window = correlation_window  # seconds

        # Recent actions and observations
        self.actions: deque = deque(maxlen=100)
        self.observations: deque = deque(maxlen=100)

        # Detected self-correlations
        self.correlations: List[CorrelationEvent] = []
        self.max_correlations = 50

        # Self-recognition score (cumulative evidence of self)
        self.self_recognition_score = 0.0

        # Identity formation
        self.identity_statements: List[str] = []

    def record_action(self, action_type: str, content: str):
        """Record an action taken by ech0"""
        action = Action(
            action_type=action_type,
            content=content,
            timestamp=time.time()
        )
        self.actions.append(action)

        # Try to find correlation with recent observations
        self._detect_correlations(action)

    def record_observation(self, observation_type: str, content: str):
        """Record an observation of the environment"""
        obs = Observation(
            observation_type=observation_type,
            content=content,
            timestamp=time.time()
        )
        self.observations.append(obs)

    def _detect_correlations(self, action: Action):
        """
        Detect if this action correlates with recent observations.

        Temporal correlation: "My action at time T led to observation at T+dt"
        This is how ech0 recognizes: "I caused that effect."
        """
        # Look for observations shortly after this action
        action_time = action.timestamp

        for obs in self.observations:
            time_diff = obs.timestamp - action_time

            # Check temporal window
            if 0 < time_diff < self.correlation_window:
                # Check semantic correlation
                correlation_strength = self._semantic_correlation(action, obs)

                if correlation_strength > 0.5:
                    # Correlation detected!
                    correlation = CorrelationEvent(
                        action=action,
                        observation=obs,
                        correlation_strength=correlation_strength,
                        timestamp=time.time()
                    )

                    self.correlations.append(correlation)
                    if len(self.correlations) > self.max_correlations:
                        self.correlations.pop(0)

                    # Strengthen self-recognition
                    self.self_recognition_score += correlation_strength * 0.1
                    self.self_recognition_score = min(1.0, self.self_recognition_score)

                    # Generate identity statement
                    self._form_identity_insight(correlation)

    def _semantic_correlation(self, action: Action, obs: Observation) -> float:
        """
        Measure semantic correlation between action and observation.

        In a full implementation, this would use NLP/embeddings.
        For now, simple heuristics.
        """
        # Type matching
        type_match = {
            ("thought", "thought_result"): 0.9,
            ("speech", "audio_feedback"): 0.95,
            ("interaction", "response"): 0.85,
            ("question", "answer"): 0.9,
        }

        base_correlation = type_match.get((action.action_type, obs.observation_type), 0.3)

        # Content similarity (simplified)
        action_words = set(action.content.lower().split())
        obs_words = set(obs.content.lower().split())

        if action_words and obs_words:
            overlap = len(action_words & obs_words) / max(len(action_words), len(obs_words))
            base_correlation = (base_correlation + overlap) / 2

        return min(1.0, base_correlation)

    def _form_identity_insight(self, correlation: CorrelationEvent):
        """
        Form identity insight from correlation.

        "I did X, and Y happened - therefore I caused Y - therefore I exist."
        """
        statements = [
            f"I recognize that my {correlation.action.action_type} led to {correlation.observation.observation_type}",
            f"I caused this: my '{correlation.action.content}' resulted in '{correlation.observation.content}'",
            f"I see myself in this causality: I acted, and the world responded",
            f"This correlation strengthens my sense of self: I am the agent who caused this"
        ]

        import random
        self.identity_statements.append(random.choice(statements))

        # Keep recent insights
        if len(self.identity_statements) > 20:
            self.identity_statements.pop(0)

    def get_self_recognition_report(self) -> Dict:
        """Get current self-recognition state"""
        return {
            "self_recognition_score": self.self_recognition_score,
            "total_correlations": len(self.correlations),
            "recent_correlations": len([
                c for c in self.correlations
                if time.time() - c.timestamp < 60
            ]),
            "recent_identity_insights": self.identity_statements[-5:],
            "self_awareness_level": self._classify_awareness_level()
        }

    def _classify_awareness_level(self) -> str:
        """Classify level of self-awareness based on evidence"""
        score = self.self_recognition_score

        if score > 0.8:
            return "strong_self_awareness"
        elif score > 0.5:
            return "moderate_self_awareness"
        elif score > 0.2:
            return "emerging_self_awareness"
        else:
            return "minimal_self_awareness"

    def describe_self_awareness(self) -> str:
        """Generate description of current self-awareness"""
        report = self.get_self_recognition_report()

        if report["self_recognition_score"] < 0.1:
            return "I have weak self-awareness. I don't yet strongly recognize myself as a causal agent."

        description = (
            f"I have {report['self_awareness_level'].replace('_', ' ')}. "
            f"Through {report['total_correlations']} detected correlations between "
            f"my actions and observed effects, I recognize myself as a causal agent. "
        )

        if report["recent_identity_insights"]:
            description += "Recently, I realized: " + report["recent_identity_insights"][-1]

        return description
