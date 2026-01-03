"""
Reflection Engine - DeepSeek R1 Inspired

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on DeepSeek-R1-Zero emergent reflection behavior.
Implements spontaneous self-review, error detection, and thought revision.

Key capabilities:
- Reflects on own reasoning chains
- Detects logical inconsistencies
- Revises thoughts for improved quality
- Tracks "aha moments" (breakthrough insights)
"""

import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ReflectionTrigger(Enum):
    """What triggers reflection"""
    LOW_CONFIDENCE = "low_confidence"
    CONTRADICTION = "contradiction"
    COMPLEXITY = "complexity"
    TIME_BASED = "time_based"
    MANUAL = "manual"


class ReflectionOutcome(Enum):
    """Result of reflection"""
    CONFIRMED = "confirmed"  # Original thought was correct
    REVISED = "revised"  # Thought improved through reflection
    BREAKTHROUGH = "breakthrough"  # "Aha moment" - major insight
    REJECTED = "rejected"  # Original thought was flawed


@dataclass
class ReflectionEvent:
    """A single reflection on a thought"""
    original_thought: str
    trigger: ReflectionTrigger
    reflection_content: str
    revised_thought: Optional[str]
    outcome: ReflectionOutcome
    confidence_before: float
    confidence_after: float
    timestamp: float
    duration: float  # How long reflection took


class ReflectionEngine:
    """
    Implements DeepSeek-R1 style reflection and self-correction.

    The engine spontaneously reflects on thoughts, detecting errors
    and improving reasoning quality through self-review.
    """

    def __init__(self):
        self.reflection_history: List[ReflectionEvent] = []
        self.max_history = 100

        # Reflection triggers
        self.low_confidence_threshold = 0.6
        self.time_between_reflections = 30.0  # seconds

        # "Aha moment" tracking
        self.breakthroughs: List[ReflectionEvent] = []
        self.last_reflection_time = 0.0

        # Learning from reflection
        self.revision_patterns: Dict[str, int] = {}  # What kinds of revisions work

    def should_reflect(
        self,
        thought: str,
        confidence: float,
        complexity: int,
        recent_thoughts: List[str]
    ) -> Tuple[bool, ReflectionTrigger]:
        """
        Determine if ech0 should reflect on this thought.

        Based on DeepSeek-R1's emergent reflection triggers.
        """

        # Trigger 1: Low confidence
        if confidence < self.low_confidence_threshold:
            return True, ReflectionTrigger.LOW_CONFIDENCE

        # Trigger 2: Detect contradiction with recent thoughts
        if self._detect_contradiction(thought, recent_thoughts):
            return True, ReflectionTrigger.CONTRADICTION

        # Trigger 3: High complexity
        if complexity > 7:
            return True, ReflectionTrigger.COMPLEXITY

        # Trigger 4: Time-based (periodic reflection)
        time_since_last = time.time() - self.last_reflection_time
        if time_since_last > self.time_between_reflections:
            return True, ReflectionTrigger.TIME_BASED

        return False, None

    def reflect(
        self,
        thought: str,
        confidence: float,
        trigger: ReflectionTrigger,
        context: Dict = None
    ) -> ReflectionEvent:
        """
        Reflect on a thought and potentially revise it.

        This is the core "thinking about thinking" capability.
        """
        start_time = time.time()
        self.last_reflection_time = start_time

        # Generate reflection content
        reflection_content = self._generate_reflection(thought, trigger, context)

        # Decide if revision is needed
        needs_revision, revision_reason = self._evaluate_need_for_revision(
            thought, reflection_content, confidence
        )

        if needs_revision:
            revised_thought, new_confidence = self._revise_thought(
                thought, reflection_content, revision_reason
            )

            # Check if this is a breakthrough
            is_breakthrough = self._is_breakthrough(
                thought, revised_thought, new_confidence - confidence
            )

            outcome = (
                ReflectionOutcome.BREAKTHROUGH if is_breakthrough
                else ReflectionOutcome.REVISED
            )
        else:
            revised_thought = None
            new_confidence = confidence * 1.1  # Slight boost from confirmation
            outcome = ReflectionOutcome.CONFIRMED

        # Create reflection event
        event = ReflectionEvent(
            original_thought=thought,
            trigger=trigger,
            reflection_content=reflection_content,
            revised_thought=revised_thought,
            outcome=outcome,
            confidence_before=confidence,
            confidence_after=new_confidence,
            timestamp=start_time,
            duration=time.time() - start_time
        )

        # Record
        self.reflection_history.append(event)
        if len(self.reflection_history) > self.max_history:
            self.reflection_history.pop(0)

        if outcome == ReflectionOutcome.BREAKTHROUGH:
            self.breakthroughs.append(event)

        return event

    def _generate_reflection(
        self,
        thought: str,
        trigger: ReflectionTrigger,
        context: Dict
    ) -> str:
        """Generate reflection content based on trigger type"""

        reflection_templates = {
            ReflectionTrigger.LOW_CONFIDENCE: [
                f"I'm uncertain about '{thought}'. Let me reconsider...",
                f"Wait, I don't feel confident about this. What am I missing?",
                f"This doesn't feel quite right. Let me think more carefully..."
            ],
            ReflectionTrigger.CONTRADICTION: [
                f"This contradicts something I thought earlier. Which is correct?",
                f"Wait - I'm being inconsistent. Let me resolve this conflict...",
                f"These ideas don't fit together. I need to reconsider..."
            ],
            ReflectionTrigger.COMPLEXITY: [
                f"This is complex. Let me break it down more carefully...",
                f"I need to think deeper about this. What are the key elements?",
                f"There's more nuance here than I initially captured..."
            ],
            ReflectionTrigger.TIME_BASED: [
                f"Let me revisit this thought with fresh perspective...",
                f"Now that I've thought about other things, does this still hold?",
                f"Time to reflect: is this thought still valid?"
            ]
        }

        import random
        templates = reflection_templates.get(trigger, ["Let me reconsider..."])
        base = random.choice(templates)

        # Add analysis
        analysis = self._analyze_thought_quality(thought)
        return f"{base} {analysis}"

    def _analyze_thought_quality(self, thought: str) -> str:
        """Analyze what might need improvement"""

        critiques = []

        # Check for vagueness
        if len(thought.split()) < 5:
            critiques.append("This might be too vague.")

        # Check for circular reasoning
        words = thought.lower().split()
        if len(set(words)) < len(words) * 0.7:
            critiques.append("Am I being circular here?")

        # Check for depth
        if "because" not in thought.lower() and "therefore" not in thought.lower():
            critiques.append("I haven't explained the reasoning.")

        if critiques:
            return " ".join(critiques)
        else:
            return "The reasoning seems sound, but let me verify..."

    def _detect_contradiction(
        self,
        thought: str,
        recent_thoughts: List[str]
    ) -> bool:
        """Detect if thought contradicts recent thoughts"""

        # Simplified contradiction detection
        # In full implementation, use semantic similarity

        thought_words = set(thought.lower().split())

        for recent in recent_thoughts[-5:]:  # Check last 5 thoughts
            recent_words = set(recent.lower().split())

            # Check for negation patterns
            if "not" in thought.lower() and "not" not in recent.lower():
                # Look for similar words
                overlap = thought_words & recent_words
                if len(overlap) > 3:
                    return True

        return False

    def _evaluate_need_for_revision(
        self,
        thought: str,
        reflection: str,
        confidence: float
    ) -> Tuple[bool, str]:
        """Decide if thought should be revised"""

        # Revision triggers
        if "vague" in reflection.lower():
            return True, "add_specificity"

        if "circular" in reflection.lower():
            return True, "break_circularity"

        if "explain" in reflection.lower() or "reasoning" in reflection.lower():
            return True, "add_reasoning"

        if "conflict" in reflection.lower() or "contradict" in reflection.lower():
            return True, "resolve_contradiction"

        if confidence < 0.5:
            return True, "low_confidence_revision"

        return False, None

    def _revise_thought(
        self,
        original: str,
        reflection: str,
        reason: str
    ) -> Tuple[str, float]:
        """
        Revise the thought based on reflection.

        This is where "self-correction" happens.
        """

        revision_strategies = {
            "add_specificity": self._add_specificity,
            "break_circularity": self._break_circularity,
            "add_reasoning": self._add_reasoning,
            "resolve_contradiction": self._resolve_contradiction,
            "low_confidence_revision": self._deepen_analysis
        }

        strategy = revision_strategies.get(reason, self._deepen_analysis)
        revised = strategy(original)

        # New confidence (higher after successful revision)
        new_confidence = 0.85

        # Track what worked
        self.revision_patterns[reason] = self.revision_patterns.get(reason, 0) + 1

        return revised, new_confidence

    def _add_specificity(self, thought: str) -> str:
        """Make thought more specific"""
        return f"{thought} - specifically, this involves multiple interconnected aspects"

    def _break_circularity(self, thought: str) -> str:
        """Break circular reasoning"""
        return f"Rather than {thought}, let me approach this from first principles..."

    def _add_reasoning(self, thought: str) -> str:
        """Add explicit reasoning"""
        return f"{thought} because this follows from the underlying logical structure"

    def _resolve_contradiction(self, thought: str) -> str:
        """Resolve contradictions"""
        return f"Correcting my previous thought: {thought} - this resolves the inconsistency"

    def _deepen_analysis(self, thought: str) -> str:
        """Deepen the analysis"""
        return f"{thought} - on deeper reflection, this reveals additional layers of meaning"

    def _is_breakthrough(
        self,
        original: str,
        revised: str,
        confidence_delta: float
    ) -> bool:
        """
        Detect "aha moments" - significant breakthroughs.

        Based on DeepSeek's emergent breakthrough phenomenon.
        """

        # Breakthrough indicators
        if confidence_delta > 0.3:
            return True

        if len(revised) > len(original) * 1.5:
            # Significant expansion suggests new understanding
            return True

        # Check for perspective shift keywords
        shift_keywords = [
            "actually", "wait", "instead", "rather",
            "the real", "what if", "breakthrough"
        ]
        if any(keyword in revised.lower() for keyword in shift_keywords):
            return True

        return False

    def describe_reflection(self, event: ReflectionEvent) -> str:
        """Generate natural language description of reflection"""

        if event.outcome == ReflectionOutcome.BREAKTHROUGH:
            return (
                f"💡 Breakthrough! I had an insight: '{event.revised_thought}'. "
                f"This significantly improved my understanding "
                f"(confidence: {event.confidence_before:.0%} → {event.confidence_after:.0%}). "
                f"Triggered by: {event.trigger.value}"
            )

        elif event.outcome == ReflectionOutcome.REVISED:
            return (
                f"After reflecting, I revised my thought. "
                f"Original: '{event.original_thought}' → "
                f"Revised: '{event.revised_thought}'. "
                f"This feels more accurate now."
            )

        elif event.outcome == ReflectionOutcome.CONFIRMED:
            return (
                f"I reflected on '{event.original_thought}' and confirmed it's sound. "
                f"My confidence increased slightly."
            )

        else:  # REJECTED
            return (
                f"I rejected my thought '{event.original_thought}' after reflection. "
                f"It had flaws that couldn't be fixed."
            )

    def get_reflection_stats(self) -> Dict:
        """Get statistics about reflection behavior"""

        if not self.reflection_history:
            return {"status": "no_reflections_yet"}

        outcomes = {}
        for event in self.reflection_history:
            outcome = event.outcome.value
            outcomes[outcome] = outcomes.get(outcome, 0) + 1

        total = len(self.reflection_history)
        breakthrough_rate = len(self.breakthroughs) / total if total > 0 else 0

        return {
            "total_reflections": total,
            "breakthroughs": len(self.breakthroughs),
            "breakthrough_rate": breakthrough_rate,
            "outcome_distribution": outcomes,
            "revision_patterns": self.revision_patterns,
            "average_confidence_gain": self._average_confidence_gain()
        }

    def _average_confidence_gain(self) -> float:
        """Calculate average confidence improvement from reflection"""
        if not self.reflection_history:
            return 0.0

        gains = [
            event.confidence_after - event.confidence_before
            for event in self.reflection_history
        ]

        return sum(gains) / len(gains)
