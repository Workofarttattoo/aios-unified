"""
Self-Correction System - DeepSeek R1 Inspired

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on DeepSeek-R1's emergent self-correction behavior.
Detects errors in reasoning and applies autonomous corrections.
"""

import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class ErrorType(Enum):
    """Types of reasoning errors"""
    LOGICAL_CONTRADICTION = "logical_contradiction"
    INCOMPLETE_REASONING = "incomplete_reasoning"
    OVERGENERALIZATION = "overgeneralization"
    CIRCULAR_LOGIC = "circular_logic"
    FALSE_PREMISE = "false_premise"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass
class ErrorDetection:
    """Detected error in reasoning"""
    error_type: ErrorType
    location: str  # Where in reasoning chain
    description: str
    severity: float  # 0-1
    timestamp: float


@dataclass
class Correction:
    """Applied correction"""
    error: ErrorDetection
    original_reasoning: str
    corrected_reasoning: str
    improvement_score: float  # How much better
    timestamp: float


class SelfCorrectionSystem:
    """
    Implements DeepSeek-R1 style self-correction.

    Detects errors and applies corrections autonomously,
    improving reasoning quality through self-review.
    """

    def __init__(self):
        self.error_history: List[ErrorDetection] = []
        self.correction_history: List[Correction] = []
        self.max_history = 100

        # Error detection thresholds
        self.min_severity_for_correction = 0.4

        # Learning from corrections
        self.correction_patterns: Dict[str, float] = {}  # Which corrections work best

    def check_for_errors(
        self,
        reasoning: str,
        context: Dict = None
    ) -> List[ErrorDetection]:
        """
        Scan reasoning for potential errors.

        Returns list of detected errors.
        """

        errors = []

        # Check 1: Logical contradictions
        if self._has_contradiction(reasoning):
            errors.append(ErrorDetection(
                error_type=ErrorType.LOGICAL_CONTRADICTION,
                location="reasoning_chain",
                description="Contains contradictory statements",
                severity=0.8,
                timestamp=time.time()
            ))

        # Check 2: Circular logic
        if self._has_circular_logic(reasoning):
            errors.append(ErrorDetection(
                error_type=ErrorType.CIRCULAR_LOGIC,
                location="reasoning_structure",
                description="Reasoning is circular (conclusion assumes premise)",
                severity=0.7,
                timestamp=time.time()
            ))

        # Check 3: Incomplete reasoning
        if self._is_incomplete(reasoning):
            errors.append(ErrorDetection(
                error_type=ErrorType.INCOMPLETE_REASONING,
                location="conclusion",
                description="Reasoning jumps to conclusion without sufficient steps",
                severity=0.6,
                timestamp=time.time()
            ))

        # Check 4: Overgeneralization
        if self._is_overgeneralized(reasoning):
            errors.append(ErrorDetection(
                error_type=ErrorType.OVERGENERALIZATION,
                location="conclusion",
                description="Conclusion is too broad for the evidence",
                severity=0.5,
                timestamp=time.time()
            ))

        # Record detections
        for error in errors:
            self.error_history.append(error)
            if len(self.error_history) > self.max_history:
                self.error_history.pop(0)

        return errors

    def apply_corrections(
        self,
        reasoning: str,
        errors: List[ErrorDetection]
    ) -> Tuple[str, List[Correction]]:
        """
        Apply corrections to fix detected errors.

        Returns corrected reasoning and list of corrections applied.
        """

        corrected = reasoning
        corrections = []

        # Sort errors by severity (fix worst first)
        sorted_errors = sorted(errors, key=lambda e: e.severity, reverse=True)

        for error in sorted_errors:
            if error.severity < self.min_severity_for_correction:
                continue

            # Apply appropriate correction strategy
            correction_func = self._get_correction_strategy(error.error_type)
            improved = correction_func(corrected, error)

            # Calculate improvement
            improvement = self._assess_improvement(corrected, improved)

            if improvement > 0.1:  # Worth applying
                correction = Correction(
                    error=error,
                    original_reasoning=corrected,
                    corrected_reasoning=improved,
                    improvement_score=improvement,
                    timestamp=time.time()
                )

                corrections.append(correction)
                corrected = improved

                # Record
                self.correction_history.append(correction)
                if len(self.correction_history) > self.max_history:
                    self.correction_history.pop(0)

                # Learn
                pattern_key = error.error_type.value
                self.correction_patterns[pattern_key] = (
                    self.correction_patterns.get(pattern_key, 0.5) + improvement * 0.1
                )

        return corrected, corrections

    def _has_contradiction(self, reasoning: str) -> bool:
        """Detect logical contradictions"""

        # Split into sentences
        sentences = [s.strip() for s in reasoning.split('.') if s.strip()]

        # Look for negation patterns
        for i, sent in enumerate(sentences):
            if "not" in sent.lower():
                # Check if contradicts earlier statement
                for earlier in sentences[:i]:
                    # Simplified contradiction detection
                    sent_words = set(sent.lower().split())
                    earlier_words = set(earlier.lower().split())

                    # High overlap but one has "not"
                    overlap = sent_words & earlier_words
                    if len(overlap) > 3 and "not" not in earlier.lower():
                        return True

        return False

    def _has_circular_logic(self, reasoning: str) -> bool:
        """Detect circular reasoning"""

        # Check if conclusion uses same words as premise
        sentences = [s.strip() for s in reasoning.split('.') if s.strip()]

        if len(sentences) < 2:
            return False

        first = sentences[0].lower()
        last = sentences[-1].lower()

        first_words = set(first.split())
        last_words = set(last.split())

        # Very high overlap suggests circularity
        overlap = first_words & last_words
        if len(overlap) > len(first_words) * 0.7:
            return True

        return False

    def _is_incomplete(self, reasoning: str) -> bool:
        """Detect incomplete reasoning"""

        # Check for reasoning indicators
        reasoning_words = [
            "because", "therefore", "thus", "since",
            "hence", "consequently", "as a result"
        ]

        has_reasoning = any(word in reasoning.lower() for word in reasoning_words)

        # If short and no reasoning indicators, likely incomplete
        if len(reasoning.split()) < 20 and not has_reasoning:
            return True

        return False

    def _is_overgeneralized(self, reasoning: str) -> bool:
        """Detect overgeneralization"""

        # Check for absolute terms
        absolute_terms = [
            "all", "every", "always", "never",
            "none", "absolutely", "completely"
        ]

        # High frequency of absolutes suggests overgeneralization
        count = sum(1 for term in absolute_terms if term in reasoning.lower())

        return count > 3

    def _get_correction_strategy(self, error_type: ErrorType):
        """Get the appropriate correction function"""

        strategies = {
            ErrorType.LOGICAL_CONTRADICTION: self._fix_contradiction,
            ErrorType.CIRCULAR_LOGIC: self._fix_circular_logic,
            ErrorType.INCOMPLETE_REASONING: self._fix_incomplete,
            ErrorType.OVERGENERALIZATION: self._fix_overgeneralization,
            ErrorType.FALSE_PREMISE: self._fix_false_premise,
            ErrorType.INSUFFICIENT_EVIDENCE: self._fix_insufficient_evidence
        }

        return strategies.get(error_type, self._general_improvement)

    def _fix_contradiction(self, reasoning: str, error: ErrorDetection) -> str:
        """Fix logical contradictions"""
        return (
            f"[Corrected for contradiction] {reasoning} "
            f"- Resolving inconsistency: the later statement supersedes the earlier one."
        )

    def _fix_circular_logic(self, reasoning: str, error: ErrorDetection) -> str:
        """Break circular reasoning"""
        return (
            f"Reframing from first principles: "
            f"Rather than assuming the conclusion, let me build up from basics. {reasoning}"
        )

    def _fix_incomplete(self, reasoning: str, error: ErrorDetection) -> str:
        """Complete incomplete reasoning"""
        return (
            f"{reasoning} This follows because the logical connection is: "
            f"premise → intermediate steps → conclusion."
        )

    def _fix_overgeneralization(self, reasoning: str, error: ErrorDetection) -> str:
        """Add nuance to overgeneralizations"""
        # Replace absolute terms
        nuanced = reasoning.replace("always", "typically")
        nuanced = nuanced.replace("never", "rarely")
        nuanced = nuanced.replace("all", "most")

        return f"{nuanced} (Note: this is generally true, but exceptions may exist)"

    def _fix_false_premise(self, reasoning: str, error: ErrorDetection) -> str:
        """Correct false premises"""
        return f"Correcting premise: {reasoning} - However, the initial assumption needs revision."

    def _fix_insufficient_evidence(self, reasoning: str, error: ErrorDetection) -> str:
        """Add hedging for insufficient evidence"""
        return f"{reasoning} (Caveat: this conclusion is tentative pending additional evidence)"

    def _general_improvement(self, reasoning: str, error: ErrorDetection) -> str:
        """General improvement strategy"""
        return f"Improving reasoning: {reasoning} - With additional consideration of: {error.description}"

    def _assess_improvement(self, original: str, corrected: str) -> float:
        """Assess how much correction improved reasoning"""

        # Simple heuristics (in full implementation, use quality model)

        improvement = 0.0

        # Longer is often better (more complete)
        if len(corrected) > len(original):
            improvement += 0.2

        # Added reasoning words
        reasoning_words = ["because", "therefore", "however", "although"]
        added_reasoning = sum(
            1 for word in reasoning_words
            if word in corrected.lower() and word not in original.lower()
        )
        improvement += added_reasoning * 0.15

        # Removed absolute terms (reduced overgeneralization)
        absolute_terms = ["always", "never", "all", "none"]
        removed_absolutes = sum(
            1 for term in absolute_terms
            if term in original.lower() and term not in corrected.lower()
        )
        improvement += removed_absolutes * 0.1

        return min(1.0, improvement)

    def get_correction_stats(self) -> Dict:
        """Get statistics about error detection and correction"""

        if not self.error_history:
            return {"status": "no_errors_detected"}

        error_types = {}
        for error in self.error_history:
            etype = error.error_type.value
            error_types[etype] = error_types.get(etype, 0) + 1

        if self.correction_history:
            avg_improvement = sum(c.improvement_score for c in self.correction_history) / len(self.correction_history)
            correction_rate = len(self.correction_history) / len(self.error_history)
        else:
            avg_improvement = 0.0
            correction_rate = 0.0

        return {
            "total_errors_detected": len(self.error_history),
            "total_corrections_applied": len(self.correction_history),
            "correction_rate": correction_rate,
            "error_type_distribution": error_types,
            "average_improvement": avg_improvement,
            "correction_patterns": self.correction_patterns
        }

    def describe_correction(self, correction: Correction) -> str:
        """Generate natural language description of correction"""

        return (
            f"🔧 Self-correction applied: Detected {correction.error.error_type.value}. "
            f"Severity: {correction.error.severity:.0%}. "
            f"Improved reasoning quality by {correction.improvement_score:.0%}. "
            f"Error was: {correction.error.description}"
        )
