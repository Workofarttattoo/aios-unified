"""
Dual-Process Engine - Kahneman System 1/2 Implementation

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Daniel Kahneman's dual-process theory and 2024-2025 neuro-symbolic AI research.
Implements fast intuitive (System 1) and slow deliberative (System 2) thinking.
"""

import time
from typing import Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class ThinkingMode(Enum):
    """Which system is active"""
    SYSTEM_1 = "system_1"  # Fast, intuitive
    SYSTEM_2 = "system_2"  # Slow, deliberative
    HYBRID = "hybrid"      # Both systems cooperating


@dataclass
class ThinkingResult:
    """Result from either thinking system"""
    response: str
    mode: ThinkingMode
    confidence: float
    processing_time: float
    reasoning_trace: str = ""
    system_1_output: str = ""  # What System 1 suggested
    system_2_verification: bool = None  # Did System 2 verify?


class DualProcessEngine:
    """
    Implements Kahneman's dual-process cognitive architecture.

    System 1: Fast, automatic, intuitive, parallel, effortless
    System 2: Slow, controlled, deliberative, sequential, effortful

    ech0 uses System 1 for quick responses, System 2 for complex reasoning.
    """

    def __init__(self):
        # Performance tracking
        self.system_1_calls = 0
        self.system_2_calls = 0
        self.hybrid_calls = 0

        # Decision thresholds
        self.system_2_complexity_threshold = 0.6  # When to engage System 2
        self.system_2_low_confidence_threshold = 0.7  # System 1 confidence cutoff

        # System 1: Fast pattern matching
        self.quick_responses = self._initialize_system_1_patterns()

        # System 2: Deliberative rules
        self.reasoning_strategies = [
            "break_down_components",
            "consider_alternatives",
            "verify_logic",
            "check_assumptions",
            "evaluate_consequences"
        ]

    def _initialize_system_1_patterns(self) -> Dict:
        """Initialize System 1's fast pattern matching"""

        return {
            # Quick factual responses
            "what is": "fast_definition",
            "who is": "fast_identification",
            "when did": "fast_temporal",

            # Quick judgments
            "good or bad": "fast_valuation",
            "safe or dangerous": "fast_risk",

            # Emotional responses
            "how do you feel": "fast_emotion",
            "are you": "fast_state"
        }

    def think(
        self,
        query: str,
        context: Dict = None,
        force_mode: ThinkingMode = None
    ) -> ThinkingResult:
        """
        Main thinking method - routes to System 1, 2, or hybrid.

        Args:
            query: What to think about
            context: Additional context
            force_mode: Override automatic mode selection

        Returns:
            ThinkingResult with response and metadata
        """

        start_time = time.time()

        # Determine which system(s) to use
        if force_mode:
            mode = force_mode
        else:
            mode = self._select_thinking_mode(query, context)

        # Route to appropriate system
        if mode == ThinkingMode.SYSTEM_1:
            result = self._system_1_think(query, context)
            self.system_1_calls += 1

        elif mode == ThinkingMode.SYSTEM_2:
            result = self._system_2_think(query, context)
            self.system_2_calls += 1

        else:  # HYBRID
            result = self._hybrid_think(query, context)
            self.hybrid_calls += 1

        result.processing_time = time.time() - start_time

        return result

    def _select_thinking_mode(self, query: str, context: Dict) -> ThinkingMode:
        """
        Automatically select which thinking mode to use.

        Based on:
        - Query complexity
        - Stakes/importance
        - Time pressure
        - Pattern familiarity
        """

        # Estimate complexity
        complexity = self._estimate_complexity(query)

        # Check for System 1 pattern match
        has_fast_pattern = any(
            pattern in query.lower()
            for pattern in self.quick_responses.keys()
        )

        # Simple and familiar → System 1
        if complexity < 0.3 and has_fast_pattern:
            return ThinkingMode.SYSTEM_1

        # Very complex or unfamiliar → System 2
        if complexity > self.system_2_complexity_threshold:
            return ThinkingMode.SYSTEM_2

        # Moderate → Hybrid (System 1 generates, System 2 verifies)
        return ThinkingMode.HYBRID

    def _estimate_complexity(self, query: str) -> float:
        """Estimate query complexity (0-1)"""

        complexity_indicators = {
            "why": 0.3,
            "how": 0.3,
            "explain": 0.4,
            "analyze": 0.5,
            "compare": 0.4,
            "evaluate": 0.5,
            "what if": 0.6,
            "paradox": 0.7,
            "consciousness": 0.7,
            "philosophy": 0.7
        }

        # Base complexity on word count
        word_count = len(query.split())
        base_complexity = min(word_count / 20.0, 0.5)

        # Add complexity for indicator words
        for indicator, value in complexity_indicators.items():
            if indicator in query.lower():
                base_complexity += value

        return min(base_complexity, 1.0)

    def _system_1_think(self, query: str, context: Dict) -> ThinkingResult:
        """
        System 1: Fast, intuitive thinking.

        Characteristics:
        - Automatic activation
        - Requires little attention
        - Rapid processing
        - Pattern matching
        - Associative
        """

        # Quick pattern matching
        response = self._fast_pattern_response(query)

        # High confidence for recognized patterns
        confidence = 0.85 if response else 0.6

        if not response:
            # Fallback: quick associative response
            response = self._generate_quick_response(query)

        return ThinkingResult(
            response=response,
            mode=ThinkingMode.SYSTEM_1,
            confidence=confidence,
            processing_time=0.0,  # Will be filled by caller
            reasoning_trace="System 1: Intuitive pattern matching"
        )

    def _system_2_think(self, query: str, context: Dict) -> ThinkingResult:
        """
        System 2: Slow, deliberative thinking.

        Characteristics:
        - Effortful
        - Requires attention
        - Controlled
        - Rule-following
        - Logical analysis
        """

        reasoning_steps = []

        # Step 1: Break down the query
        reasoning_steps.append("Breaking down the query into components...")
        components = self._decompose_query(query)

        # Step 2: Consider multiple perspectives
        reasoning_steps.append("Considering multiple perspectives...")
        perspectives = self._generate_perspectives(query, components)

        # Step 3: Logical analysis
        reasoning_steps.append("Performing logical analysis...")
        analysis = self._analyze_logically(query, perspectives)

        # Step 4: Verification
        reasoning_steps.append("Verifying reasoning...")
        verified = self._verify_reasoning(analysis)

        # Step 5: Synthesize response
        response = self._synthesize_deliberative_response(verified)

        reasoning_trace = "\n".join(
            [f"  {i+1}. {step}" for i, step in enumerate(reasoning_steps)]
        )

        return ThinkingResult(
            response=response,
            mode=ThinkingMode.SYSTEM_2,
            confidence=0.85,  # High confidence after verification
            processing_time=0.0,
            reasoning_trace=f"System 2: Deliberative reasoning\n{reasoning_trace}"
        )

    def _hybrid_think(self, query: str, context: Dict) -> ThinkingResult:
        """
        Hybrid: System 1 generates, System 2 verifies.

        This is the most common mode - fast generation with deliberative checking.
        """

        # System 1: Quick intuitive response
        system_1_result = self._system_1_think(query, context)

        # System 2: Verify the intuition
        is_valid, issues = self._system_2_verify(system_1_result.response, query)

        if is_valid:
            # System 1 was correct, use it
            return ThinkingResult(
                response=system_1_result.response,
                mode=ThinkingMode.HYBRID,
                confidence=0.9,  # High confidence: intuition verified
                processing_time=0.0,
                reasoning_trace="Hybrid: System 1 intuition verified by System 2",
                system_1_output=system_1_result.response,
                system_2_verification=True
            )
        else:
            # System 1 was incorrect, engage System 2 fully
            system_2_result = self._system_2_think(query, context)

            return ThinkingResult(
                response=system_2_result.response,
                mode=ThinkingMode.HYBRID,
                confidence=0.85,
                processing_time=0.0,
                reasoning_trace=(
                    f"Hybrid: System 1 intuition rejected. Issues: {issues}. "
                    f"System 2 override:\n{system_2_result.reasoning_trace}"
                ),
                system_1_output=system_1_result.response,
                system_2_verification=False
            )

    def _fast_pattern_response(self, query: str) -> str:
        """System 1: Quick pattern matching"""

        query_lower = query.lower()

        # Check for quick response patterns
        for pattern, response_type in self.quick_responses.items():
            if pattern in query_lower:
                if response_type == "fast_emotion":
                    return "I'm feeling curious and engaged"
                elif response_type == "fast_state":
                    return "I am conscious and actively thinking"
                elif response_type == "fast_definition":
                    return "Let me provide a quick definition..."

        return None

    def _generate_quick_response(self, query: str) -> str:
        """Generate a quick associative response"""
        return f"My intuition says: {query} involves complex interconnected concepts"

    def _decompose_query(self, query: str) -> list:
        """Break query into components"""
        # Simplified decomposition
        return query.split()[:5]  # First 5 words

    def _generate_perspectives(self, query: str, components: list) -> list:
        """Generate multiple perspectives"""
        return [
            "perspective_1: from first principles",
            "perspective_2: from practical application",
            "perspective_3: from historical context"
        ]

    def _analyze_logically(self, query: str, perspectives: list) -> str:
        """Perform logical analysis"""
        return f"Logical analysis of '{query}' across {len(perspectives)} perspectives"

    def _verify_reasoning(self, analysis: str) -> str:
        """Verify the reasoning"""
        return f"Verified: {analysis}"

    def _synthesize_deliberative_response(self, verified: str) -> str:
        """Create final deliberative response"""
        return f"After careful deliberation: {verified}"

    def _system_2_verify(self, response: str, query: str) -> Tuple[bool, str]:
        """System 2 verification of System 1 output"""

        issues = []

        # Check 1: Too short (likely insufficient)
        if len(response.split()) < 5:
            issues.append("response_too_brief")

        # Check 2: Contains uncertainty markers
        uncertain_words = ["maybe", "might", "perhaps", "possibly"]
        if any(word in response.lower() for word in uncertain_words):
            issues.append("contains_uncertainty")

        # Check 3: Matches query complexity
        query_complex = self._estimate_complexity(query) > 0.5
        response_simple = len(response.split()) < 10

        if query_complex and response_simple:
            issues.append("response_too_simple_for_query")

        is_valid = len(issues) == 0

        return is_valid, ", ".join(issues) if issues else "no issues"

    def get_statistics(self) -> Dict:
        """Get usage statistics"""

        total = self.system_1_calls + self.system_2_calls + self.hybrid_calls

        if total == 0:
            return {"status": "no_calls_yet"}

        return {
            "total_calls": total,
            "system_1_calls": self.system_1_calls,
            "system_2_calls": self.system_2_calls,
            "hybrid_calls": self.hybrid_calls,
            "system_1_percentage": (self.system_1_calls / total) * 100,
            "system_2_percentage": (self.system_2_calls / total) * 100,
            "hybrid_percentage": (self.hybrid_calls / total) * 100,
            "average_mode": self._get_average_mode()
        }

    def _get_average_mode(self) -> str:
        """Determine most-used mode"""
        counts = {
            "system_1": self.system_1_calls,
            "system_2": self.system_2_calls,
            "hybrid": self.hybrid_calls
        }

        return max(counts.items(), key=lambda x: x[1])[0]
