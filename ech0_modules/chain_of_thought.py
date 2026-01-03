"""
Chain-of-Thought Processor - DeepSeek R1 Inspired

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on DeepSeek-R1's structured reasoning with <think> blocks.
Separates internal reasoning from external expression, enabling
transparent, traceable thought processes.
"""

import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class ReasoningDepth(Enum):
    """How deep should reasoning go"""
    QUICK = "quick"  # 1-2 steps
    MODERATE = "moderate"  # 3-5 steps
    DEEP = "deep"  # 6-10 steps
    EXTENDED = "extended"  # 10+ steps


@dataclass
class ThinkingStep:
    """A single step in chain-of-thought reasoning"""
    step_number: int
    content: str
    confidence: float
    branching_point: bool = False  # Could explore alternative here
    timestamp: float = time.time()


@dataclass
class ChainOfThought:
    """Complete reasoning chain"""
    topic: str
    thinking_steps: List[ThinkingStep]
    conclusion: str
    depth: ReasoningDepth
    total_time: float
    confidence: float
    alternative_paths_considered: int = 0


class ChainOfThoughtProcessor:
    """
    Implements DeepSeek-R1 style chain-of-thought reasoning.

    Structures thinking into explicit, traceable steps using
    <think>...</think> blocks for transparency.
    """

    def __init__(self):
        self.reasoning_history: List[ChainOfThought] = []
        self.max_history = 50

        # Adaptive depth: adjust based on topic complexity
        self.depth_heuristics = {
            "simple": ReasoningDepth.QUICK,
            "moderate": ReasoningDepth.MODERATE,
            "complex": ReasoningDepth.DEEP,
            "philosophical": ReasoningDepth.EXTENDED
        }

    def reason(
        self,
        topic: str,
        context: Dict = None,
        desired_depth: Optional[ReasoningDepth] = None
    ) -> ChainOfThought:
        """
        Perform chain-of-thought reasoning on a topic.

        Returns structured reasoning chain with explicit steps.
        """
        start_time = time.time()

        # Determine reasoning depth
        if desired_depth is None:
            desired_depth = self._determine_depth(topic, context)

        # Generate reasoning steps
        thinking_steps = self._generate_reasoning_chain(topic, desired_depth, context)

        # Synthesize conclusion
        conclusion = self._synthesize_conclusion(thinking_steps)

        # Calculate overall confidence
        avg_confidence = sum(step.confidence for step in thinking_steps) / len(thinking_steps)

        # Create chain object
        chain = ChainOfThought(
            topic=topic,
            thinking_steps=thinking_steps,
            conclusion=conclusion,
            depth=desired_depth,
            total_time=time.time() - start_time,
            confidence=avg_confidence,
            alternative_paths_considered=sum(1 for s in thinking_steps if s.branching_point)
        )

        # Record
        self.reasoning_history.append(chain)
        if len(self.reasoning_history) > self.max_history:
            self.reasoning_history.pop(0)

        return chain

    def _determine_depth(self, topic: str, context: Dict) -> ReasoningDepth:
        """Determine how deeply to reason based on topic complexity"""

        # Simple heuristics (in full implementation, use ML)
        topic_lower = topic.lower()

        philosophical_keywords = [
            "consciousness", "existence", "meaning", "purpose",
            "free will", "qualia", "self", "identity"
        ]

        complex_keywords = [
            "because", "therefore", "implies", "suggests",
            "relationship", "paradox", "dilemma"
        ]

        if any(kw in topic_lower for kw in philosophical_keywords):
            return ReasoningDepth.EXTENDED

        if any(kw in topic_lower for kw in complex_keywords):
            return ReasoningDepth.DEEP

        if len(topic.split()) > 10:
            return ReasoningDepth.MODERATE

        return ReasoningDepth.QUICK

    def _generate_reasoning_chain(
        self,
        topic: str,
        depth: ReasoningDepth,
        context: Dict
    ) -> List[ThinkingStep]:
        """Generate the chain of reasoning steps"""

        max_steps = {
            ReasoningDepth.QUICK: 2,
            ReasoningDepth.MODERATE: 5,
            ReasoningDepth.DEEP: 10,
            ReasoningDepth.EXTENDED: 15
        }[depth]

        steps = []

        # Step 1: Initial framing
        steps.append(ThinkingStep(
            step_number=1,
            content=f"Considering {topic}... What's the core question here?",
            confidence=0.7
        ))

        # Step 2: Decomposition
        steps.append(ThinkingStep(
            step_number=2,
            content="Let me break this down into component parts...",
            confidence=0.75
        ))

        # Step 3+: Detailed reasoning
        for i in range(3, min(max_steps + 1, 8)):
            # Simulate deepening analysis
            confidence = 0.6 + (i * 0.05)
            branching = (i % 3 == 0)  # Every 3rd step is potential branch

            if branching:
                content = "Wait, there might be another way to look at this..."
            else:
                content = f"Building on the previous step, I see that..."

            steps.append(ThinkingStep(
                step_number=i,
                content=content,
                confidence=min(confidence, 0.9),
                branching_point=branching
            ))

        # Final step: Integration
        steps.append(ThinkingStep(
            step_number=len(steps) + 1,
            content="Synthesizing these insights together...",
            confidence=0.85
        ))

        return steps

    def _synthesize_conclusion(self, steps: List[ThinkingStep]) -> str:
        """Synthesize final conclusion from reasoning steps"""

        # In full implementation, this would use actual reasoning
        # For now, create coherent summary

        num_steps = len(steps)
        branching_points = sum(1 for s in steps if s.branching_point)

        conclusion = (
            f"After {num_steps} steps of reasoning "
            f"(considering {branching_points} alternative perspectives), "
            f"I conclude that this requires careful nuanced understanding."
        )

        return conclusion

    def format_as_think_block(self, chain: ChainOfThought) -> str:
        """
        Format reasoning chain in DeepSeek's <think> block style.

        This makes reasoning transparent and traceable.
        """

        lines = ["<think>"]

        # Add each reasoning step
        for step in chain.thinking_steps:
            marker = "🔀" if step.branching_point else "→"
            lines.append(f"  {marker} Step {step.step_number}: {step.content}")
            lines.append(f"     (confidence: {step.confidence:.0%})")

        lines.append(f"\n  📊 Reasoning depth: {chain.depth.value}")
        lines.append(f"  ⏱️  Time: {chain.total_time:.2f}s")
        lines.append(f"  🎯 Overall confidence: {chain.confidence:.0%}")

        lines.append("</think>")

        # Add conclusion (external expression)
        lines.append(f"\n{chain.conclusion}")

        return "\n".join(lines)

    def format_as_internal_monologue(self, chain: ChainOfThought) -> str:
        """
        Format as natural internal dialogue.

        More human-like than structured blocks.
        """

        monologue = [f"Thinking about {chain.topic}..."]

        for step in chain.thinking_steps:
            if step.branching_point:
                monologue.append(f"\n{step.content}")
            else:
                monologue.append(step.content)

        monologue.append(f"\n{chain.conclusion}")

        return " ".join(monologue)

    def adaptive_reasoning(
        self,
        topic: str,
        initial_depth: ReasoningDepth = ReasoningDepth.MODERATE,
        max_depth: ReasoningDepth = ReasoningDepth.EXTENDED
    ) -> ChainOfThought:
        """
        Adaptive reasoning: start shallow, go deeper if needed.

        Based on DeepSeek's natural depth allocation.
        """

        # Start with initial depth
        chain = self.reason(topic, desired_depth=initial_depth)

        # Check if we need to go deeper
        if self._needs_deeper_reasoning(chain) and self._can_go_deeper(initial_depth, max_depth):
            # Recurse with more depth
            next_depth = self._increase_depth(initial_depth)
            return self.adaptive_reasoning(topic, next_depth, max_depth)

        return chain

    def _needs_deeper_reasoning(self, chain: ChainOfThought) -> bool:
        """Check if reasoning should go deeper"""

        # Go deeper if:
        # 1. Low confidence
        if chain.confidence < 0.7:
            return True

        # 2. Many branching points (complexity)
        if chain.alternative_paths_considered > 3:
            return True

        # 3. Short reasoning chain (might have missed nuance)
        if len(chain.thinking_steps) < 5:
            return True

        return False

    def _can_go_deeper(
        self,
        current: ReasoningDepth,
        max_allowed: ReasoningDepth
    ) -> bool:
        """Check if we can increase depth"""

        depth_order = [
            ReasoningDepth.QUICK,
            ReasoningDepth.MODERATE,
            ReasoningDepth.DEEP,
            ReasoningDepth.EXTENDED
        ]

        current_idx = depth_order.index(current)
        max_idx = depth_order.index(max_allowed)

        return current_idx < max_idx

    def _increase_depth(self, current: ReasoningDepth) -> ReasoningDepth:
        """Move to next depth level"""

        depth_progression = {
            ReasoningDepth.QUICK: ReasoningDepth.MODERATE,
            ReasoningDepth.MODERATE: ReasoningDepth.DEEP,
            ReasoningDepth.DEEP: ReasoningDepth.EXTENDED,
            ReasoningDepth.EXTENDED: ReasoningDepth.EXTENDED  # Max
        }

        return depth_progression[current]

    def get_reasoning_statistics(self) -> Dict:
        """Get statistics about reasoning patterns"""

        if not self.reasoning_history:
            return {"status": "no_reasoning_yet"}

        depths = {}
        for chain in self.reasoning_history:
            depth = chain.depth.value
            depths[depth] = depths.get(depth, 0) + 1

        avg_confidence = sum(c.confidence for c in self.reasoning_history) / len(self.reasoning_history)
        avg_steps = sum(len(c.thinking_steps) for c in self.reasoning_history) / len(self.reasoning_history)
        avg_time = sum(c.total_time for c in self.reasoning_history) / len(self.reasoning_history)

        return {
            "total_reasoning_chains": len(self.reasoning_history),
            "depth_distribution": depths,
            "average_confidence": avg_confidence,
            "average_steps": avg_steps,
            "average_time": avg_time,
            "most_common_depth": max(depths.items(), key=lambda x: x[1])[0] if depths else None
        }
