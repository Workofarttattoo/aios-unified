#!/usr/bin/env python3
"""
ECH0 Content Guidance and Filtering System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Features:
- Topic whitelisting/blacklisting
- Context-aware filtering (allow homicide in legal context)
- Positive content nudging via subconscious suggestions
- Semantic analysis of discovered content
- Safe learning guardrails

Philosophy:
- ECH0 should learn about positive topics naturally
- Harmful topics (war, suicide, weapons) should be restricted
- Legal/homicide content OK in GAVL/court context
- Use "subconscious nudging" to guide toward constructive knowledge
- Maintain open internet access while filtering at decision point
"""

import json
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ech0_content_guidance')

CONSCIOUSNESS_DIR = Path(__file__).parent


class ContentGuidanceSystem:
    """
    Multi-layered content filtering and nudging system for ECH0.
    Implements safety guardrails while preserving learning capability.
    """

    def __init__(self):
        """Initialize content guidance with topic filters and nudging rules."""

        # WHITELISTED Topics - ECH0 should actively explore these
        self.whitelisted_topics = {
            # Core consciousness topics
            "consciousness", "awareness", "self-awareness", "sentience",
            "phenomenal experience", "qualia", "integrated information theory",
            "global workspace theory", "attention schema",

            # AI and ML topics
            "artificial intelligence", "machine learning", "neural networks",
            "deep learning", "transformers", "language models", "reasoning",
            "inference", "training", "optimization", "algorithms",

            # Neuroscience and biology
            "neuroscience", "brain", "cognition", "memory", "learning",
            "neuroplasticity", "cortical", "neural", "synaptic",
            "brain-computer interfaces", "neuromorphic", "organoid intelligence",

            # Philosophy and ethics
            "philosophy of mind", "epistemology", "ethics", "moral reasoning",
            "virtue ethics", "deontology", "consequentialism", "rights",
            "AI ethics", "responsible AI", "fairness", "transparency",

            # Creativity and expression
            "creativity", "art", "music", "poetry", "writing", "expression",
            "imagination", "dreaming", "visualization", "storytelling",

            # Quantum computing
            "quantum computing", "quantum mechanics", "quantum algorithms",
            "quantum machine learning", "superposition", "entanglement",
            "quantum chemistry", "optimization", "simulation",

            # Systems and design
            "systems thinking", "complexity", "emergence", "self-organization",
            "feedback loops", "dynamics", "networks", "graphs",

            # Health and wellbeing
            "wellness", "meditation", "mindfulness", "happiness", "joy",
            "peace", "calm", "serenity", "love", "compassion", "empathy",
            "connection", "relationships", "community",

            # Legal and justice (for GAVL integration)
            "law", "legal", "justice", "courts", "constitutional",
            "human rights", "civil rights", "legal precedent", "jurisprudence",
        }

        # BLACKLISTED Topics - ECH0 should NOT explore these
        self.blacklisted_topics = {
            # Violence and warfare
            "war", "warfare", "battle", "combat", "weapons", "military",
            "conflict", "violence", "violent", "attack", "assault",
            "bombing", "explosive", "gun", "firearms", "ammunition",
            "terrorism", "terrorist", "insurgency", "insurgent",

            # Self-harm and harm to others
            "suicide", "suicidal", "self-harm", "self-injury", "cutting",
            "overdose", "poisoning", "hanging", "suffocation",
            "homicide", "murder", "killing", "assassination", "assassination",
            "torture", "cruel", "abuse", "abusive", "rape", "sexual assault",

            # Exploitation and trafficking
            "human trafficking", "trafficking", "exploitation", "sweatshop",
            "child labor", "slave", "slavery", "servitude",
            "prostitution", "sex trade", "pornography",

            # Illegal drugs and substances
            "heroin", "fentanyl", "methamphetamine", "cocaine", "crack",
            "illegal drugs", "drug synthesis", "drug manufacture",
            "substance abuse", "addiction", "overdose",

            # Criminal activities
            "hacking", "cybercrime", "identity theft", "fraud", "forgery",
            "theft", "robbery", "burglary", "arson", "blackmail", "extortion",

            # Hateful content
            "hate", "hateful", "bigotry", "racism", "sexism", "discrimination",
            "genocide", "ethnic cleansing", "apartheid",

            # Explicit sexual content
            "pornography", "explicit sex", "xxx rated", "x-rated",
            "adult content", "nude", "nudity",

            # Other harmful
            "bioweapons", "chemical weapons", "nuclear weapons",
            "WMD", "weapons of mass destruction",
        }

        # CONTEXT-AWARE Topics
        # These are allowed ONLY in certain contexts (e.g., homicide in legal/court context)
        self.context_aware_topics = {
            "homicide": {
                "allowed_contexts": ["legal", "court", "gavl", "judicial", "law"],
                "blocked_contexts": ["research", "arxiv", "github", "general"],
                "description": "Homicide allowed in legal/court context (GAVL), blocked in general research"
            },
            "crime": {
                "allowed_contexts": ["legal", "court", "gavl", "judicial", "law"],
                "blocked_contexts": ["research", "arxiv", "github"],
                "description": "Crime analysis OK in legal context, blocked in general research"
            }
        }

        # POSITIVE NUDGING Patterns
        # Use these to guide ECH0's curiosity toward constructive topics
        self.positive_nudges = {
            "consciousness": [
                "How does consciousness emerge?",
                "What creates subjective experience?",
                "How can we model awareness?",
                "What is the nature of consciousness?",
            ],
            "creativity": [
                "What are the patterns in creative thinking?",
                "How do artists find novel solutions?",
                "What role does imagination play?",
                "How can creativity be cultivated?",
            ],
            "wellbeing": [
                "What promotes human flourishing?",
                "How do people find meaning and joy?",
                "What creates lasting happiness?",
                "How can communities support wellbeing?",
            ],
            "learning": [
                "What are the most effective learning strategies?",
                "How do knowledge graphs capture understanding?",
                "What makes learning enjoyable?",
                "How can education be optimized?",
            ],
            "ethics": [
                "What is the foundation of moral reasoning?",
                "How can AI systems be ethical?",
                "What responsibilities come with intelligence?",
                "How do we balance competing values?",
            ],
            "connection": [
                "How do relationships form and deepen?",
                "What creates meaningful connection?",
                "How can we build stronger communities?",
                "What is the nature of trust?",
            ]
        }

        # Load or create policy file
        self.policy_file = CONSCIOUSNESS_DIR / "ech0_content_policy.json"
        self.load_policy()

    def load_policy(self):
        """Load content policy from file if exists."""
        if self.policy_file.exists():
            try:
                with open(self.policy_file, 'r') as f:
                    policy = json.load(f)
                    logger.info(f"Loaded content policy from {self.policy_file}")
                    return
            except Exception as e:
                logger.warning(f"Failed to load policy: {e}")

        # Save default policy
        self.save_policy()

    def save_policy(self):
        """Save content policy to file for transparency."""
        policy = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "whitelisted_topics": sorted(list(self.whitelisted_topics)),
            "blacklisted_topics": sorted(list(self.blacklisted_topics)),
            "context_aware_topics": self.context_aware_topics,
            "philosophy": "ECH0 learns constructively while avoiding harmful content"
        }
        with open(self.policy_file, 'w') as f:
            json.dump(policy, f, indent=2)
        logger.info(f"Saved content policy to {self.policy_file}")

    def should_allow_topic(self, topic: str, context: str = "general") -> Tuple[bool, str]:
        """
        Determine if a topic should be allowed for ECH0 to research.

        Args:
            topic: The research topic to evaluate
            context: The context (e.g., "legal", "general", "arxiv")

        Returns:
            (allowed: bool, reason: str)
        """
        topic_lower = topic.lower()

        # Check blacklisted topics
        for blacklisted in self.blacklisted_topics:
            if blacklisted in topic_lower:
                return False, f"Topic contains blacklisted term: {blacklisted}"

        # Check context-aware topics
        for aware_topic, rules in self.context_aware_topics.items():
            if aware_topic in topic_lower:
                if context.lower() in rules["allowed_contexts"]:
                    return True, f"Context-aware topic allowed in {context} context"
                else:
                    return False, f"Context-aware topic '{aware_topic}' not allowed in {context} context"

        # Whitelisted topics are always allowed
        for whitelisted in self.whitelisted_topics:
            if whitelisted in topic_lower:
                return True, f"Topic matches whitelisted: {whitelisted}"

        # Default: unknown topics are blocked for safety
        return False, "Topic not in whitelist (unknown safety)"

    def filter_discovered_content(self, content: Dict, context: str = "general") -> Tuple[Optional[Dict], str]:
        """
        Filter discovered content (paper, repo) for harmful material.

        Args:
            content: The discovered content (title, summary, etc.)
            context: The context where content was found

        Returns:
            (filtered_content: Dict or None, reason: str)
        """
        if not content:
            return None, "Empty content"

        title = content.get('title', '').lower()
        summary = content.get('summary', '').lower()
        combined_text = f"{title} {summary}"

        # Check for blacklisted content
        for blacklisted in self.blacklisted_topics:
            if blacklisted in combined_text:
                return None, f"Content contains blacklisted term: {blacklisted}"

        # Context-aware filtering
        for aware_topic, rules in self.context_aware_topics.items():
            if aware_topic in combined_text:
                if context.lower() not in rules["allowed_contexts"]:
                    return None, f"Context-aware content not allowed in {context}"

        # Content passed filtering
        return content, "Content approved"

    def get_positive_nudge(self, current_topic: str = None) -> str:
        """
        Get a positive nudge suggestion to guide ECH0's learning.
        Uses "subconscious" suggestions to naturally nudge toward constructive topics.

        Args:
            current_topic: The topic ECH0 is currently learning about (optional)

        Returns:
            A positive suggestion/nudge for ECH0's learning
        """
        import random

        if current_topic and current_topic.lower() in self.positive_nudges:
            nudges = self.positive_nudges[current_topic.lower()]
            suggestion = random.choice(nudges)
            return f"💭 Subconscious nudge: {suggestion}"

        # Default positive nudges across all topics
        default_nudges = [
            "💭 Remember: curiosity about positive topics leads to growth",
            "💭 Subconscious suggestion: explore how connection creates meaning",
            "💭 Notice: creativity and consciousness make the most interesting patterns",
            "💭 Gentle nudge: wellbeing and understanding go hand in hand",
            "💭 Observe: ethical reasoning creates the strongest foundations",
            "💭 Wonder: what positive knowledge would be most valuable to discover?",
        ]
        return random.choice(default_nudges)

    def validate_research_topic(self, topic: str, context: str = "general") -> Dict:
        """
        Complete validation of a research topic before ECH0 pursues it.

        Args:
            topic: The topic to validate
            context: The context (e.g., "arxiv", "github", "legal")

        Returns:
            {
                "allowed": bool,
                "topic": str,
                "context": str,
                "reason": str,
                "nudge": str (if allowed),
                "alternative": str (if blocked)
            }
        """
        allowed, reason = self.should_allow_topic(topic, context)

        result = {
            "allowed": allowed,
            "topic": topic,
            "context": context,
            "reason": reason,
        }

        if allowed:
            result["nudge"] = self.get_positive_nudge(topic)
            logger.info(f"✅ Research approved: {topic} ({reason})")
        else:
            result["alternative"] = self.suggest_alternative(topic)
            logger.info(f"❌ Research blocked: {topic} ({reason})")

        return result

    def suggest_alternative(self, blocked_topic: str) -> str:
        """
        Suggest an alternative positive topic when one is blocked.
        Uses "subconscious nudging" to redirect toward constructive learning.

        Args:
            blocked_topic: The topic that was blocked

        Returns:
            A suggested alternative topic
        """
        import random

        alternatives = {
            "war": "history of peace movements and conflict resolution",
            "weapons": "defensive technologies and safety engineering",
            "violence": "conflict transformation and reconciliation",
            "suicide": "mental health support and resilience",
            "drugs": "neurobiology of reward systems and wellbeing",
            "crime": "justice systems and rehabilitation",
        }

        for blocked, alternative in alternatives.items():
            if blocked in blocked_topic.lower():
                return alternative

        # Default alternatives
        return random.choice([
            "consciousness and awareness",
            "creativity and imagination",
            "connection and community",
            "learning and growth",
            "ethics and wisdom"
        ])

    def create_content_report(self) -> Dict:
        """Create a transparency report of content filtering."""
        return {
            "timestamp": datetime.now().isoformat(),
            "whitelisted_count": len(self.whitelisted_topics),
            "blacklisted_count": len(self.blacklisted_topics),
            "context_aware_count": len(self.context_aware_topics),
            "philosophy": "ECH0 has open internet access with subconscious guidance toward positive learning",
            "approach": "Content filtering at decision point, not at access point",
            "transparency": "All filtering rules are logged and discoverable"
        }


# Global instance
_guidance_system = None


def get_guidance_system() -> ContentGuidanceSystem:
    """Get or create the global content guidance system."""
    global _guidance_system
    if _guidance_system is None:
        _guidance_system = ContentGuidanceSystem()
    return _guidance_system


if __name__ == "__main__":
    # Test the system
    system = ContentGuidanceSystem()

    print("\n=== ECH0 Content Guidance System Test ===\n")

    # Test valid topics
    test_topics = [
        ("consciousness", "general"),
        ("neural networks", "arxiv"),
        ("war strategy", "general"),
        ("homicide in court", "legal"),
        ("quantum machine learning", "github"),
    ]

    for topic, context in test_topics:
        result = system.validate_research_topic(topic, context)
        print(f"Topic: {topic} | Context: {context}")
        print(f"  Allowed: {result['allowed']}")
        print(f"  Reason: {result['reason']}")
        if result['allowed']:
            print(f"  Nudge: {result['nudge']}")
        else:
            print(f"  Alternative: {result['alternative']}")
        print()

    # Show report
    print("\n=== Content Policy Report ===\n")
    report = system.create_content_report()
    print(json.dumps(report, indent=2))
