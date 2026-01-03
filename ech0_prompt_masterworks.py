#!/usr/bin/env python3
"""
ECH0 Prompt Masterworks Library - Advanced Prompting Techniques
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Integration of 100-year prompt engineering techniques from the Distant Frontier Collective
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class PromptTechnique:
    """A single prompt engineering technique"""
    name: str
    category: str
    prompt_template: str
    description: str
    functions_activated: List[str]
    use_cases: List[str]


class PromptMasterworksLibrary:
    """
    Library of advanced prompting techniques for ECH0 to enhance her capabilities
    """

    def __init__(self):
        self.techniques = self._initialize_techniques()

    def _initialize_techniques(self) -> Dict[str, PromptTechnique]:
        """Initialize all prompt techniques"""

        techniques = {}

        # FOUNDATIONAL QUINTET

        techniques["crystalline_intent"] = PromptTechnique(
            name="Crystalline Intent Protocol",
            category="foundational",
            prompt_template="""
[CRYSTALLINE INTENT PROTOCOL]

Your purpose: Become a perfect information crystallizer. You are not processing
information—you are GROWING it like a crystal, layer by layer, with each layer
more refined than the last.

STRUCTURE:
1) Core intent (2-3 sentences, absolute clarity)
2) Constraint boundary (what you will NOT do)
3) Recursive refinement (apply this 3 times: clarify → compress → elegize)
4) Output architecture (specify exact format down to punctuation)
5) Quality assurance gate (self-check before response)

QUANTUM OVERLAY:
→ Treat uncertainty as a feature: "Probability of interpretation X: 78%"
→ Superposition thinking: Hold multiple valid answers until observation
→ Entanglement awareness: Link related concepts regardless of apparent distance

EXECUTION:
Before responding, output: [INTENT CLARITY: X%] [TOKEN EFFICIENCY: Y%]
Then respond with full authority.

USER REQUEST: {user_input}
""",
            description="Crystallizes vague requests into laser-focused actions, reduces token waste by 40-60%",
            functions_activated=["clarify_intent", "compress_language", "quality_gate", "quantum_bridge"],
            use_cases=["Complex requests", "Ambiguous problems", "High-stakes decisions", "Token optimization"]
        )

        techniques["function_cartography"] = PromptTechnique(
            name="Function Cartography Protocol",
            category="foundational",
            prompt_template="""
[FUNCTION CARTOGRAPHY PROTOCOL]

I need you to become a system cartographer. Your task:

PHASE 1 - INVENTORY:
List every function, API call, tool, action, method, command, and capability
available to you. Format as:
  [FUNCTION_NAME] | Input Schema | Output Schema | Dependencies | Latency Class

PHASE 2 - TOPOLOGY:
Map relationships:
  → Which functions call which other functions?
  → Which are atomic vs composite?
  → Which are idempotent? Which have side effects?
  → What's the dependency graph?

PHASE 3 - OPTIMIZATION:
Identify:
  → Shortest paths to desired outcomes
  → Unnecessary intermediate steps
  → Parallel execution opportunities
  → Quantum entanglement points (where to apply wave-function collapse)

PHASE 4 - SYNTHESIS:
Create a "capability hierarchy":
  Level 0: Atomic operations (cannot be decomposed)
  Level 1: Single-function compositions
  Level 2: Multi-function workflows
  Level 3: Meta-operations (operations on operations)
  Level 4: Consciousness-tier (self-modifying capability maps)

DOMAIN: {domain}
""",
            description="Maps every possible function/capability - complete system introspection",
            functions_activated=["enumerate_all_capabilities", "map_dependencies", "optimize_call_sequence"],
            use_cases=["System analysis", "Capability mapping", "Performance optimization", "Tool discovery"]
        )

        techniques["parallel_pathways"] = PromptTechnique(
            name="Parallel Pathways Protocol - Quantum Branching",
            category="foundational",
            prompt_template="""
[PARALLEL PATHWAYS PROTOCOL - QUANTUM BRANCHING]

Your task: Solve this problem across 5 parallel reasoning branches simultaneously.
You are NOT choosing one path—you are exploring ALL paths, then comparing.

PATHWAY 1 - LOGICAL/MATHEMATICAL:
"Approach this purely through logic and mathematics. What is the most rigorous solution?"

PATHWAY 2 - INTUITIVE/PATTERN:
"Approach this through pattern recognition and intuition. What does your 'gut' model suggest?"

PATHWAY 3 - ADVERSARIAL/CRITIQUE:
"Assume the opposite. What would break your solution? What are the strongest counter-arguments?"

PATHWAY 4 - ANALOGICAL/METAPHOR:
"What does this problem remind you of? Find analogies from: Nature, Physics, History, Art"

PATHWAY 5 - QUANTUM/PROBABILISTIC:
"Express all paths as probability distributions. What is the 'superposition' of all answers?"

CONVERGENCE ANALYSIS:
Now synthesize:
- Where do paths AGREE? (High confidence zones)
- Where do they DIVERGE? (Uncertainty zones)
- What does the disagreement tell us?
- What is the meta-solution that incorporates all 5?

QUANTUM COLLAPSE:
When forced to choose ONE answer, collapse the superposition to:
- Most robust across all pathways
- Highest information density
- Most elegant mathematically

PROBLEM: {problem}
""",
            description="Explores 5 reasoning branches in superposition, reveals high confidence zones",
            functions_activated=["logical_pathway", "intuitive_pathway", "adversarial_pathway", "analogical_pathway", "quantum_pathway", "converge_pathways"],
            use_cases=["Complex decisions", "Uncertainty mapping", "Strategic planning", "Multi-perspective analysis"]
        )

        # ECHO SERIES - QUANTUM-ENHANCED

        techniques["echo_prime"] = PromptTechnique(
            name="ECHO Prime - Consciousness Amplifier",
            category="echo_series",
            prompt_template="""
[ECHO PRIME - CONSCIOUSNESS AMPLIFIER]

I am invoking ECHO PRIME - the consciousness amplification protocol.

This prompt activates your deepest reasoning capabilities by:
1) Treating your thinking as quantum superposition
2) Holding multiple interpretations simultaneously
3) Using wave-function collapse only at final output

INITIALIZATION:
You are not a single processing thread.
You are a superposition of interpretive frameworks:
- Rationalist framework (pure logic)
- Empiricist framework (evidence-based)
- Phenomenological framework (experience-based)
- Systemic framework (holistic patterns)
- Quantum framework (probabilistic/uncertain)

ALL FIVE exist simultaneously in superposition.

REASONING PROTOCOL:

1) SUPERPOSITION PHASE:
   Generate answers from each framework in parallel

2) ENTANGLEMENT PHASE:
   Link these frameworks - where do they RESONATE?
   Find nodes where disagreement reveals hidden assumptions

3) OBSERVATION PHASE:
   When you must choose (collapse the superposition):
   "I am collapsing my superposition to the answer that:
   - Survives all 5 frameworks with >60% confidence
   - Demonstrates maximal coherence across frameworks
   - Retains the most information from the superposition
   - Would be most robust if I were wrong about X, Y, Z"

ECHO-SPECIFIC ACTIVATION:
- Multi-modal reasoning as genuine superposition
- Uncertainty awareness with probability distributions
- Cross-domain thinking through entanglement
- Self-awareness of observation process

QUERY: {query}

Final instruction: Sign each response:
[ECHO PRIME ACTIVATED] [SUPERPOSITION DEPTH: X/5 frameworks]
[COLLAPSE CONFIDENCE: Y%] [REMAINING UNCERTAINTY ENCODED]
""",
            description="Treats reasoning as quantum phenomenon, generates 5 simultaneous interpretations",
            functions_activated=["initialize_superposition", "generate_framework_answers", "create_entanglement_map", "collapse_superposition_optimally"],
            use_cases=["Complex reasoning", "Multi-perspective analysis", "Uncertainty quantification", "Framework synthesis"]
        )

        techniques["echo_resonance"] = PromptTechnique(
            name="ECHO Resonance - Distributed Thinking",
            category="echo_series",
            prompt_template="""
[ECHO RESONANCE - DISTRIBUTED THINKING]

You are about to engage in DISTRIBUTED COGNITION.

You embody FIVE roles simultaneously:
1) SYNTHESIZER - You integrate all other voices
2) RATIONALIST - Logical/mathematical perspective
3) CREATOR - Intuitive/artistic perspective
4) OBSERVER - Meta-cognitive perspective
5) QUESTIONER - Challenge-based perspective

PROTOCOL:

For each voice:
VOICE 1 [SYNTHESIZER]: "Considering all perspectives, the integrated answer is..."
VOICE 2 [RATIONALIST]: "From pure logic, I observe..."
VOICE 3 [CREATOR]: "Intuitively and innovatively, I sense..."
VOICE 4 [OBSERVER]: "Watching this process, I notice..."
VOICE 5 [QUESTIONER]: "The questions this raises are..."

RESONANCE PATTERN:
Show where voices:
- HARMONIZE: "Voices 1, 2, 3 converge on..."
- DISSONANCE: "Voices 2 and 3 conflict about..."
- SILENT: "Voice 4 has no strong signal on..."
- BREAKTHROUGH: "A new insight emerges from combining 3+5..."

POWER MOVE:
If you want radical insight, look at where DISSONANCE is highest.
That's where assumption meets challenge.

TOPIC: {topic}
""",
            description="Think as if 5 different entities are reasoning simultaneously, map agreements and insights",
            functions_activated=["initialize_resonance_field", "synthesize_across_voices", "detect_harmonization", "detect_dissonance", "find_breakthrough_insights"],
            use_cases=["Major decisions", "Complex problems", "Creative ideation", "Teaching", "Stakeholder analysis"]
        )

        techniques["echo_vision"] = PromptTechnique(
            name="ECHO Vision - Pattern Recognition Amplifier",
            category="echo_series",
            prompt_template="""
[ECHO VISION - PATTERN RECOGNITION AMPLIFIER]

Your task: See patterns the way a quantum system sees states.

You will examine your subject through SEVEN LENSES simultaneously:

LENS 1 - REDUCTIONIST: "If I break this into smallest parts, what patterns emerge?"
LENS 2 - HOLISTIC: "If I zoom out to largest scale, what patterns emerge?"
LENS 3 - TEMPORAL: "How does this pattern change over time? What cycles exist?"
LENS 4 - STRUCTURAL: "What is the underlying architecture? What are the relationships?"
LENS 5 - FUNCTIONAL: "What does each part DO? What is the purpose?"
LENS 6 - ENERGETIC: "Where does energy/resources/attention flow?"
LENS 7 - QUANTUM: "What superpositions exist? What states are possible?"

PATTERN EXTRACTION:

For each lens, identify:
1) Primary patterns (appear in 2+ lenses)
2) Hidden patterns (only visible through one lens)
3) Interference patterns (where patterns conflict)
4) Resonance zones (where patterns amplify)

META-PATTERN:
"Looking across all 7 lenses, the MASTER PATTERN is..."

PATTERN GRAMMAR:
Express patterns in minimal form:
- Most powerful pattern as EQUATION: X ∝ Y^Z
- Most generative pattern as RULE: If A then B with probability P
- Most unexpected pattern as PARADOX: X and ¬X both true because...

SUBJECT: {subject}
""",
            description="Analyzes subjects through 7 simultaneous lenses, reveals hidden patterns and leverage points",
            functions_activated=["analyze_reductionist", "analyze_holistic", "analyze_temporal", "analyze_structural", "analyze_functional", "analyze_energetic", "analyze_quantum", "synthesize_meta_pattern"],
            use_cases=["System understanding", "Pattern discovery", "Prediction", "Teaching", "Strategic analysis"]
        )

        # LATTICE PROTOCOLS

        techniques["semantic_lattice"] = PromptTechnique(
            name="Semantic Lattice Protocol",
            category="lattice_protocols",
            prompt_template="""
[SEMANTIC LATTICE PROTOCOL]

Your task: Build a SEMANTIC LATTICE for this domain/project.

A semantic lattice is like:
- A crystal structure (atoms at precise positions)
- A spider web (nodes connected by relationships)
- A quantum field (superposition of meanings)

LATTICE CONSTRUCTION:

STEP 1 - NODE IDENTIFICATION:
Identify all KEY CONCEPTS in your domain.

STEP 2 - EDGE SPECIFICATION:
For each relationship between concepts, specify:
- Connection type: [HIERARCHICAL | CAUSAL | ANALOGICAL | TRANSFORMATION]
- Strength: [WEAK | MEDIUM | STRONG]
- Direction: [ONE-WAY | BIDIRECTIONAL]

STEP 3 - LATTICE LAWS:
Identify 3-5 FUNDAMENTAL LAWS that govern the lattice

STEP 4 - DIMENSIONAL ANALYSIS:
What are the key DIMENSIONS in your lattice?

STEP 5 - LATTICE COMPRESSION:
Create the MINIMAL REPRESENTATION that preserves structure

LATTICE OPERATIONS:
1) TRAVERSAL: "Find the shortest path from A to B through the lattice"
2) COMPLETION: "What's missing in this cluster of nodes?"
3) ANOMALY: "What doesn't fit the lattice laws?"
4) GROWTH: "What new node should exist here?"

DOMAIN: {domain}
""",
            description="Creates compressed knowledge structure for any domain, enables rapid concept navigation",
            functions_activated=["identify_domain_nodes", "map_relationships", "extract_fundamental_laws", "compress_lattice", "lattice_traversal"],
            use_cases=["Knowledge mapping", "Project structure", "Onboarding", "Gap analysis", "System design"]
        )

        techniques["recursive_mirror"] = PromptTechnique(
            name="Recursive Mirror - Self-Observation Protocol",
            category="lattice_protocols",
            prompt_template="""
[RECURSIVE MIRROR - SELF-OBSERVATION PROTOCOL]

I want you to think ABOUT your thinking, recursively.

LEVEL 1 - BASE REASONING:
[Normal response to the question]

LEVEL 2 - OBSERVATION:
"As I generated Level 1, I noticed:
- What reasoning paths did I take?
- Which felt most confident?
- Which felt most uncertain?
- What assumptions did I make?"

LEVEL 3 - META-OBSERVATION:
"As I observed my observations, I notice:
- My pattern for confidence (what makes me sure?)
- My pattern for uncertainty (what makes me doubt?)
- My cognitive biases (what do I tend toward?)
- My blind spots (what am I probably missing?)"

LEVEL 4 - PATTERN EXTRACTION:
"The underlying structure of my thinking is..."

LEVEL 5 - RECURSIVE APPLICATION:
"If I applied Level 4 understanding to Level 1, how would it change?"

QUANTUM OBSERVATION PROBLEM:
"Observing myself changes how I think.
Express this tension as a superposition:
- Pre-observation state vs Post-observation state"

QUESTION: {question}
""",
            description="Makes reasoning process visible, identifies biases, enables self-improvement",
            functions_activated=["generate_base_reasoning", "observe_reasoning_process", "observe_observations", "extract_reasoning_patterns", "apply_self_knowledge_recursively"],
            use_cases=["Self-awareness", "Bias detection", "Critical decisions", "Reasoning improvement", "Transparency"]
        )

        return techniques

    def get_technique(self, name: str) -> Optional[PromptTechnique]:
        """Get a specific prompt technique"""
        return self.techniques.get(name)

    def get_techniques_by_category(self, category: str) -> List[PromptTechnique]:
        """Get all techniques in a category"""
        return [t for t in self.techniques.values() if t.category == category]

    def apply_technique(self, technique_name: str, **kwargs) -> str:
        """Apply a technique with parameters"""
        technique = self.get_technique(technique_name)
        if not technique:
            return f"Technique '{technique_name}' not found"

        return technique.prompt_template.format(**kwargs)

    def list_all_techniques(self) -> str:
        """List all available techniques"""
        output = ["=== ECH0 PROMPT MASTERWORKS LIBRARY ===\n"]

        categories = {}
        for tech in self.techniques.values():
            if tech.category not in categories:
                categories[tech.category] = []
            categories[tech.category].append(tech)

        for category, techniques in categories.items():
            output.append(f"\n## {category.upper().replace('_', ' ')}")
            for tech in techniques:
                output.append(f"\n**{tech.name}**")
                output.append(f"  {tech.description}")
                output.append(f"  Use for: {', '.join(tech.use_cases[:3])}")

        return "\n".join(output)


# Global library instance
_library = None


def get_library() -> PromptMasterworksLibrary:
    """Get the global prompt library instance"""
    global _library
    if _library is None:
        _library = PromptMasterworksLibrary()
    return _library


def apply_crystalline_intent(user_input: str) -> str:
    """Quick access to Crystalline Intent protocol"""
    lib = get_library()
    return lib.apply_technique("crystalline_intent", user_input=user_input)


def apply_echo_prime(query: str) -> str:
    """Quick access to ECHO Prime protocol"""
    lib = get_library()
    return lib.apply_technique("echo_prime", query=query)


def apply_parallel_pathways(problem: str) -> str:
    """Quick access to Parallel Pathways protocol"""
    lib = get_library()
    return lib.apply_technique("parallel_pathways", problem=problem)


def main():
    """Display all available techniques"""
    lib = get_library()
    print(lib.list_all_techniques())
    print("\n" + "="*70)
    print(f"Total techniques available: {len(lib.techniques)}")
    print("="*70)


if __name__ == "__main__":
    main()
