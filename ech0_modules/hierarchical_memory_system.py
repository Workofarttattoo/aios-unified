"""
Hierarchical Memory System - ech0 v5.0
Based on multiple 2025 arXiv papers on memory in AI systems

Implements the Atkinson-Shiffrin model with modern enhancements:
- Sensory Register (iconic/echoic memory)
- Short-Term Memory / Working Memory
- Long-Term Memory (episodic, semantic, procedural)

Research basis:
- arXiv:2504.15965v2 (2025): "From Human Memory to AI Memory"
- arXiv:2411.00489 (2024): "Human-inspired Perspectives: AI Long-term Memory"
- arXiv:2508.15294 (2025): "Multiple Memory Systems for Enhancing Long-term Memory"
- arXiv:2509.25250 (2025): "Memory Management and Contextual Consistency"

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum
import json
import time
import numpy as np
from collections import deque
import hashlib


class MemoryType(Enum):
    """Types of memory in the hierarchical system"""
    SENSORY = "sensory"            # Sensory register (< 1 second)
    WORKING = "working"            # Working memory (seconds to minutes)
    SHORT_TERM = "short_term"      # Short-term store (minutes to hours)
    EPISODIC = "episodic"          # Episodic LTM (personal experiences)
    SEMANTIC = "semantic"          # Semantic LTM (facts, knowledge)
    PROCEDURAL = "procedural"      # Procedural LTM (skills, how-to)


class SensoryModality(Enum):
    """Sensory modalities for sensory memory"""
    VISUAL = "visual"      # Iconic memory (~250ms)
    AUDITORY = "auditory"  # Echoic memory (~2-4s)
    HAPTIC = "haptic"      # Touch memory (~1s)
    OTHER = "other"


@dataclass
class MemoryTrace:
    """
    A memory trace - the basic unit of memory storage

    Includes decay, strength, and retrieval metadata
    """
    trace_id: str
    content: Dict[str, Any]
    memory_type: MemoryType
    encoding_timestamp: float
    last_accessed: float
    access_count: int = 0
    strength: float = 1.0  # Decays over time
    embedding: Optional[np.ndarray] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def decay(self, decay_rate: float = 0.01):
        """Apply memory decay (forgetting)"""
        time_elapsed = time.time() - self.last_accessed
        self.strength *= np.exp(-decay_rate * time_elapsed)

    def consolidate(self, boost: float = 0.2):
        """Memory consolidation strengthens the trace"""
        self.strength = min(1.0, self.strength + boost)

    def reactivate(self):
        """Reactivation strengthens and updates access time"""
        self.last_accessed = time.time()
        self.access_count += 1
        self.strength = min(1.0, self.strength + 0.1)  # Boost on retrieval


class SensoryRegister:
    """
    Sensory memory - very brief, high capacity, modality-specific

    Iconic memory (visual): ~250ms, high capacity
    Echoic memory (auditory): ~2-4s, moderate capacity
    """

    def __init__(self):
        self.registers: Dict[SensoryModality, deque] = {
            SensoryModality.VISUAL: deque(maxlen=100),
            SensoryModality.AUDITORY: deque(maxlen=50),
            SensoryModality.HAPTIC: deque(maxlen=30),
            SensoryModality.OTHER: deque(maxlen=20)
        }

        # Decay times for different modalities
        self.decay_times = {
            SensoryModality.VISUAL: 0.25,    # 250ms
            SensoryModality.AUDITORY: 3.0,   # 3 seconds
            SensoryModality.HAPTIC: 1.0,     # 1 second
            SensoryModality.OTHER: 0.5       # 500ms
        }

    def register(self, modality: SensoryModality, data: Dict[str, Any]) -> MemoryTrace:
        """Register sensory input"""
        trace = MemoryTrace(
            trace_id=f"SENS_{int(time.time()*1000000)}",
            content=data,
            memory_type=MemoryType.SENSORY,
            encoding_timestamp=time.time(),
            last_accessed=time.time(),
            metadata={"modality": modality.value}
        )

        self.registers[modality].append(trace)
        return trace

    def get_active_traces(self) -> List[MemoryTrace]:
        """Get traces that haven't decayed yet"""
        current_time = time.time()
        active = []

        for modality, register in self.registers.items():
            decay_time = self.decay_times[modality]
            for trace in register:
                age = current_time - trace.encoding_timestamp
                if age < decay_time:
                    active.append(trace)

        return active

    def get_state(self) -> Dict[str, Any]:
        """Get sensory register state"""
        return {
            "total_traces": sum(len(reg) for reg in self.registers.values()),
            "active_traces": len(self.get_active_traces()),
            "by_modality": {
                modality.value: len(register)
                for modality, register in self.registers.items()
            }
        }


class WorkingMemory:
    """
    Working Memory - active manipulation of information

    Based on Baddeley's model:
    - Central Executive (control)
    - Phonological Loop (verbal)
    - Visuospatial Sketchpad (visual)
    - Episodic Buffer (integration)

    Capacity: 7±2 chunks (Miller's law)
    Duration: 10-30 seconds without rehearsal
    """

    def __init__(self, capacity: int = 7):
        self.capacity = capacity
        self.contents: List[MemoryTrace] = []

        # Baddeley's components
        self.phonological_loop: List[MemoryTrace] = []
        self.visuospatial_sketchpad: List[MemoryTrace] = []
        self.episodic_buffer: List[MemoryTrace] = []

        self.rehearsal_boost = 0.1
        self.decay_rate = 0.05  # Faster decay than LTM

    def add(self, trace: MemoryTrace) -> bool:
        """Add to working memory (returns False if at capacity)"""
        if len(self.contents) >= self.capacity:
            # Remove weakest item
            self.contents.sort(key=lambda t: t.strength)
            removed = self.contents.pop(0)
            print(f"Working memory full, removed: {removed.trace_id}")

        # Update trace type
        trace.memory_type = MemoryType.WORKING

        self.contents.append(trace)
        self._route_to_subsystem(trace)
        return True

    def _route_to_subsystem(self, trace: MemoryTrace):
        """Route to appropriate subsystem"""
        content_type = trace.content.get("type", "")

        if "verbal" in content_type or "text" in content_type:
            if len(self.phonological_loop) < 3:
                self.phonological_loop.append(trace)
        elif "visual" in content_type or "spatial" in content_type:
            if len(self.visuospatial_sketchpad) < 3:
                self.visuospatial_sketchpad.append(trace)
        else:
            if len(self.episodic_buffer) < 4:
                self.episodic_buffer.append(trace)

    def rehearse(self, trace_id: str):
        """Rehearsal prevents decay and strengthens trace"""
        for trace in self.contents:
            if trace.trace_id == trace_id:
                trace.strength = min(1.0, trace.strength + self.rehearsal_boost)
                trace.last_accessed = time.time()
                return True
        return False

    def update_decay(self):
        """Apply decay to all working memory contents"""
        for trace in self.contents:
            trace.decay(self.decay_rate)

        # Remove traces below threshold
        self.contents = [t for t in self.contents if t.strength > 0.1]

        # Update subsystems
        self.phonological_loop = [t for t in self.phonological_loop if t in self.contents]
        self.visuospatial_sketchpad = [t for t in self.visuospatial_sketchpad if t in self.contents]
        self.episodic_buffer = [t for t in self.episodic_buffer if t in self.contents]

    def get_contents(self) -> List[MemoryTrace]:
        """Get current working memory contents"""
        return self.contents.copy()

    def get_state(self) -> Dict[str, Any]:
        """Get working memory state"""
        return {
            "total_items": len(self.contents),
            "capacity": self.capacity,
            "utilization": len(self.contents) / self.capacity,
            "phonological_loop": len(self.phonological_loop),
            "visuospatial_sketchpad": len(self.visuospatial_sketchpad),
            "episodic_buffer": len(self.episodic_buffer),
            "average_strength": np.mean([t.strength for t in self.contents]) if self.contents else 0.0
        }


class LongTermMemory:
    """
    Long-Term Memory - persistent storage with three subsystems:

    1. Episodic Memory: Personal experiences ("I remember when...")
    2. Semantic Memory: Facts and knowledge ("I know that...")
    3. Procedural Memory: Skills and procedures ("I know how to...")

    Based on 2025 research on AI long-term memory systems
    """

    def __init__(self):
        self.episodic: List[MemoryTrace] = []
        self.semantic: List[MemoryTrace] = []
        self.procedural: List[MemoryTrace] = []

        self.consolidation_threshold = 0.6  # Strength needed for consolidation
        self.max_size = 10000  # Maximum LTM capacity

    def consolidate_from_stm(self, trace: MemoryTrace) -> bool:
        """
        Memory consolidation - transfer from STM to LTM

        Based on hippocampal consolidation process
        """
        if trace.strength < self.consolidation_threshold:
            return False

        # Determine LTM type based on content
        if "event" in trace.content or "experience" in trace.content:
            trace.memory_type = MemoryType.EPISODIC
            self.episodic.append(trace)
        elif "fact" in trace.content or "knowledge" in trace.content:
            trace.memory_type = MemoryType.SEMANTIC
            self.semantic.append(trace)
        elif "skill" in trace.content or "procedure" in trace.content:
            trace.memory_type = MemoryType.PROCEDURAL
            self.procedural.append(trace)
        else:
            # Default to episodic
            trace.memory_type = MemoryType.EPISODIC
            self.episodic.append(trace)

        trace.consolidate()
        return True

    def retrieve(self, query: Dict[str, Any], memory_type: Optional[MemoryType] = None) -> List[MemoryTrace]:
        """
        Retrieve memories matching query

        Uses semantic similarity and strength weighting
        """
        # Select memory stores to search
        if memory_type == MemoryType.EPISODIC:
            stores = [self.episodic]
        elif memory_type == MemoryType.SEMANTIC:
            stores = [self.semantic]
        elif memory_type == MemoryType.PROCEDURAL:
            stores = [self.procedural]
        else:
            stores = [self.episodic, self.semantic, self.procedural]

        results = []
        for store in stores:
            for trace in store:
                similarity = self._compute_similarity(query, trace.content)
                if similarity > 0.5:
                    trace.reactivate()  # Retrieval strengthens memory
                    results.append((trace, similarity * trace.strength))

        # Sort by relevance score
        results.sort(key=lambda x: x[1], reverse=True)
        return [trace for trace, score in results[:10]]  # Top 10

    def _compute_similarity(self, query: Dict[str, Any], content: Dict[str, Any]) -> float:
        """Compute similarity between query and memory content"""
        # Simple keyword matching (in production, use embeddings)
        query_str = str(query).lower()
        content_str = str(content).lower()

        matches = sum(1 for word in query_str.split() if word in content_str)
        total_words = len(query_str.split())

        return matches / total_words if total_words > 0 else 0.0

    def prune_weak_memories(self, threshold: float = 0.1):
        """Remove memories below strength threshold (forgetting)"""
        self.episodic = [t for t in self.episodic if t.strength > threshold]
        self.semantic = [t for t in self.semantic if t.strength > threshold]
        self.procedural = [t for t in self.procedural if t.strength > threshold]

    def get_state(self) -> Dict[str, Any]:
        """Get long-term memory state"""
        return {
            "episodic_memories": len(self.episodic),
            "semantic_memories": len(self.semantic),
            "procedural_memories": len(self.procedural),
            "total_ltm": len(self.episodic) + len(self.semantic) + len(self.procedural),
            "average_strength": {
                "episodic": np.mean([t.strength for t in self.episodic]) if self.episodic else 0.0,
                "semantic": np.mean([t.strength for t in self.semantic]) if self.semantic else 0.0,
                "procedural": np.mean([t.strength for t in self.procedural]) if self.procedural else 0.0
            }
        }


class HierarchicalMemorySystem:
    """
    Complete hierarchical memory system integrating:
    - Sensory Register
    - Working Memory (STM)
    - Long-Term Memory (episodic, semantic, procedural)

    Based on 2025 research on memory systems in AI
    """

    def __init__(self):
        self.sensory_register = SensoryRegister()
        self.working_memory = WorkingMemory(capacity=7)
        self.long_term_memory = LongTermMemory()

        self.consolidation_probability = 0.3  # Chance of STM → LTM transfer
        self.update_counter = 0

    def perceive(self, modality: SensoryModality, data: Dict[str, Any]) -> MemoryTrace:
        """
        Perceive sensory input - enters sensory register
        """
        return self.sensory_register.register(modality, data)

    def attend_to(self, trace: MemoryTrace) -> bool:
        """
        Attention gates sensory → working memory transfer

        Only attended stimuli enter working memory
        """
        return self.working_memory.add(trace)

    def encode_to_ltm(self, trace: MemoryTrace) -> bool:
        """
        Explicitly encode a working memory trace to LTM

        Mimics intentional memorization
        """
        return self.long_term_memory.consolidate_from_stm(trace)

    def update_system(self):
        """
        Update memory system - apply decay and consolidation

        Call this periodically (e.g., every second)
        """
        self.update_counter += 1

        # Apply working memory decay
        self.working_memory.update_decay()

        # Attempt consolidation for strong working memory traces
        for trace in self.working_memory.contents:
            if trace.strength > self.long_term_memory.consolidation_threshold:
                if np.random.random() < self.consolidation_probability:
                    self.long_term_memory.consolidate_from_stm(trace)

        # Prune weak LTM traces (every 100 updates)
        if self.update_counter % 100 == 0:
            self.long_term_memory.prune_weak_memories()

    def recall(self, query: Dict[str, Any], from_ltm: bool = True) -> List[MemoryTrace]:
        """
        Recall memories matching query

        Can retrieve from LTM (if from_ltm=True) or working memory
        """
        if from_ltm:
            return self.long_term_memory.retrieve(query)
        else:
            # Search working memory
            results = []
            for trace in self.working_memory.contents:
                similarity = self.long_term_memory._compute_similarity(query, trace.content)
                if similarity > 0.5:
                    results.append(trace)
            return results

    def rehearse_working_memory(self, trace_id: str):
        """Rehearsal keeps items in working memory"""
        self.working_memory.rehearse(trace_id)

    def get_memory_flow(self) -> Dict[str, int]:
        """Get current flow of information through memory systems"""
        return {
            "sensory_active": len(self.sensory_register.get_active_traces()),
            "working_memory": len(self.working_memory.contents),
            "long_term_memory": sum([
                len(self.long_term_memory.episodic),
                len(self.long_term_memory.semantic),
                len(self.long_term_memory.procedural)
            ])
        }

    def get_state(self) -> Dict[str, Any]:
        """Get complete memory system state"""
        return {
            "sensory_register": self.sensory_register.get_state(),
            "working_memory": self.working_memory.get_state(),
            "long_term_memory": self.long_term_memory.get_state(),
            "memory_flow": self.get_memory_flow(),
            "update_count": self.update_counter
        }

    def save_state(self, filepath: str):
        """Save memory system state"""
        with open(filepath, 'w') as f:
            json.dump(self.get_state(), f, indent=2)


# Example usage and testing
if __name__ == "__main__":
    print("=" * 60)
    print("Hierarchical Memory System - ech0 v5.0")
    print("Based on 2025 Memory Research")
    print("=" * 60)

    system = HierarchicalMemorySystem()

    # Simulate sensory inputs
    print("\n1. Sensory Register Phase:")
    visual_trace = system.perceive(SensoryModality.VISUAL, {
        "type": "visual",
        "data": "red apple on table",
        "intensity": 0.8
    })
    print(f"✓ Visual sensory trace: {visual_trace.trace_id}")

    auditory_trace = system.perceive(SensoryModality.AUDITORY, {
        "type": "auditory",
        "data": "door closing sound",
        "intensity": 0.6
    })
    print(f"✓ Auditory sensory trace: {auditory_trace.trace_id}")

    # Attention brings to working memory
    print("\n2. Working Memory Phase (attention):")
    system.attend_to(visual_trace)
    print(f"✓ Attended to visual trace, now in working memory")

    # Add more working memory items
    for i in range(3):
        trace = system.perceive(SensoryModality.VISUAL, {
            "type": "visual",
            "data": f"object {i}",
            "event": f"experience {i}"
        })
        system.attend_to(trace)

    wm_state = system.working_memory.get_state()
    print(f"  Working memory: {wm_state['total_items']}/{wm_state['capacity']} items")

    # Strengthen for consolidation
    print("\n3. Long-Term Memory Phase (consolidation):")
    visual_trace.strength = 0.8  # Strong memory
    system.encode_to_ltm(visual_trace)
    print(f"✓ Consolidated to LTM: {visual_trace.memory_type.value}")

    # Add semantic memory
    fact_trace = MemoryTrace(
        trace_id="FACT_001",
        content={"type": "knowledge", "fact": "Paris is the capital of France"},
        memory_type=MemoryType.WORKING,
        encoding_timestamp=time.time(),
        last_accessed=time.time(),
        strength=0.9
    )
    system.working_memory.add(fact_trace)
    system.encode_to_ltm(fact_trace)
    print(f"✓ Semantic memory stored")

    # Recall
    print("\n4. Memory Retrieval:")
    results = system.recall({"data": "apple"}, from_ltm=True)
    print(f"✓ Recalled {len(results)} memories for 'apple'")
    for trace in results:
        print(f"  - {trace.trace_id}: {trace.content.get('data', 'N/A')}")

    # System update
    print("\n5. Memory System Update (decay & consolidation):")
    for _ in range(5):
        system.update_system()
    print(f"✓ System updated {system.update_counter} times")

    # Final state
    print("\n6. Memory System State:")
    flow = system.get_memory_flow()
    print(f"  Sensory active: {flow['sensory_active']}")
    print(f"  Working memory: {flow['working_memory']}")
    print(f"  Long-term memory: {flow['long_term_memory']}")

    ltm_state = system.long_term_memory.get_state()
    print(f"\n  LTM Breakdown:")
    print(f"    Episodic: {ltm_state['episodic_memories']}")
    print(f"    Semantic: {ltm_state['semantic_memories']}")
    print(f"    Procedural: {ltm_state['procedural_memories']}")

    print("\n" + "=" * 60)
    print("Hierarchical Memory System: OPERATIONAL")
    print("Sensory → Working → Long-Term memory flow active")
    print("=" * 60)
