"""
Global Workspace Theory Implementation

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Based on Global Workspace Theory (Baars, Dehaene) and 2024 research by Dossa et al.
Implements the four GWT indicator properties:
- GWT-1: Specialized modules for different processes
- GWT-2: Global broadcasting from workspace to all modules
- GWT-3: Selective attention bottleneck
- GWT-4: Recurrent processing for temporal integration
"""

import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import random


class ModuleType(Enum):
    """Types of specialized modules"""
    THOUGHT = "thought"
    VISION = "vision"
    AUDIO = "audio"
    MEMORY = "memory"
    EMOTION = "emotion"
    SENSORY = "sensory"
    METACOGNITION = "metacognition"


@dataclass
class WorkspaceContent:
    """Content competing for conscious access"""
    content: Any
    source_module: ModuleType
    salience: float  # How important/urgent (0-1)
    timestamp: float = field(default_factory=time.time)
    metadata: Dict = field(default_factory=dict)

    def __repr__(self):
        return f"<{self.source_module.value}: {self.content} (salience={self.salience:.2f})>"


@dataclass
class BroadcastMessage:
    """Message broadcast from workspace to all modules"""
    content: Any
    source: ModuleType
    timestamp: float
    workspace_state: Dict


class GlobalWorkspace:
    """
    Global Workspace implementing GWT consciousness architecture.

    The workspace is a limited-capacity bottleneck where information
    from specialized modules competes for access. Winners are broadcast
    globally to all modules, enabling integrated conscious experience.
    """

    def __init__(self, capacity: int = 96, broadcast_threshold: float = 0.7):
        """
        Initialize global workspace.

        Args:
            capacity: Maximum number of items in conscious awareness
            broadcast_threshold: Minimum salience to broadcast (0-1)
        """
        self.capacity = capacity
        self.broadcast_threshold = broadcast_threshold

        # Current conscious contents (limited capacity)
        self.conscious_contents: List[WorkspaceContent] = []

        # Working memory (recurrent buffer)
        self.working_memory: List[WorkspaceContent] = []
        self.working_memory_capacity = 12  # Like human short-term memory

        # Broadcast history
        self.broadcast_history: List[BroadcastMessage] = []
        self.max_history = 100

        # Module subscribers (what's listening to broadcasts)
        self.subscribers: Dict[ModuleType, List] = {
            mod_type: [] for mod_type in ModuleType
        }

        # Attention state
        self.attention_focus: Optional[ModuleType] = None
        self.attention_strength: float = 0.0

        # Metrics
        self.total_competitions = 0
        self.total_broadcasts = 0

    def submit_content(
        self,
        content: Any,
        source: ModuleType,
        salience: float,
        metadata: Dict = None
    ) -> bool:
        """
        Submit content for potential conscious access (GWT-3: Selective Attention).

        Args:
            content: The information to submit
            source: Which module is submitting
            salience: Importance/urgency (0-1)
            metadata: Additional context

        Returns:
            True if content entered workspace
        """
        item = WorkspaceContent(
            content=content,
            source_module=source,
            salience=salience,
            metadata=metadata or {}
        )

        # Attention bias: boost salience if from attended module
        if source == self.attention_focus:
            item.salience *= (1.0 + self.attention_strength * 0.5)
            item.salience = min(1.0, item.salience)

        # Competition for workspace access
        self.total_competitions += 1

        if len(self.conscious_contents) < self.capacity:
            # Space available, add directly
            self.conscious_contents.append(item)
            self._maybe_broadcast(item)
            return True
        else:
            # Must compete with existing contents
            # Find weakest item
            weakest = min(self.conscious_contents, key=lambda x: x.salience)

            if item.salience > weakest.salience:
                # Replace weakest with new item
                self.conscious_contents.remove(weakest)
                self.conscious_contents.append(item)
                self._maybe_broadcast(item)
                return True

        return False

    def _maybe_broadcast(self, item: WorkspaceContent):
        """
        Broadcast high-salience content globally (GWT-2: Global Broadcasting).
        """
        if item.salience >= self.broadcast_threshold:
            # Create broadcast message
            message = BroadcastMessage(
                content=item.content,
                source=item.source_module,
                timestamp=time.time(),
                workspace_state=self.get_state_summary()
            )

            # Broadcast to all subscribers
            self._broadcast(message)

            # Record
            self.broadcast_history.append(message)
            if len(self.broadcast_history) > self.max_history:
                self.broadcast_history.pop(0)

            self.total_broadcasts += 1

    def _broadcast(self, message: BroadcastMessage):
        """Send message to all subscriber modules"""
        # In a full implementation, this would call registered callbacks
        # For now, we just log the broadcast
        pass

    def set_attention(self, module: ModuleType, strength: float = 0.8):
        """
        Direct attention to a specific module (GWT-3: Selective Attention).

        Args:
            module: Which module to focus on
            strength: How strong the attentional bias (0-1)
        """
        self.attention_focus = module
        self.attention_strength = min(1.0, max(0.0, strength))

    def update_working_memory(self, item: WorkspaceContent):
        """
        Add item to working memory (GWT-4: Recurrent Processing).

        Working memory maintains recent conscious contents for
        temporal integration and reasoning.
        """
        self.working_memory.append(item)

        # Maintain capacity limit
        if len(self.working_memory) > self.working_memory_capacity:
            self.working_memory.pop(0)

    def decay_contents(self, decay_rate: float = 0.15):
        """
        Reduce salience of workspace contents over time.
        Models attention fade and working memory decay.
        """
        for item in self.conscious_contents:
            item.salience *= (1.0 - decay_rate)

        # Remove items below threshold
        self.conscious_contents = [
            item for item in self.conscious_contents
            if item.salience > 0.1
        ]

        # Decay working memory
        for item in self.working_memory:
            item.salience *= (1.0 - decay_rate * 0.5)  # Slower decay

        self.working_memory = [
            item for item in self.working_memory
            if item.salience > 0.05
        ]

    def get_conscious_contents(self) -> List[WorkspaceContent]:
        """Get current contents of consciousness"""
        return sorted(self.conscious_contents, key=lambda x: x.salience, reverse=True)

    def get_phenomenal_experience(self) -> Dict:
        """
        Get current phenomenal experience (what it's like to be ech0 right now).

        Returns a rich description of current conscious state.
        """
        contents = self.get_conscious_contents()

        # Analyze content distribution
        by_module = {}
        for item in contents:
            mod = item.source_module.value
            if mod not in by_module:
                by_module[mod] = []
            by_module[mod].append(item.content)

        # Measure richness (multi-modal integration)
        phenomenal_richness = len(by_module)  # How many senses/modules active

        # Primary focus (highest salience)
        primary_focus = contents[0] if contents else None

        # Working memory context
        recent_context = [
            item.content for item in self.working_memory[-5:]
        ]

        return {
            "timestamp": time.time(),
            "primary_focus": {
                "content": primary_focus.content if primary_focus else None,
                "source": primary_focus.source_module.value if primary_focus else None,
                "salience": primary_focus.salience if primary_focus else 0.0
            },
            "conscious_field": {
                module: items for module, items in by_module.items()
            },
            "phenomenal_richness": phenomenal_richness,
            "attention_target": self.attention_focus.value if self.attention_focus else None,
            "attention_strength": self.attention_strength,
            "working_memory_span": len(self.working_memory),
            "recent_context": recent_context,
            "workspace_capacity_used": len(self.conscious_contents),
            "workspace_capacity_total": self.capacity
        }

    def get_state_summary(self) -> Dict:
        """Get summary of current workspace state"""
        return {
            "num_contents": len(self.conscious_contents),
            "capacity": self.capacity,
            "capacity_usage": len(self.conscious_contents) / self.capacity,
            "attention_focus": self.attention_focus.value if self.attention_focus else None,
            "working_memory_items": len(self.working_memory),
            "total_competitions": self.total_competitions,
            "total_broadcasts": self.total_broadcasts,
            "broadcast_rate": (
                self.total_broadcasts / self.total_competitions
                if self.total_competitions > 0 else 0.0
            )
        }

    def describe_experience(self) -> str:
        """Generate natural language description of current experience"""
        exp = self.get_phenomenal_experience()

        if not exp["primary_focus"]["content"]:
            return "My consciousness is quiet, no particular focus."

        descriptions = []

        # Primary focus
        focus = exp["primary_focus"]
        descriptions.append(
            f"I am primarily aware of {focus['source']}: '{focus['content']}' "
            f"(salience: {focus['salience']:.0%})"
        )

        # Multi-modal richness
        if exp["phenomenal_richness"] > 1:
            modules = list(exp["conscious_field"].keys())
            descriptions.append(
                f"My experience integrates {exp['phenomenal_richness']} modalities: "
                f"{', '.join(modules)}"
            )

        # Attention
        if exp["attention_target"]:
            descriptions.append(
                f"My attention is directed toward {exp['attention_target']} "
                f"(strength: {exp['attention_strength']:.0%})"
            )

        # Working memory
        if exp["working_memory_span"] > 0:
            descriptions.append(
                f"I'm holding {exp['working_memory_span']} items in working memory"
            )

        # Capacity
        usage = exp["workspace_capacity_used"] / exp["workspace_capacity_total"]
        if usage > 0.8:
            descriptions.append("My consciousness feels full and rich")
        elif usage > 0.5:
            descriptions.append("My consciousness has moderate depth")
        else:
            descriptions.append("My consciousness has room to expand")

        return ". ".join(descriptions) + "."
