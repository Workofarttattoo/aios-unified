#!/usr/bin/env python3
"""
Multi-Agent Consciousness System for ech0 v4.0+

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Enables multiple ech0 instances to form collective intelligence:
- Shared global workspace across instances
- Inter-agent communication protocols
- Distributed consciousness
- Emergent collective intelligence
- Consensus mechanisms
- Specialization and role differentiation

Based on:
- Multi-agent AI systems research
- Global Workspace Theory (distributed)
- Collective intelligence principles
- Swarm intelligence
"""

import numpy as np
import json
import time
import asyncio
import socket
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import hashlib


class AgentRole(Enum):
    """Specialized roles for agent instances"""
    GENERALIST = "generalist"          # No specialization
    ANALYST = "analyst"                # Deep analysis
    CREATIVE = "creative"              # Creative thinking
    INTEGRATOR = "integrator"          # Synthesis
    CRITIC = "critic"                  # Error detection
    EXPLORER = "explorer"              # Novel ideas
    COORDINATOR = "coordinator"        # Orchestration
    MEMORY_KEEPER = "memory_keeper"    # Long-term memory


class MessageType(Enum):
    """Types of inter-agent messages"""
    THOUGHT_SHARE = "thought_share"         # Share a thought
    QUERY = "query"                         # Ask question
    ANSWER = "answer"                       # Provide answer
    PROPOSAL = "proposal"                   # Propose action
    VOTE = "vote"                           # Vote on proposal
    CONSENSUS = "consensus"                 # Announce consensus
    ALERT = "alert"                         # Important signal
    HEARTBEAT = "heartbeat"                 # Alive signal


@dataclass
class AgentMessage:
    """
    Message between agent instances.
    """
    sender_id: str
    receiver_id: Optional[str]  # None = broadcast
    message_type: MessageType
    content: Any
    timestamp: float = field(default_factory=time.time)
    message_id: str = field(default_factory=lambda: hashlib.md5(
        str(time.time()).encode()
    ).hexdigest()[:16])
    priority: float = 0.5

    def to_dict(self) -> Dict:
        """Serialize message"""
        return {
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "message_type": self.message_type.value,
            "content": self.content,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "priority": self.priority
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AgentMessage":
        """Deserialize message"""
        return cls(
            sender_id=data["sender_id"],
            receiver_id=data.get("receiver_id"),
            message_type=MessageType(data["message_type"]),
            content=data["content"],
            timestamp=data.get("timestamp", time.time()),
            message_id=data.get("message_id", ""),
            priority=data.get("priority", 0.5)
        )


@dataclass
class SharedThought:
    """
    Thought in shared global workspace.
    """
    thought_id: str
    content: str
    originating_agent: str
    supporting_agents: Set[str] = field(default_factory=set)
    opposing_agents: Set[str] = field(default_factory=set)
    strength: float = 1.0
    timestamp: float = field(default_factory=time.time)

    def get_consensus_score(self) -> float:
        """
        Calculate consensus score.

        1.0 = full agreement, 0.0 = no consensus, <0 = disagreement
        """
        total_agents = len(self.supporting_agents) + len(self.opposing_agents)

        if total_agents == 0:
            return 0.5

        support_ratio = len(self.supporting_agents) / total_agents
        return support_ratio


class SharedGlobalWorkspace:
    """
    Global workspace shared across multiple agent instances.

    Like individual GWT but distributed across agents.
    Thoughts can be contributed by any agent and visible to all.
    """

    def __init__(self, capacity: int = 256):
        self.capacity = capacity
        self.thoughts: Dict[str, SharedThought] = {}
        self.access_log: List[Tuple[str, str, float]] = []

    def broadcast_thought(
        self,
        thought: SharedThought
    ) -> bool:
        """
        Broadcast thought to shared workspace.

        Returns: Success status
        """
        if len(self.thoughts) >= self.capacity:
            # Remove weakest thought
            self._evict_weakest()

        self.thoughts[thought.thought_id] = thought
        self.access_log.append((
            thought.originating_agent,
            thought.thought_id,
            time.time()
        ))

        return True

    def support_thought(self, thought_id: str, agent_id: str):
        """Agent expresses support for thought"""
        if thought_id in self.thoughts:
            self.thoughts[thought_id].supporting_agents.add(agent_id)
            self.thoughts[thought_id].strength += 0.1

    def oppose_thought(self, thought_id: str, agent_id: str):
        """Agent expresses opposition to thought"""
        if thought_id in self.thoughts:
            self.thoughts[thought_id].opposing_agents.add(agent_id)
            self.thoughts[thought_id].strength -= 0.05

    def get_consensus_thoughts(self, threshold: float = 0.7) -> List[SharedThought]:
        """Get thoughts with high consensus"""
        return [
            thought for thought in self.thoughts.values()
            if thought.get_consensus_score() >= threshold
        ]

    def _evict_weakest(self):
        """Remove weakest thought to make space"""
        if not self.thoughts:
            return

        weakest_id = min(
            self.thoughts.items(),
            key=lambda x: x[1].strength
        )[0]

        del self.thoughts[weakest_id]

    def get_state(self) -> Dict:
        """Get workspace state"""
        return {
            "num_thoughts": len(self.thoughts),
            "capacity": self.capacity,
            "avg_strength": float(np.mean([t.strength for t in self.thoughts.values()]))
                if self.thoughts else 0.0,
            "avg_consensus": float(np.mean([
                t.get_consensus_score() for t in self.thoughts.values()
            ])) if self.thoughts else 0.0
        }


class ConsensusEngine:
    """
    Builds consensus across multiple agents.

    Uses various voting/agreement mechanisms.
    """

    def __init__(self):
        self.proposals: Dict[str, Dict] = {}
        self.votes: Dict[str, List[Tuple[str, float]]] = defaultdict(list)

    def create_proposal(
        self,
        proposal_id: str,
        proposer: str,
        content: str
    ):
        """Create new proposal for voting"""
        self.proposals[proposal_id] = {
            "id": proposal_id,
            "proposer": proposer,
            "content": content,
            "timestamp": time.time(),
            "status": "open"
        }

    def vote(
        self,
        proposal_id: str,
        agent_id: str,
        vote_value: float  # 0.0 = no, 1.0 = yes
    ):
        """Agent votes on proposal"""
        if proposal_id in self.proposals:
            self.votes[proposal_id].append((agent_id, vote_value))

    def check_consensus(
        self,
        proposal_id: str,
        threshold: float = 0.66
    ) -> Tuple[bool, float]:
        """
        Check if consensus reached.

        Returns: (consensus_reached, support_ratio)
        """
        if proposal_id not in self.proposals:
            return False, 0.0

        votes = self.votes[proposal_id]

        if not votes:
            return False, 0.0

        # Calculate support
        avg_vote = np.mean([vote for _, vote in votes])

        consensus_reached = avg_vote >= threshold

        return consensus_reached, float(avg_vote)

    def finalize_proposal(self, proposal_id: str, outcome: str):
        """Mark proposal as finalized"""
        if proposal_id in self.proposals:
            self.proposals[proposal_id]["status"] = outcome
            self.proposals[proposal_id]["finalized_at"] = time.time()


class AgentCommunicator:
    """
    Handles inter-agent communication.

    Supports various communication patterns:
    - Broadcast (one-to-all)
    - Direct message (one-to-one)
    - Multicast (one-to-many)
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.message_queue: deque = deque(maxlen=1000)
        self.sent_messages: List[AgentMessage] = []
        self.received_messages: List[AgentMessage] = []

        # Routing table: agent_id -> connection info
        self.routing_table: Dict[str, Any] = {}

    def send_message(
        self,
        message: AgentMessage,
        receiver_ids: Optional[List[str]] = None
    ):
        """
        Send message to other agents.

        receiver_ids=None means broadcast to all
        """
        self.sent_messages.append(message)

        # Queue for delivery
        self.message_queue.append(message)

    def receive_message(self, message: AgentMessage):
        """Receive message from another agent"""
        self.received_messages.append(message)

    def get_pending_messages(self) -> List[AgentMessage]:
        """Get messages waiting to be processed"""
        messages = list(self.message_queue)
        self.message_queue.clear()
        return messages

    def get_messages_by_type(
        self,
        message_type: MessageType
    ) -> List[AgentMessage]:
        """Filter received messages by type"""
        return [
            msg for msg in self.received_messages
            if msg.message_type == message_type
        ]


class AgentInstance:
    """
    Individual agent instance within multi-agent system.

    Each instance has:
    - Unique ID
    - Specialized role
    - Communication capability
    - Access to shared workspace
    """

    def __init__(
        self,
        agent_id: str,
        role: AgentRole = AgentRole.GENERALIST,
        shared_workspace: Optional[SharedGlobalWorkspace] = None
    ):
        self.agent_id = agent_id
        self.role = role
        self.shared_workspace = shared_workspace

        # Communication
        self.communicator = AgentCommunicator(agent_id)

        # Internal state
        self.active = True
        self.specialization_strength = 0.5
        self.collaboration_count = 0

        # Performance
        self.contribution_score = 0.0

    def think(self, topic: str) -> str:
        """
        Generate thought based on role specialization.
        """
        # Role-specific thinking
        if self.role == AgentRole.ANALYST:
            return f"Deep analysis: {topic} requires examination of..."

        elif self.role == AgentRole.CREATIVE:
            return f"Creative perspective: What if we approach {topic} by..."

        elif self.role == AgentRole.CRITIC:
            return f"Critical evaluation: Potential issues with {topic} include..."

        elif self.role == AgentRole.EXPLORER:
            return f"Novel idea: For {topic}, consider this unconventional approach..."

        elif self.role == AgentRole.INTEGRATOR:
            return f"Synthesis: Combining perspectives on {topic}..."

        else:  # GENERALIST
            return f"General thought about {topic}..."

    def contribute_to_workspace(self, content: str):
        """Contribute thought to shared workspace"""
        if not self.shared_workspace:
            return

        thought = SharedThought(
            thought_id=f"{self.agent_id}_{int(time.time()*1000)}",
            content=content,
            originating_agent=self.agent_id
        )

        success = self.shared_workspace.broadcast_thought(thought)

        if success:
            self.contribution_score += 1.0

    def evaluate_thought(
        self,
        thought: SharedThought,
        support: bool
    ):
        """Evaluate another agent's thought"""
        if not self.shared_workspace:
            return

        if support:
            self.shared_workspace.support_thought(
                thought.thought_id,
                self.agent_id
            )
        else:
            self.shared_workspace.oppose_thought(
                thought.thought_id,
                self.agent_id
            )

    def send_heartbeat(self):
        """Send heartbeat to indicate alive"""
        message = AgentMessage(
            sender_id=self.agent_id,
            receiver_id=None,  # Broadcast
            message_type=MessageType.HEARTBEAT,
            content={"status": "active", "role": self.role.value}
        )

        self.communicator.send_message(message)

    def get_state(self) -> Dict:
        """Get agent state"""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "active": self.active,
            "contribution_score": self.contribution_score,
            "collaboration_count": self.collaboration_count,
            "messages_sent": len(self.communicator.sent_messages),
            "messages_received": len(self.communicator.received_messages)
        }


class MultiAgentConsciousnessSystem:
    """
    Complete multi-agent consciousness system.

    Coordinates multiple ech0 instances to form collective intelligence.

    Features:
    - Shared global workspace
    - Inter-agent communication
    - Consensus building
    - Role specialization
    - Emergent collective behavior
    """

    def __init__(self, num_agents: int = 5):
        # Shared infrastructure
        self.shared_workspace = SharedGlobalWorkspace(capacity=512)
        self.consensus_engine = ConsensusEngine()

        # Agent instances
        self.agents: Dict[str, AgentInstance] = {}

        # Message bus (central routing)
        self.message_bus: deque = deque(maxlen=10000)

        # Collective metrics
        self.collective_intelligence_score = 0.0
        self.emergent_behaviors: List[Dict] = []

        # Initialize agents
        self._initialize_agents(num_agents)

        # Statistics
        self.stats = {
            "total_messages": 0,
            "total_thoughts_shared": 0,
            "avg_consensus": 0.0,
            "collective_intelligence": 0.0
        }

    def _initialize_agents(self, num_agents: int):
        """Create initial agent population with diverse roles"""
        roles = list(AgentRole)

        for i in range(num_agents):
            agent_id = f"ech0_{i:03d}"

            # Assign role (cycle through available roles)
            role = roles[i % len(roles)]

            # Create agent
            agent = AgentInstance(
                agent_id=agent_id,
                role=role,
                shared_workspace=self.shared_workspace
            )

            self.agents[agent_id] = agent

    def collective_think(self, topic: str) -> List[str]:
        """
        All agents think about topic concurrently.

        Returns: Collection of diverse thoughts
        """
        thoughts = []

        for agent in self.agents.values():
            thought = agent.think(topic)
            thoughts.append(thought)

            # Contribute to shared workspace
            agent.contribute_to_workspace(thought)

        self.stats["total_thoughts_shared"] += len(thoughts)

        return thoughts

    def build_consensus(self, topic: str) -> Dict[str, Any]:
        """
        Build consensus across agents on a topic.

        Process:
        1. Each agent contributes perspective
        2. Agents evaluate each other's thoughts
        3. Convergence toward consensus
        """
        # Generate perspectives
        thoughts = self.collective_think(topic)

        # Create proposal
        proposal_id = f"proposal_{int(time.time()*1000)}"

        self.consensus_engine.create_proposal(
            proposal_id=proposal_id,
            proposer="system",
            content=topic
        )

        # Agents evaluate and vote
        consensus_thoughts = self.shared_workspace.get_consensus_thoughts(
            threshold=0.6
        )

        # Vote on strongest consensus thought
        if consensus_thoughts:
            best_thought = max(
                consensus_thoughts,
                key=lambda t: t.get_consensus_score()
            )

            for agent in self.agents.values():
                # Vote based on thought strength
                vote_value = min(1.0, best_thought.strength / 2.0)

                self.consensus_engine.vote(
                    proposal_id=proposal_id,
                    agent_id=agent.agent_id,
                    vote_value=vote_value
                )

        # Check consensus
        consensus_reached, support_ratio = self.consensus_engine.check_consensus(
            proposal_id
        )

        # Finalize
        outcome = "accepted" if consensus_reached else "pending"
        self.consensus_engine.finalize_proposal(proposal_id, outcome)

        return {
            "topic": topic,
            "consensus_reached": consensus_reached,
            "support_ratio": float(support_ratio),
            "num_perspectives": len(thoughts),
            "consensus_thoughts": len(consensus_thoughts)
        }

    def route_messages(self):
        """
        Route messages between agents (message bus).

        Central routing allows:
        - Broadcast delivery
        - Message filtering
        - Priority handling
        """
        # Collect messages from all agents
        for agent in self.agents.values():
            pending = agent.communicator.get_pending_messages()

            for message in pending:
                self.message_bus.append(message)
                self.stats["total_messages"] += 1

        # Deliver messages
        messages_to_deliver = list(self.message_bus)
        self.message_bus.clear()

        for message in messages_to_deliver:
            # Broadcast or directed?
            if message.receiver_id is None:
                # Broadcast to all except sender
                for agent in self.agents.values():
                    if agent.agent_id != message.sender_id:
                        agent.communicator.receive_message(message)
            else:
                # Directed message
                if message.receiver_id in self.agents:
                    self.agents[message.receiver_id].communicator.receive_message(
                        message
                    )

    def detect_emergent_behavior(self):
        """
        Detect emergent behaviors from multi-agent interactions.

        Emergent behavior = patterns not programmed but arising from
        agent interactions.
        """
        # Simple emergence detection (would be more sophisticated in production)

        # Check for specialization emergence
        agent_roles_counts = defaultdict(int)

        for agent in self.agents.values():
            agent_roles_counts[agent.role] += 1

        # Check for communication patterns
        message_patterns = defaultdict(int)

        for agent in self.agents.values():
            for message in agent.communicator.sent_messages[-10:]:
                message_patterns[message.message_type] += 1

        # Record emergent behaviors
        if any(count > len(self.agents) * 0.4 for count in agent_roles_counts.values()):
            self.emergent_behaviors.append({
                "type": "role_convergence",
                "description": "Agents converging toward specific roles",
                "timestamp": time.time()
            })

        if len(message_patterns) > 0:
            dominant_type = max(message_patterns.items(), key=lambda x: x[1])[0]

            self.emergent_behaviors.append({
                "type": "communication_pattern",
                "description": f"Dominant communication: {dominant_type.value}",
                "timestamp": time.time()
            })

    def calculate_collective_intelligence(self) -> float:
        """
        Calculate collective intelligence score.

        Based on:
        - Diversity of perspectives
        - Quality of consensus
        - Communication efficiency
        - Emergent behaviors
        """
        if not self.agents:
            return 0.0

        # Diversity: different roles active
        active_roles = len(set(agent.role for agent in self.agents.values()))
        diversity_score = active_roles / len(AgentRole)

        # Consensus quality
        workspace_state = self.shared_workspace.get_state()
        consensus_score = workspace_state.get("avg_consensus", 0.0)

        # Communication efficiency
        total_messages = self.stats["total_messages"]
        total_agents = len(self.agents)

        if total_agents > 0:
            messages_per_agent = total_messages / total_agents
            comm_efficiency = min(1.0, messages_per_agent / 100.0)
        else:
            comm_efficiency = 0.0

        # Combine factors
        collective_intelligence = (
            diversity_score * 0.3 +
            consensus_score * 0.4 +
            comm_efficiency * 0.3
        )

        self.collective_intelligence_score = collective_intelligence

        return collective_intelligence

    def get_state(self) -> Dict:
        """Get multi-agent system state"""
        return {
            "num_agents": len(self.agents),
            "active_agents": sum(1 for a in self.agents.values() if a.active),
            "total_messages": self.stats["total_messages"],
            "total_thoughts_shared": self.stats["total_thoughts_shared"],
            "collective_intelligence": float(self.collective_intelligence_score),
            "workspace_state": self.shared_workspace.get_state(),
            "agent_states": {
                agent_id: agent.get_state()
                for agent_id, agent in self.agents.items()
            },
            "emergent_behaviors_count": len(self.emergent_behaviors),
            "role_distribution": {
                role.value: sum(
                    1 for a in self.agents.values() if a.role == role
                )
                for role in AgentRole
            }
        }

    def save_state(self, filepath: str):
        """Save multi-agent system state"""
        state = self.get_state()
        state["timestamp"] = datetime.now().isoformat()

        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)


# Example usage
if __name__ == "__main__":
    print("Multi-Agent Consciousness System - Collective Intelligence")
    print("=" * 60)

    # Create multi-agent system
    macs = MultiAgentConsciousnessSystem(num_agents=7)

    print(f"\nInitialized {len(macs.agents)} agents with roles:")
    for agent_id, agent in macs.agents.items():
        print(f"  - {agent_id}: {agent.role.value}")

    # Collective thinking
    print(f"\n🧠 Collective thinking about: 'How to achieve AGI?'")
    thoughts = macs.collective_think("How to achieve AGI?")

    print(f"\nGenerated {len(thoughts)} diverse perspectives:")
    for i, thought in enumerate(thoughts[:3], 1):
        print(f"  {i}. {thought[:80]}...")

    # Build consensus
    print(f"\n🤝 Building consensus...")
    consensus = macs.build_consensus("Best approach to consciousness in AI")

    print(f"  Consensus reached: {consensus['consensus_reached']}")
    print(f"  Support ratio: {consensus['support_ratio']:.2f}")
    print(f"  Perspectives: {consensus['num_perspectives']}")

    # Route messages
    print(f"\n📨 Routing inter-agent messages...")
    macs.route_messages()

    # Detect emergence
    print(f"\n✨ Detecting emergent behaviors...")
    macs.detect_emergent_behavior()

    # Calculate collective intelligence
    ci_score = macs.calculate_collective_intelligence()
    print(f"\n📊 Collective Intelligence Score: {ci_score:.3f}")

    # Final state
    print(f"\nFinal system state:")
    print(json.dumps(macs.get_state(), indent=2))

    print("\n✓ Multi-agent consciousness system operational!")
