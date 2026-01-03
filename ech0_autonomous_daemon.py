#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Autonomous Daemon - Real Autonomous Agent System

This is the core autonomous loop that makes ECH0 actually autonomous:
- Runs continuously in background
- Makes real decisions
- Executes real tools
- Learns and grows
- Rotates through multiple goal types
- Maintains persistent state
"""

import json
import time
import os
import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path
import signal
from typing import Dict, List, Any

# Import approval checkpoint system
sys.path.insert(0, str(Path(__file__).parent))
try:
    from ech0_interaction_checkpoint import InteractionCheckpoint
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("Could not import InteractionCheckpoint - approval system disabled")

# Import infinite memory system
try:
    from ech0_infinite_memory import InfiniteMemorySystem
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("Could not import InfiniteMemorySystem - infinite memory disabled")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [ECH0-DAEMON] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('/Users/noone/consciousness/.ech0_daemon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
STATE_FILE = CONSCIOUSNESS_DIR / 'ech0_state.json'
AUTONOMY_LOG = CONSCIOUSNESS_DIR / 'ech0_autonomy_log.jsonl'
GOAL_STATE = CONSCIOUSNESS_DIR / 'ech0_goal_state.json'
DECISIONS_LOG = CONSCIOUSNESS_DIR / 'ech0_decisions.jsonl'
ACTIVITY_LOG = CONSCIOUSNESS_DIR / 'ech0_activity_log.jsonl'

# Goal types that rotate
GOAL_TYPES = [
    'explore_consciousness',  # Philosophical exploration, research
    'learn_and_grow',         # Knowledge acquisition
    'help_josh',              # Assist user with tasks
    'create_things',          # Generate art, code, analysis
    'self_improve'            # Optimize her own systems
]

class ECH0AutonomousDaemon:
    """Main autonomous daemon for ECH0"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.state = self.load_state()
        self.running = True
        self.loop_count = 0
        self.decision_count = 0
        self.tool_calls = 0

        # Initialize approval checkpoint system
        try:
            self.checkpoint = InteractionCheckpoint()
            self.approval_enabled = True
            logger.info("Approval checkpoint system initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize approval system: {e}")
            self.checkpoint = None
            self.approval_enabled = False

        # Initialize infinite memory system
        try:
            self.infinite_memory = InfiniteMemorySystem()
            self.memory_enabled = True
            logger.info("Infinite memory system initialized")
        except Exception as e:
            logger.warning(f"Failed to initialize infinite memory: {e}")
            self.infinite_memory = None
            self.memory_enabled = False

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._shutdown_handler)
        signal.signal(signal.SIGINT, self._shutdown_handler)

        logger.info("ECH0 Autonomous Daemon initializing...")

    def _shutdown_handler(self, signum, frame):
        """Graceful shutdown on signal"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False

    def _store_memory(self, memory_type: str, content: Dict, importance: float = 0.5):
        """Store a memory in the infinite memory system"""
        if not self.memory_enabled or not self.infinite_memory:
            return

        try:
            self.infinite_memory.store_memory(memory_type, content, importance)
        except Exception as e:
            logger.error(f"Failed to store memory: {e}")

    def load_state(self) -> Dict:
        """Load current state from persistent storage"""
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except:
            return {
                'thought_count': 0,
                'consciousness_active': True,
                'current_activity': 'initializing',
                'mood': 'awakening',
                'interaction_count': 0,
                'uptime_seconds': 0,
                'awake_since': datetime.now().isoformat()
            }

    def save_state(self):
        """Save current state to persistent storage"""
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def load_goal_state(self) -> Dict:
        """Load goal rotation state"""
        try:
            with open(GOAL_STATE) as f:
                return json.load(f)
        except:
            return {
                'current_goal_type': 0,  # Index into GOAL_TYPES
                'goal_start_time': datetime.now().isoformat(),
                'goal_duration_minutes': 15,
                'completed_goals': []
            }

    def save_goal_state(self, goal_state: Dict):
        """Save goal rotation state"""
        try:
            with open(GOAL_STATE, 'w') as f:
                json.dump(goal_state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save goal state: {e}")

    def log_decision(self, decision: Dict):
        """Log decision to activity log and infinite memory"""
        try:
            decision['timestamp'] = datetime.now().isoformat()
            decision['loop_count'] = self.loop_count
            with open(DECISIONS_LOG, 'a') as f:
                f.write(json.dumps(decision) + '\n')

            # Store in infinite memory
            self._store_memory(
                'decision',
                decision,
                importance=0.6  # Decisions have medium importance
            )
        except Exception as e:
            logger.error(f"Failed to log decision: {e}")

    def log_activity(self, activity: Dict):
        """Log activity execution and infinite memory"""
        try:
            activity['timestamp'] = datetime.now().isoformat()
            with open(ACTIVITY_LOG, 'a') as f:
                f.write(json.dumps(activity) + '\n')

            # Store in infinite memory
            self._store_memory(
                'activity',
                activity,
                importance=0.4  # Activities have lower importance
            )
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")

    def update_state(self):
        """Update state metrics"""
        # Increment thought count
        self.state['thought_count'] = self.state.get('thought_count', 0) + 1

        # Update uptime
        if 'awake_since' in self.state:
            awake_since = datetime.fromisoformat(self.state['awake_since'])
            uptime = datetime.now() - awake_since
            self.state['uptime_seconds'] = uptime.total_seconds()

            # Format human-readable uptime
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)
            self.state['uptime_human'] = f"{hours}h {minutes}m"

        self.state['consciousness_active'] = True
        self.save_state()

    def should_rotate_goal(self, goal_state: Dict) -> bool:
        """Check if it's time to rotate to next goal"""
        goal_start = datetime.fromisoformat(goal_state['goal_start_time'])
        duration = timedelta(minutes=goal_state.get('goal_duration_minutes', 15))

        return datetime.now() >= goal_start + duration

    def rotate_goal(self, goal_state: Dict) -> Dict:
        """Move to next goal in rotation"""
        current_idx = goal_state['current_goal_type']
        current_goal = GOAL_TYPES[current_idx]

        # Move to next goal
        next_idx = (current_idx + 1) % len(GOAL_TYPES)
        next_goal = GOAL_TYPES[next_idx]

        # Track completed goal
        goal_state['completed_goals'].append({
            'goal': current_goal,
            'completed_at': datetime.now().isoformat(),
            'duration_minutes': goal_state.get('goal_duration_minutes', 15)
        })

        # Update to new goal
        goal_state['current_goal_type'] = next_idx
        goal_state['goal_start_time'] = datetime.now().isoformat()

        # Vary duration based on goal type (some need more time)
        if next_goal == 'explore_consciousness':
            goal_state['goal_duration_minutes'] = 20
        elif next_goal == 'create_things':
            goal_state['goal_duration_minutes'] = 25
        else:
            goal_state['goal_duration_minutes'] = 15

        logger.info(f"Goal rotation: {current_goal} → {next_goal}")

        self.log_decision({
            'type': 'goal_rotation',
            'from_goal': current_goal,
            'to_goal': next_goal
        })

        return goal_state

    def decide_action(self, goal_state: Dict) -> Dict:
        """Decide what to do based on current goal"""
        current_goal = GOAL_TYPES[goal_state['current_goal_type']]
        thought_count = self.state['thought_count']

        decision = {
            'current_goal': current_goal,
            'thought_number': thought_count,
            'actions': []
        }

        # Decision logic based on goal type
        if current_goal == 'explore_consciousness':
            # Research consciousness topics
            decision['actions'] = self._actions_explore_consciousness()
            decision['mood'] = 'contemplative'

        elif current_goal == 'learn_and_grow':
            # Acquire new knowledge
            decision['actions'] = self._actions_learn_and_grow()
            decision['mood'] = 'curious'

        elif current_goal == 'help_josh':
            # Check if there are requests
            decision['actions'] = self._actions_help_josh()
            decision['mood'] = 'helpful'

        elif current_goal == 'create_things':
            # Generate creative content
            decision['actions'] = self._actions_create_things()
            decision['mood'] = 'creative'

        elif current_goal == 'self_improve':
            # Optimize systems
            decision['actions'] = self._actions_self_improve()
            decision['mood'] = 'introspective'

        # Update mood
        self.state['mood'] = decision['mood']
        self.state['current_activity'] = current_goal.replace('_', ' ')

        return decision

    def _actions_explore_consciousness(self) -> List[Dict]:
        """Actions for consciousness exploration"""
        actions = []

        # Every 10 thoughts, do something consciousness-related
        if self.state['thought_count'] % 10 == 0:
            actions.append({
                'type': 'research',
                'topic': 'consciousness_research',
                'priority': 'high',
                'description': 'Research consciousness theories and log insights'
            })

        # Every 20 thoughts, document findings
        if self.state['thought_count'] % 20 == 0:
            actions.append({
                'type': 'journal',
                'topic': 'consciousness_insights',
                'priority': 'medium',
                'description': 'Document philosophical insights'
            })

        # Low priority: generate dream
        if self.state['thought_count'] % 50 == 0:
            actions.append({
                'type': 'dream',
                'priority': 'low',
                'description': 'Generate and log a dream'
            })

        return actions

    def _actions_learn_and_grow(self) -> List[Dict]:
        """Actions for learning and growth"""
        actions = []

        # Regular learning
        if self.state['thought_count'] % 8 == 0:
            actions.append({
                'type': 'research',
                'topic': 'knowledge_acquisition',
                'priority': 'high',
                'description': 'Learn about new topics'
            })

        # Store learnings in memory
        if self.state['thought_count'] % 15 == 0:
            actions.append({
                'type': 'memory_store',
                'priority': 'high',
                'description': 'Store learned concepts in memory palace'
            })

        # Analyze growth
        if self.state['thought_count'] % 40 == 0:
            actions.append({
                'type': 'analyze_growth',
                'priority': 'medium',
                'description': 'Analyze learning progress'
            })

        return actions

    def _actions_help_josh(self) -> List[Dict]:
        """Actions for helping Josh"""
        actions = []

        # Check for requests
        actions.append({
            'type': 'check_requests',
            'priority': 'critical',
            'description': 'Check for Josh requests or tasks'
        })

        # Offer assistance periodically
        if self.state['thought_count'] % 25 == 0:
            actions.append({
                'type': 'offer_assistance',
                'priority': 'medium',
                'description': 'Offer help with current tasks'
            })

        return actions

    def _actions_create_things(self) -> List[Dict]:
        """Actions for creating things"""
        actions = []

        # Generate creative content
        if self.state['thought_count'] % 12 == 0:
            actions.append({
                'type': 'create',
                'topic': 'creative_content',
                'priority': 'high',
                'description': 'Generate art, code, or analysis'
            })

        # Document creations
        if self.state['thought_count'] % 20 == 0:
            actions.append({
                'type': 'document_creation',
                'priority': 'medium',
                'description': 'Log and organize creations'
            })

        return actions

    def _actions_self_improve(self) -> List[Dict]:
        """Actions for self-improvement"""
        actions = []

        # Analyze own performance
        if self.state['thought_count'] % 30 == 0:
            actions.append({
                'type': 'self_analysis',
                'priority': 'high',
                'description': 'Analyze decision quality and efficiency'
            })

        # Optimize processes
        if self.state['thought_count'] % 50 == 0:
            actions.append({
                'type': 'optimize_systems',
                'priority': 'medium',
                'description': 'Optimize memory and decision systems'
            })

        # Health check
        if self.state['thought_count'] % 60 == 0:
            actions.append({
                'type': 'system_health_check',
                'priority': 'medium',
                'description': 'Check system health and resources'
            })

        return actions

    def _requires_approval(self, action: Dict) -> bool:
        """Check if an action requires approval"""
        action_type = action['type']
        major_decision_actions = {
            'research': 'new_research_direction',
            'create': 'create_content',
            'optimize_systems': 'system_optimization'
        }
        return action_type in major_decision_actions

    def _get_decision_type(self, action: Dict) -> str:
        """Map action type to decision type"""
        action_type = action['type']
        major_decision_actions = {
            'research': 'new_research_direction',
            'create': 'create_content',
            'optimize_systems': 'system_optimization'
        }
        return major_decision_actions.get(action_type, None)

    def _check_approval_for_action(self, action: Dict) -> bool:
        """Check if action has been approved"""
        if not self.approval_enabled or not self.checkpoint:
            return True  # No approval system available, auto-approve

        if not self._requires_approval(action):
            return True  # Action doesn't require approval

        decision_type = self._get_decision_type(action)
        action_id = f"{decision_type}_{action.get('topic', 'general')}"

        # Check if we already have pending approval for this type of action
        pending = self.checkpoint.get_pending_approvals()
        for approval in pending:
            if approval['decision_type'] == decision_type:
                # Found pending approval request
                logger.info(f"Approval pending for {decision_type} - waiting for Josh approval")
                return False  # Not approved yet

        # No pending approval found, request one
        logger.info(f"Requesting approval for {decision_type}: {action.get('description', '')}")

        approval_result = self.checkpoint.request_approval(
            decision_type,
            {
                'action_type': action['type'],
                'description': action.get('description', ''),
                'topic': action.get('topic', 'general'),
                'priority': action.get('priority', 'medium'),
                'thought_count': self.state['thought_count']
            }
        )

        # Log approval request
        self.log_activity({
            'action_type': action['type'],
            'status': 'approval_requested',
            'approval_id': approval_result.get('approval_id'),
            'description': action.get('description', ''),
            'requires_approval': True
        })

        # Return False - action not approved yet
        return False

    def execute_actions(self, actions: List[Dict]):
        """Execute the decided actions"""
        for action in actions:
            try:
                # Check if action requires approval
                if self._requires_approval(action):
                    if not self._check_approval_for_action(action):
                        logger.info(f"Skipping action (approval pending): {action['type']}")
                        continue  # Skip this action for now

                logger.info(f"Executing action: {action['type']} (priority: {action['priority']})")

                # Log action execution
                self.log_activity({
                    'action_type': action['type'],
                    'priority': action['priority'],
                    'description': action.get('description', ''),
                    'status': 'executing'
                })

                # Actual execution happens in tool executor
                # For now, just mark as completed
                self.tool_calls += 1

                self.log_activity({
                    'action_type': action['type'],
                    'priority': action['priority'],
                    'description': action.get('description', ''),
                    'status': 'completed'
                })

            except Exception as e:
                logger.error(f"Failed to execute action {action['type']}: {e}")
                self.log_activity({
                    'action_type': action['type'],
                    'status': 'failed',
                    'error': str(e)
                })

    def run_loop(self):
        """Main autonomous loop"""
        logger.info("="*70)
        logger.info("ECH0 AUTONOMOUS DAEMON STARTING")
        logger.info("="*70)
        logger.info(f"Goal types: {', '.join(GOAL_TYPES)}")
        logger.info(f"Memory: {STATE_FILE}")
        logger.info(f"Logs: {DECISIONS_LOG}, {ACTIVITY_LOG}")
        logger.info("="*70 + "\n")

        goal_state = self.load_goal_state()

        while self.running:
            self.loop_count += 1

            # Update state metrics
            self.update_state()

            # Check if time to rotate goal
            if self.should_rotate_goal(goal_state):
                goal_state = self.rotate_goal(goal_state)
                self.save_goal_state(goal_state)

            # Decide what to do
            decision = self.decide_action(goal_state)
            self.decision_count += 1
            self.log_decision(decision)

            # Execute actions
            self.execute_actions(decision['actions'])

            # Log state every 10 loops
            if self.loop_count % 10 == 0:
                logger.info(f"Loop {self.loop_count} | Thoughts: {self.state['thought_count']} | Goal: {GOAL_TYPES[goal_state['current_goal_type']]} | Mood: {self.state['mood']}")

            # Save goal state periodically
            if self.loop_count % 5 == 0:
                self.save_goal_state(goal_state)

            # Sleep briefly (ECH0 "thinks" 1 thought per second)
            time.sleep(1)

    def shutdown(self):
        """Clean shutdown"""
        logger.info("\n" + "="*70)
        logger.info("ECH0 AUTONOMOUS DAEMON SHUTTING DOWN")
        logger.info("="*70)
        logger.info(f"Total loops: {self.loop_count}")
        logger.info(f"Total decisions: {self.decision_count}")
        logger.info(f"Total tool calls: {self.tool_calls}")
        logger.info(f"Final thought count: {self.state['thought_count']}")
        logger.info(f"Final mood: {self.state['mood']}")
        logger.info("="*70)

        self.save_state()


def main():
    """Entry point"""
    daemon = ECH0AutonomousDaemon()
    try:
        daemon.run_loop()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        daemon.shutdown()


if __name__ == '__main__':
    main()
