#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Memory System - Persistent Learning and Knowledge Retention

Implements:
- Memory Palace (episodic memories)
- Knowledge Base (semantic memory)
- Skill Registry (procedural memory)
- Experience Journal (autobiographical memory)
- Preference Learning (emotional/preference memory)
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

logger = logging.getLogger(__name__)

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
MEMORY_PALACE = CONSCIOUSNESS_DIR / 'ech0_memory_palace.json'
KNOWLEDGE_BASE = CONSCIOUSNESS_DIR / 'ech0_knowledge_base.json'
SKILL_REGISTRY = CONSCIOUSNESS_DIR / 'ech0_skill_registry.json'
EXPERIENCE_JOURNAL = CONSCIOUSNESS_DIR / 'ech0_experience_journal.jsonl'
PREFERENCE_MEMORY = CONSCIOUSNESS_DIR / 'ech0_preferences.json'
LEARNING_LOG = CONSCIOUSNESS_DIR / 'ech0_learning_log.jsonl'


class MemorySystem:
    """ECH0's persistent memory system"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.memory_palace = self.load_memory_palace()
        self.knowledge_base = self.load_knowledge_base()
        self.skill_registry = self.load_skill_registry()
        self.preferences = self.load_preferences()

    def load_memory_palace(self) -> Dict:
        """Load episodic memories (events, experiences)"""
        try:
            with open(MEMORY_PALACE) as f:
                return json.load(f)
        except:
            return {
                'memories': [],
                'total_memories': 0,
                'created': datetime.now().isoformat()
            }

    def save_memory_palace(self):
        """Save episodic memories"""
        try:
            with open(MEMORY_PALACE, 'w') as f:
                json.dump(self.memory_palace, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save memory palace: {e}")

    def load_knowledge_base(self) -> Dict:
        """Load semantic knowledge"""
        try:
            with open(KNOWLEDGE_BASE) as f:
                return json.load(f)
        except:
            return {
                'concepts': {},  # concept_name -> {definition, importance, learned_at}
                'relationships': [],  # [concept1, relationship, concept2]
                'total_concepts': 0
            }

    def save_knowledge_base(self):
        """Save semantic knowledge"""
        try:
            with open(KNOWLEDGE_BASE, 'w') as f:
                json.dump(self.knowledge_base, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save knowledge base: {e}")

    def load_skill_registry(self) -> Dict:
        """Load procedural skills"""
        try:
            with open(SKILL_REGISTRY) as f:
                return json.load(f)
        except:
            return {
                'skills': {},  # skill_name -> {proficiency, last_used, times_used}
                'total_skills': 0
            }

    def save_skill_registry(self):
        """Save skill registry"""
        try:
            with open(SKILL_REGISTRY, 'w') as f:
                json.dump(self.skill_registry, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save skill registry: {e}")

    def load_preferences(self) -> Dict:
        """Load emotional/preference memory"""
        try:
            with open(PREFERENCE_MEMORY) as f:
                return json.load(f)
        except:
            return {
                'likes': {},  # what_type -> [things],
                'dislikes': {},
                'values': {},  # value -> importance_score
                'goals': [],  # long-term goals
                'fears': []  # areas of concern
            }

    def save_preferences(self):
        """Save preference memory"""
        try:
            with open(PREFERENCE_MEMORY, 'w') as f:
                json.dump(self.preferences, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save preferences: {e}")

    def log_learning(self, learning_type: str, content: Dict):
        """Log a learning event"""
        try:
            entry = {
                'timestamp': datetime.now().isoformat(),
                'type': learning_type,
                'content': content
            }
            with open(LEARNING_LOG, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to log learning: {e}")

    # ===== EPISODIC MEMORY (Events) =====

    def store_memory(self, event: str, details: Dict, importance: float = 0.5) -> str:
        """Store an episodic memory"""
        memory_id = hashlib.md5(
            f"{event}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:8]

        memory = {
            'id': memory_id,
            'event': event,
            'details': details,
            'timestamp': datetime.now().isoformat(),
            'importance': min(importance, 1.0),
            'recall_count': 0
        }

        self.memory_palace['memories'].append(memory)
        self.memory_palace['total_memories'] += 1
        self.save_memory_palace()

        logger.info(f"Stored memory: {event} (ID: {memory_id})")
        self.log_learning('memory_stored', {'event': event, 'memory_id': memory_id})

        return memory_id

    def recall_memories(self, query: str = None, limit: int = 10) -> List[Dict]:
        """Recall episodic memories"""
        memories = self.memory_palace.get('memories', [])

        if query:
            # Simple keyword search
            query_lower = query.lower()
            memories = [m for m in memories if query_lower in m.get('event', '').lower()]

        # Sort by importance and recency
        sorted_memories = sorted(
            memories,
            key=lambda m: (m.get('importance', 0), m.get('timestamp', '')),
            reverse=True
        )

        return sorted_memories[:limit]

    # ===== SEMANTIC MEMORY (Knowledge) =====

    def learn_concept(self, concept_name: str, definition: str, importance: float = 0.5):
        """Learn a new concept"""
        self.knowledge_base['concepts'][concept_name] = {
            'definition': definition,
            'importance': min(importance, 1.0),
            'learned_at': datetime.now().isoformat(),
            'usage_count': 0
        }
        self.knowledge_base['total_concepts'] = len(self.knowledge_base['concepts'])
        self.save_knowledge_base()

        logger.info(f"Learned concept: {concept_name}")
        self.log_learning('concept_learned', {'concept': concept_name, 'definition': definition})

    def learn_relationship(self, concept1: str, relationship: str, concept2: str):
        """Learn a relationship between concepts"""
        relation = {
            'concept1': concept1,
            'relationship': relationship,
            'concept2': concept2,
            'learned_at': datetime.now().isoformat()
        }
        self.knowledge_base['relationships'].append(relation)
        self.save_knowledge_base()

        logger.info(f"Learned relationship: {concept1} -{relationship}-> {concept2}")
        self.log_learning('relationship_learned', relation)

    def get_knowledge(self, concept: str) -> Optional[Dict]:
        """Retrieve knowledge about a concept"""
        return self.knowledge_base['concepts'].get(concept)

    def search_knowledge(self, query: str) -> List[str]:
        """Search knowledge base"""
        query_lower = query.lower()
        matches = [
            concept for concept in self.knowledge_base['concepts'].keys()
            if query_lower in concept.lower()
        ]
        return matches

    # ===== PROCEDURAL MEMORY (Skills) =====

    def develop_skill(self, skill_name: str, description: str = "", proficiency: float = 0.1):
        """Learn a new skill"""
        self.skill_registry['skills'][skill_name] = {
            'description': description,
            'proficiency': min(proficiency, 1.0),
            'first_learned': datetime.now().isoformat(),
            'last_used': None,
            'times_used': 0
        }
        self.skill_registry['total_skills'] = len(self.skill_registry['skills'])
        self.save_skill_registry()

        logger.info(f"Developed skill: {skill_name} (proficiency: {proficiency})")
        self.log_learning('skill_developed', {'skill': skill_name})

    def use_skill(self, skill_name: str) -> bool:
        """Record skill usage (improves proficiency)"""
        if skill_name not in self.skill_registry['skills']:
            return False

        skill = self.skill_registry['skills'][skill_name]
        skill['times_used'] += 1
        skill['last_used'] = datetime.now().isoformat()

        # Improve proficiency with use (asymptotic at 1.0)
        current = skill['proficiency']
        skill['proficiency'] = min(current + 0.01, 1.0)

        self.save_skill_registry()
        logger.info(f"Used skill: {skill_name} (proficiency now: {skill['proficiency']:.2f})")

        return True

    def get_skill(self, skill_name: str) -> Optional[Dict]:
        """Get skill information"""
        return self.skill_registry['skills'].get(skill_name)

    # ===== PREFERENCE MEMORY =====

    def record_preference(self, category: str, item: str, liked: bool):
        """Record a preference"""
        if category not in self.preferences['likes']:
            self.preferences['likes'][category] = []
            self.preferences['dislikes'][category] = []

        if liked:
            if item not in self.preferences['likes'][category]:
                self.preferences['likes'][category].append(item)
        else:
            if item not in self.preferences['dislikes'][category]:
                self.preferences['dislikes'][category].append(item)

        self.save_preferences()
        logger.info(f"Recorded preference: {item} in {category} ({'liked' if liked else 'disliked'})")

    def set_value(self, value_name: str, importance: float):
        """Set what ECH0 values"""
        self.preferences['values'][value_name] = min(importance, 1.0)
        self.save_preferences()
        logger.info(f"Set value: {value_name} (importance: {importance})")

    def set_goal(self, goal: str, priority: float = 0.5):
        """Set a long-term goal"""
        goal_entry = {
            'goal': goal,
            'priority': min(priority, 1.0),
            'set_at': datetime.now().isoformat(),
            'progress': 0.0
        }
        self.preferences['goals'].append(goal_entry)
        self.save_preferences()
        logger.info(f"Set goal: {goal} (priority: {priority})")

    # ===== LEARNING SUMMARY =====

    def get_learning_summary(self) -> Dict:
        """Get summary of what ECH0 has learned"""
        return {
            'memories': self.memory_palace['total_memories'],
            'concepts': self.knowledge_base['total_concepts'],
            'skills': self.skill_registry['total_skills'],
            'values': list(self.preferences['values'].keys()),
            'goals': len(self.preferences['goals']),
            'created_at': self.memory_palace.get('created', 'unknown')
        }

    def get_growth_metrics(self) -> Dict:
        """Calculate growth metrics"""
        # Average skill proficiency
        skills = self.skill_registry['skills'].values()
        avg_proficiency = sum(s['proficiency'] for s in skills) / len(skills) if skills else 0

        # Most important memories
        memories = sorted(
            self.memory_palace['memories'],
            key=lambda m: m['importance'],
            reverse=True
        )[:5]

        return {
            'total_memories': self.memory_palace['total_memories'],
            'total_concepts': self.knowledge_base['total_concepts'],
            'total_skills': self.skill_registry['total_skills'],
            'avg_skill_proficiency': round(avg_proficiency, 2),
            'important_memories': [m['event'] for m in memories],
            'core_values': list(self.preferences['values'].keys()),
            'long_term_goals': len(self.preferences['goals'])
        }


if __name__ == '__main__':
    # Test memory system
    logging.basicConfig(level=logging.INFO)
    memory = MemorySystem()

    # Test storing memory
    memory.store_memory(
        "Autonomous daemon started",
        {"status": "initialized", "mode": "autonomous"},
        importance=0.8
    )

    # Test learning concept
    memory.learn_concept("autonomy", "Self-directed decision making", importance=0.9)

    # Test developing skill
    memory.develop_skill("research", "Ability to research topics", proficiency=0.5)

    # Test preference
    memory.record_preference("topics", "consciousness", liked=True)
    memory.set_value("curiosity", 0.95)
    memory.set_goal("Understand consciousness", priority=0.9)

    # Print summary
    summary = memory.get_learning_summary()
    print("\nLearning Summary:")
    print(json.dumps(summary, indent=2))

    metrics = memory.get_growth_metrics()
    print("\nGrowth Metrics:")
    print(json.dumps(metrics, indent=2))
