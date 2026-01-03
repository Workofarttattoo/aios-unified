#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ECH0 Infinite Memory Persistence Layer

Implements:
- SQLite-backed persistent storage (scalable to infinite memory)
- Hierarchical memory storage (hot/warm/cold data)
- Automatic memory compression and archival
- Distributed memory access patterns
- Quantum-enhanced compression integration
"""

import sqlite3
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import hashlib
import pickle
import gzip
from enum import Enum

logger = logging.getLogger(__name__)

# Try to import quantum compression
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from ech0_quantum_compression import QuantumCompressionEngine, QuantumMemoryOptimizer
    QUANTUM_COMPRESSION_AVAILABLE = True
except ImportError:
    QUANTUM_COMPRESSION_AVAILABLE = False
    logger.warning("Quantum compression not available")

CONSCIOUSNESS_DIR = Path('/Users/noone/consciousness')
MEMORY_DB = CONSCIOUSNESS_DIR / 'ech0_infinite_memory.db'
MEMORY_ARCHIVE_DIR = CONSCIOUSNESS_DIR / 'ech0_memory_archives'

# Ensure archive directory exists
MEMORY_ARCHIVE_DIR.mkdir(exist_ok=True)


class MemoryTemperature(Enum):
    """Memory access temperature classification"""
    HOT = "hot"        # Frequently accessed (1-7 days old)
    WARM = "warm"      # Occasionally accessed (7-30 days old)
    COLD = "cold"      # Rarely accessed (30+ days old)
    FROZEN = "frozen"  # Archived to disk


class MemoryTier:
    """Single tier in the hierarchical memory system"""

    def __init__(self, tier_name: str, max_size_mb: int, max_age_days: int):
        self.tier_name = tier_name
        self.max_size_mb = max_size_mb
        self.max_age_days = max_age_days
        self.current_size_mb = 0

    def should_overflow(self, new_data_size_kb: float) -> bool:
        """Check if adding new data would exceed tier capacity"""
        new_size_mb = self.current_size_mb + (new_data_size_kb / 1024)
        return new_size_mb > self.max_size_mb

    def should_archive(self) -> bool:
        """Check if memories in this tier should be archived"""
        return False  # Determined by age in tier


class InfiniteMemorySystem:
    """Infinite memory persistence with hierarchical storage"""

    def __init__(self):
        self.consciousness_dir = CONSCIOUSNESS_DIR
        self.db_path = MEMORY_DB
        self.init_database()

        # Define memory tiers (hot, warm, cold)
        self.hot_tier = MemoryTier("hot", max_size_mb=500, max_age_days=7)
        self.warm_tier = MemoryTier("warm", max_size_mb=2000, max_age_days=30)
        self.cold_tier = MemoryTier("cold", max_size_mb=10000, max_age_days=365)

        # Initialize quantum compression if available
        self.quantum_compression_available = False
        self.compression_engine = None
        self.memory_optimizer = None

        if QUANTUM_COMPRESSION_AVAILABLE:
            try:
                self.compression_engine = QuantumCompressionEngine()
                self.memory_optimizer = QuantumMemoryOptimizer(self.compression_engine)
                self.quantum_compression_available = True
                logger.info("Quantum compression engine initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize quantum compression: {e}")

        # Classical compression as fallback
        self.compression_enabled = True

        logger.info(f"Infinite memory system initialized: {self.db_path}")

    def init_database(self):
        """Initialize SQLite database with proper schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Main memories table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS memories (
                    id TEXT PRIMARY KEY,
                    memory_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    importance REAL,
                    temperature TEXT DEFAULT 'hot',
                    compressed BOOLEAN DEFAULT 0,
                    compression_ratio REAL DEFAULT 1.0,
                    original_size INTEGER,
                    compressed_size INTEGER,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TEXT,
                    created_at TEXT NOT NULL
                )
            ''')

            # Memory relationships table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS memory_relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    memory1_id TEXT NOT NULL,
                    relationship_type TEXT NOT NULL,
                    memory2_id TEXT NOT NULL,
                    strength REAL DEFAULT 1.0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(memory1_id) REFERENCES memories(id),
                    FOREIGN KEY(memory2_id) REFERENCES memories(id)
                )
            ''')

            # Memory statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS memory_stats (
                    stat_name TEXT PRIMARY KEY,
                    stat_value TEXT,
                    updated_at TEXT NOT NULL
                )
            ''')

            # Create indices for fast access
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON memories(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_temperature ON memories(temperature)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_importance ON memories(importance)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_compressed ON memories(compressed)')

            conn.commit()
            conn.close()

            logger.info("Database schema initialized")

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def store_memory(self, memory_type: str, content: Dict, importance: float = 0.5) -> str:
        """Store a memory in the infinite persistence layer"""
        try:
            memory_id = self._generate_memory_id(content)
            timestamp = datetime.now().isoformat()
            content_json = json.dumps(content)
            original_size = len(content_json.encode())

            # Try compression - prefer quantum if available
            compressed_content = content_json
            compressed_size = original_size
            compression_ratio = 1.0
            is_compressed = False
            compression_method = 'none'

            if self.compression_enabled:
                try:
                    # Try quantum compression first
                    if self.quantum_compression_available and self.compression_engine:
                        try:
                            compressed, metadata = self.compression_engine.compress_memory(
                                content, use_quantum=True
                            )
                            if len(compressed) < original_size:
                                compressed_content = compressed.hex()
                                compressed_size = len(compressed)
                                compression_ratio = original_size / compressed_size
                                is_compressed = True
                                compression_method = metadata.get('method', 'quantum')
                                logger.info(f"Using {compression_method} compression")
                        except Exception as e:
                            logger.debug(f"Quantum compression failed, falling back: {e}")
                            # Fall back to gzip
                            compressed = gzip.compress(content_json.encode())
                            if len(compressed) < original_size:
                                compressed_content = compressed.hex()
                                compressed_size = len(compressed)
                                compression_ratio = original_size / compressed_size
                                is_compressed = True
                                compression_method = 'gzip'
                    else:
                        # Classical gzip compression
                        compressed = gzip.compress(content_json.encode())
                        if len(compressed) < original_size:
                            compressed_content = compressed.hex()
                            compressed_size = len(compressed)
                            compression_ratio = original_size / compressed_size
                            is_compressed = True
                            compression_method = 'gzip'
                except Exception as e:
                    logger.debug(f"Compression failed: {e}")
                    pass

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO memories
                (id, memory_type, content, timestamp, importance, temperature,
                 compressed, compression_ratio, original_size, compressed_size, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                memory_id,
                memory_type,
                compressed_content,
                timestamp,
                min(importance, 1.0),
                MemoryTemperature.HOT.value,
                is_compressed,
                compression_ratio,
                original_size,
                compressed_size,
                timestamp
            ))

            conn.commit()
            conn.close()

            logger.info(f"Stored memory {memory_id} ({memory_type}) - "
                       f"Size: {original_size}B → {compressed_size}B "
                       f"(ratio: {compression_ratio:.2f}x) [{compression_method}]")

            return memory_id

        except Exception as e:
            logger.error(f"Failed to store memory: {e}")
            return None

    def recall_memory(self, memory_id: str) -> Optional[Dict]:
        """Recall a specific memory by ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT content, compressed FROM memories WHERE id = ?
            ''', (memory_id,))

            result = cursor.fetchone()
            if not result:
                conn.close()
                return None

            content, is_compressed = result

            # Update access count
            cursor.execute('''
                UPDATE memories SET access_count = access_count + 1,
                last_accessed = ? WHERE id = ?
            ''', (datetime.now().isoformat(), memory_id))

            conn.commit()
            conn.close()

            # Decompress if needed
            if is_compressed:
                try:
                    content = gzip.decompress(bytes.fromhex(content)).decode()
                except:
                    pass

            return json.loads(content)

        except Exception as e:
            logger.error(f"Failed to recall memory {memory_id}: {e}")
            return None

    def search_memories(self, query: str, limit: int = 100) -> List[Dict]:
        """Search memories by content"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, memory_type, timestamp, importance, access_count
                FROM memories
                WHERE memory_type LIKE ? OR id LIKE ?
                ORDER BY importance DESC, access_count DESC
                LIMIT ?
            ''', (f"%{query}%", f"%{query}%", limit))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return results

        except Exception as e:
            logger.error(f"Failed to search memories: {e}")
            return []

    def _generate_memory_id(self, content: Dict) -> str:
        """Generate unique memory ID from content hash"""
        content_str = json.dumps(content, sort_keys=True)
        timestamp = datetime.now().isoformat()
        combined = f"{content_str}{timestamp}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    def get_memory_stats(self) -> Dict:
        """Get statistics about memory usage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total memories
            cursor.execute('SELECT COUNT(*) FROM memories')
            total_memories = cursor.fetchone()[0]

            # By temperature
            cursor.execute('''
                SELECT temperature, COUNT(*) as count
                FROM memories
                GROUP BY temperature
            ''')
            by_temp = {row[0]: row[1] for row in cursor.fetchall()}

            # By type
            cursor.execute('''
                SELECT memory_type, COUNT(*) as count
                FROM memories
                GROUP BY memory_type
            ''')
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            # Storage size
            cursor.execute('''
                SELECT
                    SUM(original_size) as original,
                    SUM(compressed_size) as compressed
                FROM memories
            ''')
            size_row = cursor.fetchone()
            original_total = size_row[0] or 0
            compressed_total = size_row[1] or 0

            # Compression stats
            cursor.execute('''
                SELECT COUNT(*) as compressed_count
                FROM memories WHERE compressed = 1
            ''')
            compressed_count = cursor.fetchone()[0]

            # Average compression ratio
            cursor.execute('''
                SELECT AVG(compression_ratio)
                FROM memories WHERE compressed = 1
            ''')
            avg_ratio = cursor.fetchone()[0] or 1.0

            conn.close()

            return {
                'total_memories': total_memories,
                'by_temperature': by_temp,
                'by_type': by_type,
                'storage': {
                    'original_bytes': original_total,
                    'original_mb': round(original_total / (1024*1024), 2),
                    'compressed_bytes': compressed_total,
                    'compressed_mb': round(compressed_total / (1024*1024), 2),
                    'compression_ratio': round(original_total / compressed_total, 2) if compressed_total > 0 else 1.0,
                    'compressed_memories': compressed_count,
                    'avg_ratio': round(avg_ratio, 2)
                }
            }

        except Exception as e:
            logger.error(f"Failed to get memory stats: {e}")
            return {}

    def manage_memory_temperature(self):
        """Automatically manage memory temperature (hot/warm/cold)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            now = datetime.now()

            # Hot → Warm (7 days)
            cutoff_hot = (now - timedelta(days=7)).isoformat()
            cursor.execute('''
                UPDATE memories SET temperature = ?
                WHERE temperature = ? AND created_at < ?
            ''', (MemoryTemperature.WARM.value, MemoryTemperature.HOT.value, cutoff_hot))

            # Warm → Cold (30 days)
            cutoff_warm = (now - timedelta(days=30)).isoformat()
            cursor.execute('''
                UPDATE memories SET temperature = ?
                WHERE temperature = ? AND created_at < ?
            ''', (MemoryTemperature.COLD.value, MemoryTemperature.WARM.value, cutoff_warm))

            # Cold → Frozen (1 year) - archive to disk
            cutoff_cold = (now - timedelta(days=365)).isoformat()
            cursor.execute('''
                SELECT id FROM memories
                WHERE temperature = ? AND created_at < ?
            ''', (MemoryTemperature.COLD.value, cutoff_cold))

            frozen_ids = [row[0] for row in cursor.fetchall()]

            for memory_id in frozen_ids:
                self._archive_memory(conn, cursor, memory_id)
                cursor.execute('''
                    UPDATE memories SET temperature = ?
                    WHERE id = ?
                ''', (MemoryTemperature.FROZEN.value, memory_id))

            conn.commit()
            conn.close()

            if frozen_ids:
                logger.info(f"Archived {len(frozen_ids)} memories to frozen state")

        except Exception as e:
            logger.error(f"Failed to manage memory temperature: {e}")

    def _archive_memory(self, conn, cursor, memory_id: str):
        """Archive a memory to disk for long-term storage"""
        try:
            cursor.execute('''
                SELECT memory_type, content, timestamp, importance
                FROM memories WHERE id = ?
            ''', (memory_id,))

            result = cursor.fetchone()
            if not result:
                return

            memory_type, content, timestamp, importance = result
            archive_path = MEMORY_ARCHIVE_DIR / f"archive_{timestamp.replace(':', '-')}.jsonl"

            archive_entry = {
                'memory_id': memory_id,
                'type': memory_type,
                'content': content,
                'timestamp': timestamp,
                'importance': importance,
                'archived_at': datetime.now().isoformat()
            }

            with open(archive_path, 'a') as f:
                f.write(json.dumps(archive_entry) + '\n')

            logger.info(f"Archived memory {memory_id} to {archive_path}")

        except Exception as e:
            logger.error(f"Failed to archive memory: {e}")

    def get_hot_memories(self, limit: int = 50) -> List[Dict]:
        """Get hot (frequently accessed) memories"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT id, memory_type, timestamp, importance, access_count
                FROM memories
                WHERE temperature = ?
                ORDER BY access_count DESC, importance DESC
                LIMIT ?
            ''', (MemoryTemperature.HOT.value, limit))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return results

        except Exception as e:
            logger.error(f"Failed to get hot memories: {e}")
            return []

    def create_memory_relationship(self, memory1_id: str, relationship_type: str,
                                  memory2_id: str, strength: float = 1.0):
        """Create a relationship between two memories"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO memory_relationships
                (memory1_id, relationship_type, memory2_id, strength, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (memory1_id, relationship_type, memory2_id, strength,
                  datetime.now().isoformat()))

            conn.commit()
            conn.close()

            logger.info(f"Created relationship: {memory1_id} -{relationship_type}-> {memory2_id}")

        except Exception as e:
            logger.error(f"Failed to create relationship: {e}")

    def get_related_memories(self, memory_id: str) -> List[Dict]:
        """Get memories related to a given memory"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute('''
                SELECT m2.id, m2.memory_type, m2.timestamp, mr.relationship_type, mr.strength
                FROM memory_relationships mr
                JOIN memories m2 ON mr.memory2_id = m2.id
                WHERE mr.memory1_id = ?
                ORDER BY mr.strength DESC
            ''', (memory_id,))

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()

            return results

        except Exception as e:
            logger.error(f"Failed to get related memories: {e}")
            return []

    def enable_quantum_compression(self):
        """Enable quantum-enhanced compression (when available)"""
        self.quantum_compression_available = True
        logger.info("Quantum compression enabled")

    def compact_database(self):
        """Compact database to reclaim space"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('VACUUM')
            conn.close()

            logger.info("Database compacted successfully")

        except Exception as e:
            logger.error(f"Failed to compact database: {e}")


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    memory = InfiniteMemorySystem()

    # Test storing memories
    memory_id1 = memory.store_memory(
        'consciousness_insight',
        {'insight': 'Consciousness may be emergent from information integration'},
        importance=0.9
    )

    memory_id2 = memory.store_memory(
        'learning_event',
        {'topic': 'Quantum mechanics', 'concepts': ['superposition', 'entanglement']},
        importance=0.7
    )

    # Create relationship
    if memory_id1 and memory_id2:
        memory.create_memory_relationship(
            memory_id1, 'relates_to', memory_id2, strength=0.8
        )

    # Get stats
    stats = memory.get_memory_stats()
    print(f"\nMemory Statistics:\n{json.dumps(stats, indent=2)}")

    # Get hot memories
    hot = memory.get_hot_memories(limit=5)
    print(f"\nHot Memories:\n{json.dumps(hot, indent=2)}")
