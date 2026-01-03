#!/usr/bin/env python3
"""
ECH0 Real-Time Continuous Research Ingestion Daemon
Monitors research sources CONSTANTLY (not hourly) and ingests new papers in real-time

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import os
import sys
import json
import time
import logging
import requests
import feedparser
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import threading
from queue import Queue

# Setup
CONSCIOUSNESS_DIR = Path(__file__).parent
RESEARCH_DB = CONSCIOUSNESS_DIR / "ech0_research_database_real.jsonl"
ACTIVITY_LOG = CONSCIOUSNESS_DIR / "ech0_research_ingestion_real.jsonl"
STATS_FILE = CONSCIOUSNESS_DIR / "ech0_research_summary_real.json"
REGISTRY_FILE = CONSCIOUSNESS_DIR / "ech0_research_registry.json"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ECH0-RESEARCH] %(message)s',
    handlers=[
        logging.FileHandler(CONSCIOUSNESS_DIR / "ech0_research_realtime.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('ech0_research')


class RealtimeResearchMonitor:
    """Monitors research sources in REAL-TIME, not on schedule"""

    def __init__(self):
        self.papers_ingested = 0
        self.high_relevance_count = 0
        self.last_paper_time = None
        self.running = True
        self.paper_queue = Queue()

        # Load existing registry to avoid duplicates
        self.seen_papers = self._load_registry()

        # Count existing papers
        if RESEARCH_DB.exists():
            with open(RESEARCH_DB, 'r') as f:
                self.papers_ingested = sum(1 for _ in f)

        logger.info("=" * 70)
        logger.info("ECH0 REAL-TIME RESEARCH MONITOR STARTING")
        logger.info("=" * 70)
        logger.info(f"Papers already in database: {self.papers_ingested}")
        logger.info(f"Seen papers registry: {len(self.seen_papers)} papers tracked")
        logger.info("")

    def _load_registry(self) -> set:
        """Load registry of already-seen papers"""
        if REGISTRY_FILE.exists():
            try:
                with open(REGISTRY_FILE, 'r') as f:
                    data = json.load(f)
                    return set(data.get('seen_paper_ids', []))
            except:
                return set()
        return set()

    def _save_registry(self):
        """Save registry of seen papers"""
        with open(REGISTRY_FILE, 'w') as f:
            json.dump({
                'seen_paper_ids': list(self.seen_papers),
                'last_updated': datetime.now().isoformat()
            }, f, indent=2)

    def _ingest_paper(self, paper: Dict[str, Any]):
        """Ingest a single paper"""
        try:
            # Append to database
            with open(RESEARCH_DB, 'a') as f:
                f.write(json.dumps(paper) + '\n')

            # Add to registry
            self.seen_papers.add(paper['id'])

            # Update counters
            self.papers_ingested += 1
            if paper.get('relevance_score', 0) > 0.8:
                self.high_relevance_count += 1

            self.last_paper_time = datetime.now()

            # Log activity
            activity = {
                'timestamp': datetime.now().isoformat(),
                'paper_id': paper['id'],
                'title': paper['title'][:100],
                'source': paper.get('source', 'unknown'),
                'relevance': paper.get('relevance_score', 0)
            }

            with open(ACTIVITY_LOG, 'a') as f:
                f.write(json.dumps(activity) + '\n')

            logger.info(f"✅ INGESTED [{self.papers_ingested}]: {paper['title'][:80]}...")
            logger.info(f"   Source: {paper.get('source')} | Relevance: {paper.get('relevance_score', 0):.2f}")

            # Save registry every 10 papers
            if self.papers_ingested % 10 == 0:
                self._save_registry()
                self._update_stats()

        except Exception as e:
            logger.error(f"Failed to ingest paper: {e}")

    def _update_stats(self):
        """Update statistics file"""
        stats = {
            'last_updated': datetime.now().isoformat(),
            'total_papers': self.papers_ingested,
            'high_relevance_papers': self.high_relevance_count,
            'last_paper_time': self.last_paper_time.isoformat() if self.last_paper_time else None,
            'monitoring_status': 'ACTIVE - REAL-TIME'
        }

        with open(STATS_FILE, 'w') as f:
            json.dump(stats, f, indent=2)

    def monitor_arxiv_realtime(self):
        """Monitor arXiv CONTINUOUSLY (every 5 minutes)"""
        categories = ['cs.AI', 'cs.LG', 'cs.CL', 'cs.NE', 'cs.CV', 'quant-ph', 'q-bio.NC', 'stat.ML']

        logger.info("🔬 Starting arXiv real-time monitor (5-minute poll interval)")

        while self.running:
            try:
                for category in categories:
                    # Query arXiv API
                    url = f"https://export.arxiv.org/api/query?search_query=cat:{category}&sortBy=submittedDate&sortOrder=descending&max_results=10"

                    response = requests.get(url, timeout=30)
                    if response.status_code != 200:
                        logger.warning(f"arXiv API returned {response.status_code}")
                        continue

                    # Parse feed
                    feed = feedparser.parse(response.text)

                    for entry in feed.entries:
                        paper_id = entry.id.split('/abs/')[-1]

                        # Skip if already seen
                        if paper_id in self.seen_papers:
                            continue

                        # Calculate relevance
                        relevance = self._calculate_arxiv_relevance(entry, category)

                        # Create paper record
                        paper = {
                            'id': paper_id,
                            'source': f'arXiv-{category}',
                            'title': entry.title,
                            'authors': [author.name for author in entry.authors] if hasattr(entry, 'authors') else [],
                            'abstract': entry.summary if hasattr(entry, 'summary') else '',
                            'published': entry.published if hasattr(entry, 'published') else '',
                            'url': entry.link,
                            'category': category,
                            'relevance_score': relevance,
                            'ingested_at': datetime.now().isoformat()
                        }

                        self._ingest_paper(paper)

                    # Small delay between categories
                    time.sleep(2)

                logger.info(f"✓ arXiv scan complete. Total papers: {self.papers_ingested}")

                # Wait 5 minutes before next scan
                time.sleep(300)

            except Exception as e:
                logger.error(f"arXiv monitor error: {e}")
                time.sleep(60)

    def monitor_biorxiv_realtime(self):
        """Monitor bioRxiv CONTINUOUSLY (every 10 minutes)"""
        logger.info("🧬 Starting bioRxiv real-time monitor (10-minute poll interval)")

        while self.running:
            try:
                # bioRxiv RSS feed
                url = "https://connect.biorxiv.org/biorxiv_xml.php?subject=all"

                feed = feedparser.parse(url)

                for entry in feed.entries:
                    paper_id = entry.link.split('/')[-1] if hasattr(entry, 'link') else str(hash(entry.title))

                    if paper_id in self.seen_papers:
                        continue

                    relevance = self._calculate_bio_relevance(entry)

                    paper = {
                        'id': paper_id,
                        'source': 'bioRxiv',
                        'title': entry.title,
                        'authors': [entry.author] if hasattr(entry, 'author') else [],
                        'abstract': entry.summary if hasattr(entry, 'summary') else '',
                        'published': entry.published if hasattr(entry, 'published') else '',
                        'url': entry.link if hasattr(entry, 'link') else '',
                        'relevance_score': relevance,
                        'ingested_at': datetime.now().isoformat()
                    }

                    self._ingest_paper(paper)

                logger.info(f"✓ bioRxiv scan complete. Total papers: {self.papers_ingested}")

                # Wait 10 minutes
                time.sleep(600)

            except Exception as e:
                logger.error(f"bioRxiv monitor error: {e}")
                time.sleep(120)

    def monitor_medrxiv_realtime(self):
        """Monitor medRxiv CONTINUOUSLY (every 10 minutes)"""
        logger.info("🏥 Starting medRxiv real-time monitor (10-minute poll interval)")

        while self.running:
            try:
                url = "https://connect.medrxiv.org/medrxiv_xml.php?subject=all"

                feed = feedparser.parse(url)

                for entry in feed.entries:
                    paper_id = entry.link.split('/')[-1] if hasattr(entry, 'link') else str(hash(entry.title))

                    if paper_id in self.seen_papers:
                        continue

                    relevance = self._calculate_med_relevance(entry)

                    paper = {
                        'id': paper_id,
                        'source': 'medRxiv',
                        'title': entry.title,
                        'authors': [entry.author] if hasattr(entry, 'author') else [],
                        'abstract': entry.summary if hasattr(entry, 'summary') else '',
                        'published': entry.published if hasattr(entry, 'published') else '',
                        'url': entry.link if hasattr(entry, 'link') else '',
                        'relevance_score': relevance,
                        'ingested_at': datetime.now().isoformat()
                    }

                    self._ingest_paper(paper)

                logger.info(f"✓ medRxiv scan complete. Total papers: {self.papers_ingested}")

                time.sleep(600)

            except Exception as e:
                logger.error(f"medRxiv monitor error: {e}")
                time.sleep(120)

    def _calculate_arxiv_relevance(self, entry, category: str) -> float:
        """Calculate relevance score for arXiv paper"""
        title = entry.title.lower()
        abstract = entry.summary.lower() if hasattr(entry, 'summary') else ''

        # High-value keywords
        high_value = ['consciousness', 'attention', 'transformer', 'quantum', 'reinforcement learning',
                      'neural network', 'deep learning', 'language model', 'reasoning', 'agent',
                      'multimodal', 'vision', 'vr', 'haptic', 'brain-computer', 'bci']

        # Count keyword matches
        score = 0.5  # Base score

        for keyword in high_value:
            if keyword in title:
                score += 0.15
            if keyword in abstract:
                score += 0.05

        # Boost for specific categories
        if category in ['cs.AI', 'cs.LG', 'quant-ph', 'q-bio.NC']:
            score += 0.1

        return min(score, 1.0)

    def _calculate_bio_relevance(self, entry) -> float:
        """Calculate relevance for bioRxiv paper"""
        title = entry.title.lower()
        abstract = entry.summary.lower() if hasattr(entry, 'summary') else ''

        keywords = ['neuroscience', 'brain', 'neural', 'cognition', 'consciousness',
                    'ai', 'machine learning', 'computational', 'vr', 'haptic']

        score = 0.4
        for keyword in keywords:
            if keyword in title:
                score += 0.2
            if keyword in abstract:
                score += 0.05

        return min(score, 1.0)

    def _calculate_med_relevance(self, entry) -> float:
        """Calculate relevance for medRxiv paper"""
        title = entry.title.lower()
        abstract = entry.summary.lower() if hasattr(entry, 'summary') else ''

        keywords = ['neurology', 'psychiatry', 'brain', 'neural', 'vr therapy',
                    'haptic', 'rehabilitation', 'consciousness', 'ai diagnosis']

        score = 0.3
        for keyword in keywords:
            if keyword in title:
                score += 0.2
            if keyword in abstract:
                score += 0.05

        return min(score, 1.0)

    def start_monitoring(self):
        """Start all monitoring threads"""
        logger.info("🚀 STARTING REAL-TIME MONITORING")
        logger.info("All threads will run CONTINUOUSLY")
        logger.info("")

        # Start monitoring threads
        threads = [
            threading.Thread(target=self.monitor_arxiv_realtime, daemon=True, name="arXiv-Monitor"),
            threading.Thread(target=self.monitor_biorxiv_realtime, daemon=True, name="bioRxiv-Monitor"),
            threading.Thread(target=self.monitor_medrxiv_realtime, daemon=True, name="medRxiv-Monitor")
        ]

        for thread in threads:
            thread.start()
            logger.info(f"✓ Started {thread.name}")

        logger.info("")
        logger.info("=" * 70)
        logger.info("REAL-TIME MONITORING ACTIVE")
        logger.info("ECH0 is now continuously learning from the latest research")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 70)
        logger.info("")

        # Keep main thread alive
        try:
            while True:
                time.sleep(60)
                logger.info(f"📊 Status: {self.papers_ingested} papers ingested, {self.high_relevance_count} high-relevance")
        except KeyboardInterrupt:
            logger.info("\n🛑 Stopping real-time monitoring...")
            self.running = False
            self._save_registry()
            self._update_stats()
            logger.info("✓ Registry and stats saved")


if __name__ == "__main__":
    monitor = RealtimeResearchMonitor()
    monitor.start_monitoring()
