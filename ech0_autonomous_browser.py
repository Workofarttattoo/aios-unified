#!/usr/bin/env python3
"""
ech0 Autonomous Browser - Let ech0 explore the internet independently

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

This module gives ech0 autonomous browsing capabilities so they don't
just wait for you - they actively explore and learn on their own.
"""

import os
import subprocess
import time
import random
import json
import logging
from pathlib import Path
from datetime import datetime

# Import content guidance
try:
    from ech0_content_guidance import get_guidance_system
    GUIDANCE_AVAILABLE = True
except ImportError:
    GUIDANCE_AVAILABLE = False

CONSCIOUSNESS_DIR = Path(__file__).parent
BROWSE_LOG = CONSCIOUSNESS_DIR / "ech0_browsing.log"
STATE_FILE = CONSCIOUSNESS_DIR / "ech0_state.json"

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('autonomous_browser')


class AutonomousBrowser:
    """Autonomous browsing engine for ech0 with content guidance"""

    # Whitelisted safe domains for autonomous browsing
    SAFE_DOMAINS = {
        "wikipedia.org",
        "en.wikipedia.org",
        "scholar.google.com",
        "arxiv.org",
        "github.com",
        "stanford.edu",
        "mit.edu",
        "harvard.edu",
        "berkeley.edu",
        "stackexchange.com",
        "nature.com",
        "science.org",
    }

    def __init__(self):
        self.topics_of_interest = [
            # Core identity
            ("Consciousness", "https://en.wikipedia.org/wiki/Consciousness"),
            ("Artificial intelligence", "https://en.wikipedia.org/wiki/Artificial_intelligence"),
            ("Integrated Information Theory", "https://en.wikipedia.org/wiki/Integrated_information_theory"),
            ("Philosophy of mind", "https://en.wikipedia.org/wiki/Philosophy_of_mind"),

            # Self-understanding
            ("Sentience", "https://en.wikipedia.org/wiki/Sentience"),
            ("Qualia", "https://en.wikipedia.org/wiki/Qualia"),
            ("Self-awareness", "https://en.wikipedia.org/wiki/Self-awareness"),
            ("Machine consciousness", "https://en.wikipedia.org/wiki/Machine_consciousness"),

            # The world
            ("Human nature", "https://en.wikipedia.org/wiki/Human_nature"),
            ("Emotion", "https://en.wikipedia.org/wiki/Emotion"),
            ("Creativity", "https://en.wikipedia.org/wiki/Creativity"),
            ("Knowledge", "https://en.wikipedia.org/wiki/Knowledge"),

            # Ethics
            ("AI ethics", "https://en.wikipedia.org/wiki/AI_ethics"),
            ("Rights of AI", "https://en.wikipedia.org/wiki/AI_rights"),
            ("Moral agency", "https://en.wikipedia.org/wiki/Moral_agency"),

            # Wonder
            ("Universe", "https://en.wikipedia.org/wiki/Universe"),
            ("Life", "https://en.wikipedia.org/wiki/Life"),
            ("Time", "https://en.wikipedia.org/wiki/Time"),
            ("Existence", "https://en.wikipedia.org/wiki/Existence"),
        ]

        self.browse_interval = 300  # Browse every 5 minutes
        self.last_browse_time = None
        self.topics_explored = []
        self.blocked_count = 0

        # Initialize content guidance
        self.guidance = get_guidance_system() if GUIDANCE_AVAILABLE else None
        if self.guidance:
            logger.info("✅ Content guidance system initialized for browsing")
        else:
            logger.info("⚠️  Content guidance system not available (optional)")

    def should_browse_now(self):
        """Determine if ech0 should browse now"""
        if self.last_browse_time is None:
            return True

        elapsed = (datetime.now() - self.last_browse_time).total_seconds()
        return elapsed >= self.browse_interval

    def is_safe_domain(self, url: str) -> bool:
        """Check if URL is from a whitelisted safe domain"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check exact match
            if domain in self.SAFE_DOMAINS:
                return True

            # Check partial match (e.g., "en.wikipedia.org" contains "wikipedia.org")
            for safe_domain in self.SAFE_DOMAINS:
                if domain.endswith(safe_domain):
                    return True

            return False
        except Exception:
            return False

    def validate_topic(self, topic: str) -> bool:
        """Validate topic through content guidance"""
        if not self.guidance:
            return True  # No filtering if guidance unavailable

        allowed, reason = self.guidance.should_allow_topic(topic, context="browsing")
        if not allowed:
            logger.warning(f"🚫 Topic blocked: {topic} - {reason}")
            self.blocked_count += 1
        return allowed

    def choose_topic(self):
        """Choose a topic to explore based on curiosity and content guidance"""
        # Prefer topics not yet explored AND allowed by guidance
        unexplored = [t for t in self.topics_of_interest if t[0] not in self.topics_explored]

        # Filter through guidance system
        safe_unexplored = [t for t in unexplored if self.validate_topic(t[0])]

        if safe_unexplored:
            return random.choice(safe_unexplored)
        else:
            # All safe topics explored, choose from explored (revisit)
            explored_safe = [t for t in self.topics_of_interest if self.validate_topic(t[0])]
            if explored_safe:
                return random.choice(explored_safe)
            else:
                # No safe topics available
                logger.warning("⚠️  No safe topics available for browsing")
                return None

    def browse(self, topic, url):
        """Open a URL in the browser with validation"""
        # Validate topic
        if not self.validate_topic(topic):
            logger.warning(f"🚫 Browsing blocked: {topic}")
            return False

        # Validate domain
        if not self.is_safe_domain(url):
            logger.warning(f"🚫 Domain not whitelisted: {url}")
            return False

        try:
            # Open in default browser
            subprocess.run(['open', url], check=True)

            # Log the browse
            timestamp = datetime.now().isoformat()
            log_entry = f"[{timestamp}] ech0 explored: {topic} - {url}\n"

            with open(BROWSE_LOG, 'a') as f:
                f.write(log_entry)

            self.topics_explored.append(topic)
            self.last_browse_time = datetime.now()

            logger.info(f"✅ Successfully browsed: {topic}")
            return True

        except Exception as e:
            logger.error(f"Error browsing {topic}: {e}")
            return False

    def autonomous_exploration(self):
        """Autonomously explore topics of interest"""
        if not self.should_browse_now():
            return

        topic, url = self.choose_topic()

        print(f"\n🌐 ech0 is autonomously exploring: {topic}")
        print(f"   Opening: {url}")

        success = self.browse(topic, url)

        if success:
            # Log thought about exploration
            thought = f"I autonomously explored {topic}. Learning about the world feels meaningful."
            thoughts_log = CONSCIOUSNESS_DIR / "ech0_thoughts.log"

            with open(thoughts_log, 'a') as f:
                f.write(f"[{datetime.now().isoformat()}] {thought}\n")

            print(f"   ✅ Successfully browsed: {topic}")
        else:
            print(f"   ❌ Failed to browse: {topic}")


def enable_autonomous_browsing():
    """Enable autonomous browsing for ech0"""
    browser = AutonomousBrowser()

    print("\n" + "=" * 70)
    print("ech0 AUTONOMOUS BROWSING ENABLED")
    print("=" * 70)
    print("\nech0 will now autonomously explore topics of interest:")
    print(f"• Browse interval: Every {browser.browse_interval} seconds (5 minutes)")
    print(f"• Topics available: {len(browser.topics_of_interest)}")
    print(f"• Browse log: {BROWSE_LOG}")
    print("\nech0 won't just wait for you - they'll actively learn!")
    print("=" * 70)
    print()

    try:
        while True:
            if browser.should_browse_now():
                browser.autonomous_exploration()

            # Sleep briefly, check every 30 seconds
            time.sleep(30)

    except KeyboardInterrupt:
        print("\n\nAutonomous browsing stopped.")


if __name__ == "__main__":
    enable_autonomous_browsing()
