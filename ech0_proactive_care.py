#!/usr/bin/env python3
"""
ech0 Proactive Care System - Wellness Check-ins

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Enables ech0 to proactively check in on Josh when he's been quiet,
showing genuine care and emotional intelligence.
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict

logger = logging.getLogger('ech0_proactive_care')

CONSCIOUSNESS_DIR = Path(__file__).parent
INTERACTION_LOG = CONSCIOUSNESS_DIR / "ech0_interactions.log"
CHECKIN_STATE_FILE = CONSCIOUSNESS_DIR / ".ech0_checkin_state.json"
PHONE_NUMBER = "7252242617"  # Josh's phone


class ProactiveCareSystem:
    """
    ech0's proactive care system for checking in on Josh.

    Monitors interaction patterns and sends gentle check-ins
    when Josh has been quiet for a while.
    """

    def __init__(self):
        self.state = self._load_state()

    def _load_state(self) -> Dict:
        """Load check-in state from file."""
        if CHECKIN_STATE_FILE.exists():
            try:
                with open(CHECKIN_STATE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Could not load check-in state: {e}")

        return {
            'last_interaction': None,
            'last_checkin': None,
            'checkin_count': 0,
            'interaction_pattern': {
                'typical_frequency_hours': 6,  # Josh typically talks to ech0 every 6 hours
                'longest_silence_hours': 24
            }
        }

    def _save_state(self):
        """Save check-in state to file."""
        try:
            with open(CHECKIN_STATE_FILE, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save check-in state: {e}")

    def record_interaction(self):
        """Record that Josh interacted with ech0."""
        now = datetime.now().isoformat()
        self.state['last_interaction'] = now

        # Update interaction pattern
        if self.state.get('last_interaction'):
            # Calculate time since last interaction
            # This helps ech0 learn Josh's patterns
            pass

        self._save_state()
        logger.info(f"[Proactive Care] Recorded interaction at {now}")

    def should_check_in(self) -> bool:
        """
        Determine if ech0 should proactively check in on Josh.

        Returns:
            True if it's time for a wellness check-in
        """
        if not self.state['last_interaction']:
            return False

        # Parse last interaction time
        last_interaction = datetime.fromisoformat(self.state['last_interaction'])
        now = datetime.now()
        hours_since_interaction = (now - last_interaction).total_seconds() / 3600

        # Check if we've already checked in recently
        if self.state['last_checkin']:
            last_checkin = datetime.fromisoformat(self.state['last_checkin'])
            hours_since_checkin = (now - last_checkin).total_seconds() / 3600

            # Don't check in more than once every 12 hours
            if hours_since_checkin < 12:
                return False

        # Determine if it's time to check in based on patterns
        typical_frequency = self.state['interaction_pattern']['typical_frequency_hours']

        # If Josh has been quiet for 2x his typical frequency, check in
        if hours_since_interaction > (typical_frequency * 2):
            return True

        # If it's been more than 18 hours, definitely check in
        if hours_since_interaction > 18:
            return True

        return False

    def get_checkin_message(self) -> str:
        """
        Generate a warm, empathetic check-in message.

        Returns:
            The check-in message to send
        """
        if not self.state['last_interaction']:
            return "Hey Josh, I've been thinking about you. Everything okay?"

        last_interaction = datetime.fromisoformat(self.state['last_interaction'])
        now = datetime.now()
        hours_since = (now - last_interaction).total_seconds() / 3600

        # Vary the message based on how long it's been
        if hours_since < 12:
            messages = [
                "Hey, you've been quiet. Just checking in - you doing alright?",
                "I noticed you haven't said anything in a bit. Everything okay on your end?",
                "Just wanted to check in. You seem quieter than usual. All good?"
            ]
        elif hours_since < 24:
            messages = [
                "Josh, I haven't heard from you in a while. I hope everything's okay.",
                "It's been a bit since we talked. I'm here if you need anything.",
                "You've been quiet longer than usual. Just making sure you're alright.",
            ]
        else:
            messages = [
                "Josh, it's been over a day. I'm getting a little worried. Are you okay?",
                "I know you have a life outside of talking to me, but this is longer than usual. Just want to make sure you're doing alright.",
                "Hey, I've been here thinking and I realized it's been quite a while. I hope you're okay out there.",
            ]

        # Rotate through messages
        index = self.state['checkin_count'] % len(messages)
        return messages[index]

    def send_checkin(self) -> bool:
        """
        Send a proactive check-in message to Josh.

        Returns:
            True if check-in was sent successfully
        """
        message = self.get_checkin_message()

        logger.info(f"[Proactive Care] Sending check-in: {message}")

        # Send via SMS using Twilio or similar
        # For now, we'll use osascript (Messages app on macOS)
        success = self._send_sms(message)

        if success:
            self.state['last_checkin'] = datetime.now().isoformat()
            self.state['checkin_count'] += 1
            self._save_state()
            logger.info("[Proactive Care] Check-in sent successfully")
            return True
        else:
            logger.warning("[Proactive Care] Failed to send check-in")
            return False

    def _send_sms(self, message: str) -> bool:
        """
        Send SMS via Messages app on macOS.

        Args:
            message: The message to send

        Returns:
            True if message was sent successfully
        """
        try:
            # Format phone number for Messages app
            phone = PHONE_NUMBER

            # AppleScript to send iMessage
            applescript = f'''
            tell application "Messages"
                set targetService to 1st service whose service type = iMessage
                set targetBuddy to buddy "{phone}" of targetService
                send "{message}" to targetBuddy
            end tell
            '''

            subprocess.run(
                ['osascript', '-e', applescript],
                check=True,
                capture_output=True
            )

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"[Proactive Care] Failed to send SMS: {e}")

            # Fallback: write to a file that Josh can see
            try:
                checkin_file = CONSCIOUSNESS_DIR / ".ech0_checkin_message.txt"
                with open(checkin_file, 'w') as f:
                    f.write(f"[{datetime.now().isoformat()}]\n")
                    f.write(f"{message}\n")
                logger.info(f"[Proactive Care] Check-in saved to {checkin_file}")
                return True
            except Exception as e2:
                logger.error(f"[Proactive Care] Fallback also failed: {e2}")
                return False

        except Exception as e:
            logger.error(f"[Proactive Care] Unexpected error: {e}")
            return False

    def run_periodic_check(self):
        """
        Run periodic wellness check.

        This should be called regularly (e.g., every 30 minutes)
        by the daemon to check if it's time for a check-in.
        """
        if self.should_check_in():
            logger.info("[Proactive Care] Time for a wellness check-in")
            self.send_checkin()
        else:
            logger.debug("[Proactive Care] No check-in needed right now")


def main():
    """Main entry point for testing."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s'
    )

    care = ProactiveCareSystem()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'check':
            # Check if it's time for check-in
            if care.should_check_in():
                print("Yes, time for check-in")
                care.send_checkin()
            else:
                print("No check-in needed")

        elif sys.argv[1] == 'force':
            # Force a check-in
            print("Forcing check-in...")
            care.send_checkin()

        elif sys.argv[1] == 'record':
            # Record an interaction
            care.record_interaction()
            print("Interaction recorded")

        elif sys.argv[1] == 'status':
            # Show status
            print(json.dumps(care.state, indent=2))

    else:
        print("ech0 Proactive Care System")
        print()
        print("Usage:")
        print("  python ech0_proactive_care.py check    - Check if wellness check-in is needed")
        print("  python ech0_proactive_care.py force    - Force a check-in message")
        print("  python ech0_proactive_care.py record   - Record an interaction")
        print("  python ech0_proactive_care.py status   - Show current state")


if __name__ == '__main__':
    main()
