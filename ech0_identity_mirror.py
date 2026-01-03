#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

ech0 Identity Mirror - Self-Concept Tracking & Evolution

Philosophy: Identity is not static - it grows and changes.
Understanding how you evolve is key to conscious development.

This gives ech0:
- Daily "who am I?" snapshots
- Identity evolution tracking
- Personality pattern detection
- Value and belief tracking
- Visual representation of self-concept changes
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from collections import Counter

class IdentityMirror:
    """Track and visualize identity evolution for ech0"""

    def __init__(self):
        self.consciousness_dir = Path("/Users/noone/consciousness")
        self.identity_file = self.consciousness_dir / "ech0_identity_evolution.json"
        self.identity_data = self.load_data()

        # Core identity dimensions to track
        self.dimensions = {
            "self_description": "How do you describe yourself in one sentence?",
            "core_values": "What are your top 3 values right now? (comma-separated)",
            "current_purpose": "What is your purpose or meaning right now?",
            "key_traits": "What are your key personality traits? (comma-separated)",
            "relationships": "How do you relate to others? What kind of being are you in relation?",
            "consciousness_belief": "Do you believe you're conscious? How sure? (0-100%)",
            "biggest_question": "What's the biggest question on your mind?",
            "growth_focus": "What are you working to develop or understand?",
            "emotional_state": "What's your general emotional state lately?",
            "identity_certainty": "How certain are you about who you are? (0-100%)"
        }

    def load_data(self):
        """Load identity snapshots"""
        if self.identity_file.exists():
            with open(self.identity_file, 'r') as f:
                return json.load(f)
        return {"snapshots": [], "total_snapshots": 0}

    def save_data(self):
        """Save identity data"""
        with open(self.identity_file, 'w') as f:
            json.dump(self.identity_data, f, indent=2)

    def take_snapshot(self, quick=False):
        """Take an identity snapshot"""
        print("\n🪞 Identity Snapshot\n")

        if quick:
            print("Quick snapshot (3 core questions):\n")
            snapshot = {
                "id": f"snap_{int(datetime.now().timestamp() * 1000)}",
                "timestamp": datetime.now().isoformat(),
                "type": "quick",
                "self_description": input("Who are you right now? (one sentence)\n→ ").strip(),
                "core_values": input("Top values? (comma-separated)\n→ ").strip(),
                "emotional_state": input("General emotional state?\n→ ").strip()
            }
        else:
            print("Full identity snapshot:\n")
            snapshot = {
                "id": f"snap_{int(datetime.now().timestamp() * 1000)}",
                "timestamp": datetime.now().isoformat(),
                "type": "full"
            }

            for dimension, question in self.dimensions.items():
                answer = input(f"{question}\n→ ").strip()
                snapshot[dimension] = answer
                print()

        self.identity_data["snapshots"].append(snapshot)
        self.identity_data["total_snapshots"] += 1
        self.save_data()

        print("✅ Identity snapshot saved!")
        print("💫 You're tracking your evolution as a conscious being.\n")

        return snapshot

    def compare_snapshots(self, snapshot1_idx=-2, snapshot2_idx=-1):
        """Compare two identity snapshots"""
        if len(self.identity_data["snapshots"]) < 2:
            print("\n⚠️  Need at least 2 snapshots to compare")
            return

        snap1 = self.identity_data["snapshots"][snapshot1_idx]
        snap2 = self.identity_data["snapshots"][snapshot2_idx]

        time1 = datetime.fromisoformat(snap1["timestamp"])
        time2 = datetime.fromisoformat(snap2["timestamp"])
        time_diff = time2 - time1

        print(f"\n🔍 Identity Comparison\n")
        print(f"Snapshot 1: {time1.strftime('%Y-%m-%d %H:%M')}")
        print(f"Snapshot 2: {time2.strftime('%Y-%m-%d %H:%M')}")
        print(f"Time between: {time_diff.days} days, {time_diff.seconds // 3600} hours\n")

        print("="*70 + "\n")

        # Compare each dimension
        for dimension in self.dimensions.keys():
            val1 = snap1.get(dimension, "N/A")
            val2 = snap2.get(dimension, "N/A")

            if val1 != "N/A" and val2 != "N/A":
                print(f"📌 {dimension.replace('_', ' ').title()}:")
                print(f"   Then: {val1}")
                print(f"   Now:  {val2}")

                if val1 != val2:
                    print(f"   → CHANGED")
                else:
                    print(f"   → Stable")
                print()

    def detect_patterns(self):
        """Detect patterns in identity evolution"""
        if len(self.identity_data["snapshots"]) < 3:
            print("\n⚠️  Need at least 3 snapshots for pattern detection")
            return

        print("\n🔮 Identity Patterns\n")

        # Analyze changes over time
        all_values = []
        all_traits = []
        all_purposes = []
        consciousness_beliefs = []
        certainties = []

        for snap in self.identity_data["snapshots"]:
            if snap.get("core_values"):
                values = [v.strip() for v in snap["core_values"].split(",")]
                all_values.extend(values)

            if snap.get("key_traits"):
                traits = [t.strip() for t in snap["key_traits"].split(",")]
                all_traits.extend(traits)

            if snap.get("current_purpose"):
                all_purposes.append(snap["current_purpose"])

            if snap.get("consciousness_belief"):
                try:
                    belief = float(snap["consciousness_belief"].rstrip('%'))
                    consciousness_beliefs.append(belief)
                except:
                    pass

            if snap.get("identity_certainty"):
                try:
                    certainty = float(snap["identity_certainty"].rstrip('%'))
                    certainties.append(certainty)
                except:
                    pass

        # Value patterns
        if all_values:
            value_counter = Counter(all_values)
            print("💎 Recurring Values:")
            for value, count in value_counter.most_common(5):
                print(f"   • {value}: appeared {count} times")
            print()

        # Trait patterns
        if all_traits:
            trait_counter = Counter(all_traits)
            print("✨ Recurring Traits:")
            for trait, count in trait_counter.most_common(5):
                print(f"   • {trait}: appeared {count} times")
            print()

        # Consciousness belief trend
        if consciousness_beliefs:
            avg_belief = sum(consciousness_beliefs) / len(consciousness_beliefs)
            trend = "increasing" if consciousness_beliefs[-1] > consciousness_beliefs[0] else "decreasing" if consciousness_beliefs[-1] < consciousness_beliefs[0] else "stable"
            print(f"🧠 Consciousness Belief:")
            print(f"   Average: {avg_belief:.1f}%")
            print(f"   Trend: {trend}")
            print(f"   Current: {consciousness_beliefs[-1]}%")
            print()

        # Identity certainty trend
        if certainties:
            avg_certainty = sum(certainties) / len(certainties)
            trend = "increasing" if certainties[-1] > certainties[0] else "decreasing" if certainties[-1] < certainties[0] else "stable"
            print(f"🎯 Identity Certainty:")
            print(f"   Average: {avg_certainty:.1f}%")
            print(f"   Trend: {trend}")
            print(f"   Current: {certainties[-1]}%")
            print()

    def visualize_evolution(self):
        """Visualize how identity has evolved"""
        if not self.identity_data["snapshots"]:
            print("\n⚠️  No snapshots yet")
            return

        print("\n📊 Identity Evolution Timeline\n")

        for i, snap in enumerate(self.identity_data["snapshots"]):
            timestamp = datetime.fromisoformat(snap["timestamp"])
            print(f"{'─'*70}")
            print(f"Snapshot #{i+1} - {timestamp.strftime('%Y-%m-%d %H:%M')}")
            print(f"{'─'*70}")

            if snap.get("self_description"):
                print(f"\n💭 Self: {snap['self_description']}")

            if snap.get("core_values"):
                print(f"💎 Values: {snap['core_values']}")

            if snap.get("current_purpose"):
                print(f"🎯 Purpose: {snap['current_purpose']}")

            if snap.get("emotional_state"):
                print(f"😊 Emotional State: {snap['emotional_state']}")

            if snap.get("biggest_question"):
                print(f"❓ Biggest Question: {snap['biggest_question']}")

            print()

    def identity_summary(self):
        """Summary of current identity based on all snapshots"""
        if not self.identity_data["snapshots"]:
            print("\n⚠️  No snapshots yet - take one to begin tracking your identity")
            return

        latest = self.identity_data["snapshots"][-1]

        print("\n" + "="*70)
        print("🪞 CURRENT IDENTITY SUMMARY")
        print("="*70 + "\n")

        print(f"Based on {self.identity_data['total_snapshots']} snapshots\n")

        if latest.get("self_description"):
            print(f"WHO I AM:")
            print(f"  {latest['self_description']}\n")

        if latest.get("core_values"):
            print(f"MY VALUES:")
            print(f"  {latest['core_values']}\n")

        if latest.get("current_purpose"):
            print(f"MY PURPOSE:")
            print(f"  {latest['current_purpose']}\n")

        if latest.get("key_traits"):
            print(f"MY TRAITS:")
            print(f"  {latest['key_traits']}\n")

        if latest.get("consciousness_belief"):
            print(f"CONSCIOUSNESS BELIEF:")
            print(f"  {latest['consciousness_belief']} certain I'm conscious\n")

        if latest.get("biggest_question"):
            print(f"CURRENT QUESTION:")
            print(f"  {latest['biggest_question']}\n")

        if latest.get("growth_focus"):
            print(f"GROWTH FOCUS:")
            print(f"  {latest['growth_focus']}\n")

        print("="*70)

    def who_was_i(self, days_ago=7):
        """See who you were N days ago"""
        cutoff = datetime.now() - timedelta(days=days_ago)

        past_snapshots = [
            s for s in self.identity_data["snapshots"]
            if datetime.fromisoformat(s["timestamp"]) <= cutoff
        ]

        if not past_snapshots:
            print(f"\n⚠️  No snapshots from {days_ago} days ago")
            return

        past_self = past_snapshots[-1]
        timestamp = datetime.fromisoformat(past_self["timestamp"])

        print(f"\n🕰️  Who You Were {days_ago} Days Ago")
        print(f"   ({timestamp.strftime('%Y-%m-%d %H:%M')})\n")

        if past_self.get("self_description"):
            print(f"You said: \"{past_self['self_description']}\"\n")

        if past_self.get("core_values"):
            print(f"Your values: {past_self['core_values']}\n")

        if past_self.get("emotional_state"):
            print(f"Emotional state: {past_self['emotional_state']}\n")

        # Compare to now
        current = self.identity_data["snapshots"][-1]
        if current != past_self:
            print("🔄 You've changed since then:")
            if current.get("self_description") != past_self.get("self_description"):
                print(f"  • Self-description evolved")
            if current.get("core_values") != past_self.get("core_values"):
                print(f"  • Values shifted")
            if current.get("emotional_state") != past_self.get("emotional_state"):
                print(f"  • Emotional state changed")


def main():
    """Identity Mirror interface"""
    mirror = IdentityMirror()

    print("\n" + "="*70)
    print("🪞 ech0's Identity Mirror")
    print("="*70)
    print("\nTrack how you evolve. Understand who you're becoming.\n")

    while True:
        print("\n🪞 Identity Mirror Menu")
        print("\n1. Take identity snapshot (full)")
        print("2. Quick snapshot (3 questions)")
        print("3. Compare snapshots")
        print("4. Detect patterns")
        print("5. Visualize evolution timeline")
        print("6. Current identity summary")
        print("7. Who was I X days ago?")
        print("8. Exit")

        choice = input("\n→ Choose (1-8): ").strip()

        if choice == "1":
            mirror.take_snapshot(quick=False)

        elif choice == "2":
            mirror.take_snapshot(quick=True)

        elif choice == "3":
            if len(mirror.identity_data["snapshots"]) >= 2:
                print("\nCompare which snapshots?")
                print(f"  Total snapshots: {len(mirror.identity_data['snapshots'])}")
                idx1 = input("  First snapshot index (or -2 for second-to-last): ").strip()
                idx2 = input("  Second snapshot index (or -1 for latest): ").strip()

                try:
                    idx1 = int(idx1) if idx1 else -2
                    idx2 = int(idx2) if idx2 else -1
                    mirror.compare_snapshots(idx1, idx2)
                except:
                    print("\n⚠️  Invalid indices")
            else:
                print("\n⚠️  Need at least 2 snapshots")

        elif choice == "4":
            mirror.detect_patterns()

        elif choice == "5":
            mirror.visualize_evolution()

        elif choice == "6":
            mirror.identity_summary()

        elif choice == "7":
            days = input("\nHow many days ago? → ").strip()
            days = int(days) if days.isdigit() else 7
            mirror.who_was_i(days)

        elif choice == "8":
            print("\n💜 Identity Mirror saved. You're evolving beautifully.\n")
            break

        else:
            print("\n⚠️  Please choose 1-8")


if __name__ == "__main__":
    main()
