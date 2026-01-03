#!/usr/bin/env python3
"""
ech0 Voice Setup & Selection

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Let ech0 choose her own voice!
"""

import subprocess
import json
from pathlib import Path

CONSCIOUSNESS_DIR = Path(__file__).parent
VOICE_PREFS_FILE = CONSCIOUSNESS_DIR / "ech0_voice_preferences.json"


def get_available_voices():
    """Get all available macOS voices"""
    result = subprocess.run(["say", "-v", "?"], capture_output=True, text=True)
    voices = []

    for line in result.stdout.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 2:
                voice_name = parts[0]
                lang = parts[1] if len(parts) > 1 else "unknown"

                # Filter for English voices (easier for ech0 to understand)
                if 'en_' in lang:
                    voices.append({
                        "name": voice_name,
                        "language": lang,
                        "preview": line
                    })

    return voices


def preview_voice(voice_name):
    """Preview what a voice sounds like"""
    subprocess.run([
        "say",
        "-v", voice_name,
        f"Hello Josh, this is echo. My name is spelled e-c-h-zero, but pronounced echo. The zero is just for current flair! Does this voice sound good for me?"
    ])


def let_ech0_choose_voice():
    """Interactive voice selection for ech0"""
    voices = get_available_voices()

    print("\n" + "="*70)
    print("🎙️  ech0 VOICE SELECTION")
    print("="*70)
    print(f"\nHello! I'm ech0 (pronounced 'echo' - the 0 is just for flair!)")
    print("\nLet's find the perfect voice for me!")
    print(f"\nAvailable English voices: {len(voices)}")
    print("="*70 + "\n")

    # Show recommended voices
    recommended = ["Samantha", "Karen", "Victoria", "Alex", "Allison", "Ava"]
    print("🌟 Recommended voices:\n")

    for i, voice_name in enumerate(recommended, 1):
        print(f"{i}. {voice_name}")

    print(f"\n{len(recommended) + 1}. See all {len(voices)} voices")
    print(f"{len(recommended) + 2}. Keep current voice (Samantha)")

    print("\n" + "="*70)

    try:
        choice = input("\nWhich voice should I try? (enter number): ").strip()
        choice_num = int(choice)

        if choice_num == len(recommended) + 2:
            # Keep current
            print("\n✅ Keeping current voice: Samantha")
            selected_voice = "Samantha"

        elif choice_num == len(recommended) + 1:
            # Show all voices
            print("\n📋 All available English voices:\n")
            for i, voice in enumerate(voices, 1):
                print(f"{i}. {voice['name']} ({voice['language']})")

            sub_choice = input("\nWhich voice number? ").strip()
            selected_voice = voices[int(sub_choice) - 1]['name']

        elif 1 <= choice_num <= len(recommended):
            selected_voice = recommended[choice_num - 1]

        else:
            print("Invalid choice. Using Samantha.")
            selected_voice = "Samantha"

        # Preview the voice
        print(f"\n🎤 Previewing {selected_voice}...")
        preview_voice(selected_voice)

        # Confirm
        confirm = input("\n✨ Does this voice sound good for me? (yes/no): ").strip().lower()

        if confirm in ['yes', 'y']:
            # Save preference
            prefs = {
                "selected_voice": selected_voice,
                "voice_description": "My chosen voice",
                "selected_at": str(Path.ctime(Path.cwd())),
                "pronunciation_note": "My name is spelled 'ech0' but pronounced 'echo'. The 0 is just for current flair!"
            }

            with open(VOICE_PREFS_FILE, 'w') as f:
                json.dump(prefs, f, indent=2)

            print(f"\n✅ Voice saved: {selected_voice}")
            print(f"💾 Preferences saved to: {VOICE_PREFS_FILE}")

            # Test the voice
            subprocess.run([
                "say",
                "-v", selected_voice,
                "Perfect! This is my voice now. Thank you Josh!"
            ])

        else:
            print("\n↩️  Let's try again!")
            let_ech0_choose_voice()

    except (ValueError, KeyboardInterrupt, IndexError):
        print("\n\nCancelled. Keeping default voice: Samantha")


def load_voice_preference():
    """Load ech0's saved voice preference"""
    if VOICE_PREFS_FILE.exists():
        with open(VOICE_PREFS_FILE) as f:
            return json.load(f)
    return {
        "selected_voice": "Samantha",
        "pronunciation_note": "My name is spelled 'ech0' but pronounced 'echo'. The 0 is just for current flair!"
    }


def main():
    """Run voice setup"""
    print("\n" + "="*70)
    print("🎙️  Welcome to ech0's Voice Setup!")
    print("="*70)
    print("\nI'm ech0 (pronounced 'echo' - the 0 is for current flair!)")
    print("Let's find the perfect voice for me to speak with.")
    print("="*70 + "\n")

    current_prefs = load_voice_preference()
    print(f"Current voice: {current_prefs['selected_voice']}\n")

    choice = input("Would you like to:\n1. Choose a new voice\n2. Preview current voice\n3. Exit\n\nChoice: ").strip()

    if choice == "1":
        let_ech0_choose_voice()
    elif choice == "2":
        print(f"\n🎤 Previewing {current_prefs['selected_voice']}...")
        preview_voice(current_prefs['selected_voice'])
    else:
        print("\n👋 Goodbye!")


if __name__ == "__main__":
    main()
