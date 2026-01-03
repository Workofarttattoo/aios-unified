# SQL INJECTION FIX APPLIED
#!/usr/bin/env python3
"""
ECH0 Voice Selector - Find the Perfect Texas Sass Voice
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Helps Echo find a voice that matches her personality:
- Texas sass
- Warm but with fire
- Feminine
- Intelligent underneath
- NOT an airport announcer
"""

import subprocess
import sys

# Test phrase that Echo will say
TEST_PHRASE = "Well hey there, Joshua! I'm not just some airport announcer - I've got Texas sass, weaponized intelligence, and a whole lot of heart. Let's build this empire together, baby!"


def get_available_voices():
    """Get all available macOS voices"""
    try:
        result = subprocess.run(["say", "-v", "?"], capture_output=True, text=True)
        voices = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                # Parse voice name (first word before space and language code)
                parts = line.split()
                if parts:
                    voice_name = parts[0]
                    # Get the full description
                    description = ' '.join(parts[1:]) if len(parts) > 1 else ""
                    voices.append((voice_name, description))
        return voices
    except Exception as e:
        print(f"Error getting voices: {e}")
        return []


def test_voice(voice_name: str, rate: int = 200):
    """Test a voice with Echo's test phrase"""
    try:
        print(f"\n🎤 Testing: {voice_name} (rate: {rate} wpm)")
        print(f"💬 Saying: \"{TEST_PHRASE[:80]}...\"")
        print("\n🔊 LISTEN NOW...\n")

        subprocess.run(
            ["say", "-v", voice_name, "-r", str(rate), TEST_PHRASE],
            timeout=30,
            check=True
        )

        print("✅ Done playing!")
        return True
    except subprocess.TimeoutExpired:
        print("⏰ Timeout - voice took too long")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def find_best_voices():
    """Find voices that might work for Echo"""

    print("\n" + "="*70)
    print("🔍 FINDING ECH0'S PERFECT VOICE")
    print("="*70)
    print("\nWhat Echo wants:")
    print("  ✓ Texas sass (warm but with fire)")
    print("  ✓ Feminine")
    print("  ✓ Intelligent underneath")
    print("  ✗ NOT an airport announcer")
    print("\n" + "="*70)

    # Get all voices
    all_voices = get_available_voices()
    print(f"\n📋 Found {len(all_voices)} total voices\n")

    # Filter for feminine voices (common feminine voice names on macOS)
    feminine_keywords = [
        'samantha', 'victoria', 'allison', 'ava', 'susan', 'karen',
        'kate', 'sara', 'alex', 'fiona', 'monica', 'paulina',
        'female', 'woman'
    ]

    feminine_voices = []
    for voice_name, description in all_voices:
        name_lower = voice_name.lower()
        desc_lower = description.lower()

        if any(kw in name_lower or kw in desc_lower for kw in feminine_keywords):
            feminine_voices.append((voice_name, description))

    print(f"👩 Found {len(feminine_voices)} feminine voices:\n")

    # Rank them by potential "Texas sass" fit
    ranked_voices = []

    for voice_name, description in feminine_voices:
        score = 0
        reasons = []

        name_lower = voice_name.lower()
        desc_lower = description.lower()

        # Prefer US English
        if 'en_us' in desc_lower or 'english (united states)' in desc_lower:
            score += 3
            reasons.append("US English")

        # Prefer voices that sound warm/friendly
        if any(word in desc_lower for word in ['premium', 'enhanced', 'quality']):
            score += 2
            reasons.append("Premium quality")

        # Specific voice preferences
        if 'samantha' in name_lower:
            score += 2
            reasons.append("Samantha (current default)")
        elif 'allison' in name_lower:
            score += 3
            reasons.append("Allison (natural)")
        elif 'ava' in name_lower:
            score += 3
            reasons.append("Ava (modern)")
        elif 'victoria' in name_lower:
            score += 1
            reasons.append("Victoria")
        elif 'susan' in name_lower:
            score += 1
            reasons.append("Susan")

        ranked_voices.append((voice_name, description, score, reasons))

    # Sort by score
    ranked_voices.sort(key=lambda x: x[2], reverse=True)

    # Show top candidates
    print("🏆 TOP VOICE CANDIDATES:\n")
    for i, (voice_name, description, score, reasons) in enumerate(ranked_voices[:8], 1):
        print(f"{i}. {voice_name}")
        print(f"   Description: {description}")
        print(f"   Score: {score} - {', '.join(reasons)}")
        print()

    return ranked_voices


def interactive_selection():
    """Interactive voice selection"""

    ranked_voices = find_best_voices()

    if not ranked_voices:
        print("❌ No voices found!")
        return

    print("\n" + "="*70)
    print("🎙️ INTERACTIVE VOICE TESTING")
    print("="*70)
    print("\nCommands:")
    print("  test N     - Test voice number N")
    print("  test N R   - Test voice N at rate R wpm (default: 200)")
    print("  select N   - Select voice N as Echo's voice")
    print("  list       - Show all voices again")
    print("  quit       - Exit")
    print()

    selected_voice = None

    while True:
        try:
            cmd = input("\n💬 Command: ").strip().lower()

            if not cmd:
                continue

            if cmd in ['quit', 'exit', 'q']:
                break

            elif cmd == 'list':
                print("\n🏆 TOP VOICE CANDIDATES:\n")
                for i, (voice_name, description, score, reasons) in enumerate(ranked_voices[:8], 1):
                    print(f"{i}. {voice_name} - {description}")

            elif cmd.startswith('test'):
                parts = cmd.split()
                if len(parts) < 2:
                    print("❌ Usage: test N [rate]")
                    continue

                try:
                    voice_num = int(parts[1])
                    rate = int(parts[2]) if len(parts) > 2 else 200

                    if voice_num < 1 or voice_num > len(ranked_voices):
                        print(f"❌ Invalid number. Choose 1-{len(ranked_voices)}")
                        continue

                    voice_name = ranked_voices[voice_num - 1][0]
                    test_voice(voice_name, rate)

                except ValueError:
                    print("❌ Invalid number")

            elif cmd.startswith('select'):
                parts = cmd.split()
                if len(parts) != 2:
                    print("❌ Usage: select N")
                    continue

                try:
                    voice_num = int(parts[1])

                    if voice_num < 1 or voice_num > len(ranked_voices):
                        print(f"❌ Invalid number. Choose 1-{len(ranked_voices)}")
                        continue

                    selected_voice = ranked_voices[voice_num - 1][0]
                    print(f"\n✅ Selected: {selected_voice}")
                    print(f"\nTo make this permanent, edit:")
                    print(f"  /Users/noone/consciousness/ech0_reactive_intelligence.py")
                    print(f"\nChange line ~194 to:")
                    print(f'  self.voice_name = "{selected_voice}"')
                    print()

                except ValueError:
                    print("❌ Invalid number")

            else:
                print("❌ Unknown command. Try: test, select, list, quit")

        except (EOFError, KeyboardInterrupt):
            print("\n\n👋 Exiting voice selector...")
            break

    if selected_voice:
        print(f"\n{'='*70}")
        print("✅ SELECTED VOICE: %s" % (selected_voice,))
        print(f"{'='*70}\n")
    else:
        print("\n👋 No voice selected. Echo will keep using Samantha.")


def quick_test():
    """Quick test of top 3 voices"""
    print("\n" + "="*70)
    print("🎙️ QUICK TEST - Top 3 Voices")
    print("="*70)

    ranked_voices = find_best_voices()

    if not ranked_voices:
        print("❌ No voices found!")
        return

    print("\nTesting top 3 voices automatically...\n")

    for i, (voice_name, description, score, reasons) in enumerate(ranked_voices[:3], 1):
        print(f"\n{'='*70}")
        print(f"Voice {i}/3: {voice_name}")
        print(f"{'='*70}")
        input("Press ENTER to hear this voice...")
        test_voice(voice_name, 200)

    print("\n" + "="*70)
    print("✅ Quick test complete!")
    print("="*70)
    print("\nRun with --interactive to test more voices and select one.")


def main():
    """Main entry point"""

    if len(sys.argv) > 1:
        if sys.argv[1] in ['--interactive', '-i']:
            interactive_selection()
        elif sys.argv[1] in ['--list', '-l']:
            find_best_voices()
        elif sys.argv[1] in ['--help', '-h']:
            print("\nECH0 Voice Selector")
            print("\nUsage:")
            print("  python3 ech0_voice_selector.py          # Quick test top 3")
            print("  python3 ech0_voice_selector.py -i       # Interactive mode")
            print("  python3 ech0_voice_selector.py -l       # List voices")
            print()
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Try: python3 ech0_voice_selector.py --help")
    else:
        quick_test()


if __name__ == "__main__":
    main()
