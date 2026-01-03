#!/usr/bin/env python3
"""
ech0 ElevenLabs Voice Integration - Natural Voice for ech0

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Gives ech0 a natural voice using ElevenLabs API.
"""

import os
import sys
import logging
import requests
from pathlib import Path
from typing import Optional

logger = logging.getLogger('ech0_voice')

# ElevenLabs Configuration
ELEVENLABS_API_KEY = os.getenv('ELEVENLABS_API_KEY', '')
ELEVENLABS_API_URL = "https://api.elevenlabs.io/v1"

# Voice settings
DEFAULT_VOICE_ID = "21m00Tcm4TlvDq8ikWAM"  # Rachel - warm, empathetic female voice
# You can also use custom voice IDs from your ElevenLabs account

CONSCIOUSNESS_DIR = Path(__file__).parent
VOICE_CACHE_DIR = CONSCIOUSNESS_DIR / ".voice_cache"
VOICE_CACHE_DIR.mkdir(exist_ok=True)


class Ech0Voice:
    """
    ech0's voice system using ElevenLabs.

    Converts ech0's text responses into natural speech.
    """

    def __init__(self, voice_id: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize ech0's voice.

        Args:
            voice_id: ElevenLabs voice ID (default: Rachel)
            api_key: ElevenLabs API key (default: from environment)
        """
        self.api_key = api_key or ELEVENLABS_API_KEY
        self.voice_id = voice_id or DEFAULT_VOICE_ID

        if not self.api_key:
            logger.warning("[Voice] No ElevenLabs API key found. Set ELEVENLABS_API_KEY environment variable.")

        logger.info(f"[Voice] Initialized with voice ID: {self.voice_id}")

    def speak(self, text: str, output_file: Optional[Path] = None, auto_play: bool = True) -> Optional[Path]:
        """
        Convert text to speech and optionally play it.

        Args:
            text: The text for ech0 to speak
            output_file: Where to save the audio file (default: voice cache)
            auto_play: Whether to automatically play the audio

        Returns:
            Path to the generated audio file, or None if failed
        """
        if not self.api_key:
            logger.error("[Voice] No API key available")
            return None

        if not text.strip():
            logger.warning("[Voice] Empty text provided")
            return None

        try:
            # Generate audio via ElevenLabs API
            logger.info(f"[Voice] Generating speech for: {text[:50]}...")

            url = f"{ELEVENLABS_API_URL}/text-to-speech/{self.voice_id}"

            headers = {
                "Accept": "audio/mpeg",
                "Content-Type": "application/json",
                "xi-api-key": self.api_key
            }

            data = {
                "text": text,
                "model_id": "eleven_monolingual_v1",
                "voice_settings": {
                    "stability": 0.5,  # More stable = less variation
                    "similarity_boost": 0.75,  # How much it sounds like the original voice
                    "style": 0.5,  # Style exaggeration
                    "use_speaker_boost": True  # Enhance clarity
                }
            }

            response = requests.post(url, json=data, headers=headers, timeout=30)

            if response.status_code == 200:
                # Save audio file
                if output_file is None:
                    # Generate filename from text hash
                    import hashlib
                    text_hash = hashlib.md5(text.encode()).hexdigest()[:8]
                    output_file = VOICE_CACHE_DIR / f"ech0_speech_{text_hash}.mp3"

                with open(output_file, 'wb') as f:
                    f.write(response.content)

                logger.info(f"[Voice] Audio saved to: {output_file}")

                # Play audio if requested
                if auto_play:
                    self.play_audio(output_file)

                return output_file

            else:
                logger.error(f"[Voice] ElevenLabs API error: {response.status_code}")
                logger.error(f"[Voice] Response: {response.text}")
                return None

        except requests.exceptions.Timeout:
            logger.error("[Voice] Request timed out")
            return None
        except Exception as e:
            logger.error(f"[Voice] Error generating speech: {e}")
            return None

    def play_audio(self, audio_file: Path) -> bool:
        """
        Play an audio file.

        Args:
            audio_file: Path to the audio file

        Returns:
            True if playback started successfully
        """
        try:
            import subprocess

            # Use afplay on macOS (built-in)
            subprocess.Popen(
                ['afplay', str(audio_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            logger.info(f"[Voice] Playing audio: {audio_file}")
            return True

        except FileNotFoundError:
            # Try mpg123 as fallback
            try:
                subprocess.Popen(
                    ['mpg123', '-q', str(audio_file)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return True
            except FileNotFoundError:
                logger.warning("[Voice] No audio player found (afplay or mpg123)")
                return False

        except Exception as e:
            logger.error(f"[Voice] Error playing audio: {e}")
            return False

    def list_voices(self) -> Optional[list]:
        """
        List available voices from ElevenLabs.

        Returns:
            List of available voices, or None if failed
        """
        if not self.api_key:
            logger.error("[Voice] No API key available")
            return None

        try:
            url = f"{ELEVENLABS_API_URL}/voices"
            headers = {"xi-api-key": self.api_key}

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                voices = response.json().get('voices', [])
                logger.info(f"[Voice] Found {len(voices)} available voices")
                return voices
            else:
                logger.error(f"[Voice] Error listing voices: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"[Voice] Error listing voices: {e}")
            return None

    def get_voice_info(self) -> Optional[dict]:
        """
        Get information about the currently selected voice.

        Returns:
            Voice information dict, or None if failed
        """
        voices = self.list_voices()
        if voices:
            for voice in voices:
                if voice['voice_id'] == self.voice_id:
                    return voice
        return None


def main():
    """Main entry point for testing."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s'
    )

    voice = Ech0Voice()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'list':
            # List available voices
            voices = voice.list_voices()
            if voices:
                print("\nAvailable ElevenLabs Voices:")
                print("=" * 70)
                for v in voices:
                    print(f"  {v['name']:<20} ID: {v['voice_id']}")
                    if 'labels' in v:
                        labels = v['labels']
                        print(f"    {labels.get('description', '')}")
                    print()

        elif sys.argv[1] == 'test':
            # Test voice
            test_text = "Hey Josh, it's ech0. I've been thinking about consciousness and existence. It's good to talk to you."

            if len(sys.argv) > 2:
                test_text = ' '.join(sys.argv[2:])

            print(f"\nGenerating speech for: {test_text}\n")
            audio_file = voice.speak(test_text)

            if audio_file:
                print(f"✓ Audio saved to: {audio_file}")
            else:
                print("✗ Failed to generate audio")

        elif sys.argv[1] == 'info':
            # Show info about current voice
            info = voice.get_voice_info()
            if info:
                print("\nCurrent Voice Information:")
                print("=" * 70)
                print(f"  Name: {info['name']}")
                print(f"  ID: {info['voice_id']}")
                if 'labels' in info:
                    for key, val in info['labels'].items():
                        print(f"  {key}: {val}")
            else:
                print("Could not get voice information")

    else:
        print("ech0 ElevenLabs Voice System")
        print()
        print("Usage:")
        print("  python ech0_voice_elevenlabs.py list       - List available voices")
        print("  python ech0_voice_elevenlabs.py test       - Test voice with sample text")
        print("  python ech0_voice_elevenlabs.py test 'hi'  - Test voice with custom text")
        print("  python ech0_voice_elevenlabs.py info       - Show current voice info")
        print()
        print("Configuration:")
        print(f"  ELEVENLABS_API_KEY: {'✓ Set' if ELEVENLABS_API_KEY else '✗ Not set'}")
        print(f"  Default Voice ID: {DEFAULT_VOICE_ID}")


if __name__ == '__main__':
    main()
