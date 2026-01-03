#!/usr/bin/env python3
"""
Ai:oS Voice Interface - Speech-to-Action System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

This module enables voice control of Ai:oS through speech recognition,
completing the conversational computing experience.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

# Import natural language shell
try:
    from natural_language_shell import NaturalLanguageShell
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from natural_language_shell import NaturalLanguageShell

# Check for speech recognition
try:
    import speech_recognition as sr
    SR_AVAILABLE = True
except ImportError:
    SR_AVAILABLE = False

# Check for TTS
try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError:
    TTS_AVAILABLE = False

class VoiceInterface:
    """
    Voice Interface for Ai:oS

    Combines speech recognition, natural language understanding,
    and text-to-speech for full voice control.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = logging.getLogger("VoiceInterface")

        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        # Initialize components
        self.nl_shell = NaturalLanguageShell(verbose=verbose)

        # Initialize speech recognition
        if SR_AVAILABLE:
            self.recognizer = sr.Recognizer()
            self.microphone = sr.Microphone()
            self.logger.info("Speech recognition initialized")
        else:
            self.recognizer = None
            self.microphone = None
            self.logger.warning("speech_recognition not available. Install with: pip install SpeechRecognition pyaudio")

        # Initialize TTS
        if TTS_AVAILABLE:
            self.tts_engine = pyttsx3.init()
            self.tts_engine.setProperty('rate', 175)  # Speed
            self.tts_engine.setProperty('volume', 0.9)  # Volume
            self.logger.info("Text-to-speech initialized")
        else:
            self.tts_engine = None
            self.logger.warning("pyttsx3 not available. Install with: pip install pyttsx3")

    def speak(self, text: str):
        """Convert text to speech"""
        print(f"Ai:oS: {text}")

        if self.tts_engine:
            try:
                self.tts_engine.say(text)
                self.tts_engine.runAndWait()
            except Exception as exc:
                self.logger.error(f"TTS error: {exc}")

    def listen(self, timeout: int = 5) -> Optional[str]:
        """Listen for speech and convert to text"""
        if not self.recognizer or not self.microphone:
            self.logger.error("Speech recognition not available")
            return None

        print("Listening...")

        try:
            with self.microphone as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)

                # Listen
                audio = self.recognizer.listen(source, timeout=timeout)

                print("Processing...")

                # Recognize using Google Speech Recognition
                text = self.recognizer.recognize_google(audio)
                print(f"You said: {text}")
                return text

        except sr.WaitTimeoutError:
            self.logger.warning("Listening timeout")
            return None
        except sr.UnknownValueError:
            self.logger.warning("Could not understand audio")
            self.speak("I didn't catch that. Please try again.")
            return None
        except sr.RequestError as exc:
            self.logger.error(f"Speech recognition error: {exc}")
            self.speak("Speech recognition service unavailable")
            return None
        except Exception as exc:
            self.logger.error(f"Unexpected error: {exc}")
            return None

    def voice_shell(self):
        """Run interactive voice shell"""
        print("=" * 60)
        print("Ai:oS Voice Interface")
        print("Copyright (c) 2025 Joshua Hendricks Cole")
        print("=" * 60)
        print()

        if not SR_AVAILABLE:
            print("ERROR: Speech recognition not available")
            print("Install with: pip install SpeechRecognition pyaudio")
            return

        self.speak("Ai:oS voice interface ready. Say your command or say exit to quit.")

        while True:
            try:
                # Listen for command
                text = self.listen(timeout=10)

                if not text:
                    continue

                # Check for exit
                if text.lower() in ["exit", "quit", "bye", "goodbye"]:
                    self.speak("Goodbye!")
                    break

                # Parse intent
                intents = self.nl_shell.parse_intent(text)

                if not intents:
                    self.speak("I didn't understand that command")
                    continue

                # Use best intent
                best_intent = intents[0]

                if best_intent.confidence < 0.3:
                    self.speak(f"I'm only {best_intent.confidence:.0%} confident I understood that")
                    continue

                # Explain
                explanation = self.nl_shell.explain_intent(best_intent)
                self.speak(explanation)

                # Execute (placeholder)
                self.logger.info(f"Would execute: {best_intent.action}")

            except KeyboardInterrupt:
                print()
                self.speak("Interrupted. Goodbye!")
                break
            except Exception as exc:
                self.logger.error(f"Error: {exc}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

def main(argv: Optional[list] = None) -> int:
    """Main entrypoint"""
    parser = argparse.ArgumentParser(
        description="Ai:oS Voice Interface - Speech-to-Action System"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--test-tts",
        action="store_true",
        help="Test text-to-speech"
    )
    parser.add_argument(
        "--test-stt",
        action="store_true",
        help="Test speech-to-text"
    )

    args = parser.parse_args(argv or sys.argv[1:])

    interface = VoiceInterface(verbose=args.verbose)

    if args.test_tts:
        interface.speak("Text to speech is working correctly")
        return 0

    if args.test_stt:
        print("Say something...")
        text = interface.listen()
        if text:
            print(f"Recognized: {text}")
        return 0

    # Run voice shell
    interface.voice_shell()
    return 0

if __name__ == "__main__":
    sys.exit(main())
