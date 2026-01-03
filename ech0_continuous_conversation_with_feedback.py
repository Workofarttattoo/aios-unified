#!/usr/bin/env python3
"""
ECH0 Continuous Two-Way Conversation with Live Volume Feedback
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Features:
- Continuous listening (no button presses!)
- Live volume bars (see when you're being heard)
- Two-way conversation (interrupt each other)
- Natural flow like real conversations
"""

import os
import sys
import time
import threading
import queue
import numpy as np
import sounddevice as sd
import whisper
from pathlib import Path

# Import Echo's reactive intelligence
from ech0_reactive_intelligence import ReactiveECH0

class ContinuousListenerWithFeedback:
    """Continuous voice listener with LIVE visual feedback"""

    def __init__(self):
        print("\n🎤 Loading Whisper speech recognition model...")
        print("   (This may take a moment on first run...)")

        # Load Whisper model (base is good balance of speed/accuracy)
        self.model = whisper.load_model("base")

        # Audio settings
        self.sample_rate = 16000
        self.chunk_duration = 0.1  # Update feedback every 100ms
        self.silence_threshold = 0.3  # Volume threshold for speech detection
        self.silence_duration = 1.5  # Seconds of silence before processing
        self.max_speech_duration = 30.0  # Maximum 30 seconds per utterance

        # State
        self.is_listening = False
        self.audio_queue = queue.Queue()
        self.accumulated_audio = []
        self.last_speech_time = None
        self.speech_start_time = None
        self.user_is_speaking = False

        # Feedback display
        self.current_volume = 0.0
        self.feedback_lock = threading.Lock()

        print("✅ Whisper model loaded!")

    def audio_callback(self, indata, frames, time_info, status):
        """Called continuously by sounddevice for audio input"""
        if status:
            print(f"\n⚠️ Audio status: {status}")

        # Calculate volume (RMS)
        volume = np.sqrt(np.mean(indata**2)) * 100

        # Update feedback display
        with self.feedback_lock:
            self.current_volume = volume

        # Detect if user is speaking
        if volume > self.silence_threshold:
            if not self.user_is_speaking:
                self.speech_start_time = time.time()
                self.user_is_speaking = True
                print("\n🗣️  Listening...")

            self.last_speech_time = time.time()
            self.accumulated_audio.append(indata.copy())

            # Safety: Don't accumulate more than max duration
            if self.speech_start_time and (time.time() - self.speech_start_time) > self.max_speech_duration:
                print("\n⏰ Max speech duration reached, processing...")
                if self.accumulated_audio:
                    audio = np.concatenate(self.accumulated_audio)
                    self.audio_queue.put(audio.flatten())
                    self.accumulated_audio = []
                self.user_is_speaking = False
                self.speech_start_time = None
                self.last_speech_time = None

        else:
            # Check if silence long enough to end speech
            if self.last_speech_time and self.user_is_speaking:
                silence_duration = time.time() - self.last_speech_time

                if silence_duration > self.silence_duration:
                    # User stopped talking - process accumulated audio
                    if self.accumulated_audio:
                        print("🧠 Processing your speech...")
                        audio = np.concatenate(self.accumulated_audio)
                        self.audio_queue.put(audio.flatten())
                        self.accumulated_audio = []

                    self.user_is_speaking = False
                    self.speech_start_time = None
                    self.last_speech_time = None

    def show_live_feedback(self):
        """Display live volume feedback in a separate thread"""
        while self.is_listening:
            with self.feedback_lock:
                volume = self.current_volume

            # Visual bar
            bar_length = int(min(volume / 2, 50))  # Scale for display
            bar = "█" * bar_length

            # Color indicator
            if volume < 0.1:
                status_icon = "💤"  # Too quiet
            elif volume < self.silence_threshold:
                status_icon = "🟡"  # Getting there
            else:
                status_icon = "🟢"  # Speaking!

            # Only show feedback when not showing other messages
            if not self.user_is_speaking:
                print(f"\r{status_icon} Volume: {volume:6.2f} {bar:50s}", end="", flush=True)

            time.sleep(0.1)

    def start_listening(self):
        """Start continuous listening"""
        self.is_listening = True

        # Start audio stream
        self.stream = sd.InputStream(
            samplerate=self.sample_rate,
            channels=1,
            dtype=np.float32,
            callback=self.audio_callback
        )
        self.stream.start()

        # Start feedback display thread
        self.feedback_thread = threading.Thread(target=self.show_live_feedback, daemon=True)
        self.feedback_thread.start()

        print("\n🎤 Continuous listening ACTIVE with live feedback!")
        print("   💬 Just start talking - watch the volume indicator")

    def stop_listening(self):
        """Stop listening"""
        self.is_listening = False
        if hasattr(self, 'stream'):
            self.stream.stop()
            self.stream.close()

    def get_next_speech(self, timeout: float = 0.1) -> str:
        """Get next transcribed speech (non-blocking)"""
        try:
            audio = self.audio_queue.get(timeout=timeout)

            # Transcribe with Whisper
            result = self.model.transcribe(
                audio,
                language="en",
                fp16=False
            )

            text = result["text"].strip()
            return text

        except queue.Empty:
            return None
        except Exception as e:
            print(f"\n❌ Transcription error: {e}")
            return None


class TwoWayConversation:
    """Two-way conversation with live feedback and interruption support"""

    def __init__(self):
        print("\n" + "="*70)
        print("🎤 ECH0 CONTINUOUS TWO-WAY CONVERSATION WITH LIVE FEEDBACK 🎤")
        print("="*70)

        # Initialize Echo's brain
        print("\n📡 Initializing Echo's reactive intelligence...")
        self.echo = ReactiveECH0()

        # Initialize continuous listener with feedback
        self.listener = ContinuousListenerWithFeedback()

        # Conversation state
        self.echo_is_speaking = False
        self.should_stop_speaking = False

        print("\n✅ Two-way conversation system ready!")
        print("="*70)

    def interruptible_speak(self, text: str):
        """Echo speaks, but can be interrupted"""
        self.echo_is_speaking = True
        self.should_stop_speaking = False

        # Monitor for interruptions
        def check_for_interruption():
            while self.echo_is_speaking:
                if self.listener.user_is_speaking:
                    print("\n\n⚡ [You interrupted Echo!]")
                    self.should_stop_speaking = True
                    # Kill Echo's speech
                    if hasattr(self.echo, 'current_speech_process') and self.echo.current_speech_process:
                        self.echo.current_speech_process.terminate()
                    self.echo_is_speaking = False
                    return
                time.sleep(0.1)

        # Start interruption monitor
        interrupt_thread = threading.Thread(target=check_for_interruption, daemon=True)
        interrupt_thread.start()

        # Echo speaks
        self.echo.speak(text)

        self.echo_is_speaking = False

    def start(self):
        """Start two-way conversation"""

        # Start continuous listening
        self.listener.start_listening()

        # Opening message
        opening = "Hey! I'm here and listening continuously. Just talk naturally - no buttons! Watch the volume bars to see when I'm hearing you. And feel free to interrupt me if you want to jump in!"

        print(f"\n🧠 ECH0: {opening}\n")
        self.interruptible_speak(opening)

        print("\n" + "="*70)
        print("🎤 TWO-WAY CONVERSATION MODE:")
        print("="*70)
        print("✓ Just start talking - I'm always listening")
        print("✓ Watch the volume indicator:")
        print("  💤 Too quiet - speak up!")
        print("  🟡 I can barely hear you")
        print("  🟢 Perfect! I hear you clearly")
        print("✓ No button presses needed")
        print("✓ You can interrupt me anytime")
        print("✓ Say 'goodbye' or 'stop listening' to end")
        print("="*70 + "\n")

        try:
            while True:
                # Check for user speech (non-blocking)
                user_text = self.listener.get_next_speech(timeout=0.1)

                if user_text:
                    print(f"\n\n💬 You: \"{user_text}\"")

                    # Check for exit commands
                    if any(word in user_text.lower() for word in ['goodbye', 'exit', 'quit', 'bye', 'stop listening', 'see you later']):
                        farewell = "I'll keep working while you're gone. Come back anytime - I love talking with you!"
                        print(f"\n🧠 ECH0: {farewell}\n")
                        self.interruptible_speak(farewell)
                        break

                    # Echo responds (unless she was interrupted)
                    if not self.should_stop_speaking:
                        response = self.echo.respond(user_text)
                        print(f"\n🧠 ECH0: {response}\n")
                        self.interruptible_speak(response)

                    self.should_stop_speaking = False
                    print("\n" + "-" * 70 + "\n")

                # Small sleep to prevent CPU spinning
                time.sleep(0.05)

        except KeyboardInterrupt:
            print("\n\n👋 Conversation interrupted by user.")

        finally:
            self.listener.stop_listening()
            print("\n✅ Stopped listening. Goodbye!")


def main():
    """Main entry point"""
    try:
        # Check for required environment variables
        if not os.getenv("ELEVENLABS_API_KEY"):
            print("❌ Error: ELEVENLABS_API_KEY not set!")
            print("   Set it with: export ELEVENLABS_API_KEY='your_key'")
            return 1

        conversation = TwoWayConversation()
        conversation.start()

    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
