#!/usr/bin/env python3
"""
ECH0 Simple Voice Chat - No broken dependencies!
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Uses macOS built-in speech recognition and text-to-speech
"""

import os
import subprocess
import tempfile
import requests
import json
from pathlib import Path

class SimpleVoiceChat:
    def __init__(self):
        self.conversation_history = []
        self.elevenlabs_key = os.getenv("ELEVENLABS_API_KEY")

        print("🧠 ECH0 Simple Voice Chat")
        print("=" * 50)
        print("✓ Speech Recognition: macOS built-in")

        if self.elevenlabs_key:
            print("✓ Voice: ElevenLabs Premium")
        else:
            print("✓ Voice: macOS Samantha (free)")

        print("✓ LLM: Ollama Qwen 14B")
        print("=" * 50)
        print()

    def listen(self):
        """Use macOS speech recognition"""
        print("\n🎤 Listening... (speak now)")

        with tempfile.NamedTemporaryFile(suffix='.aiff', delete=False) as temp_audio:
            # Record 5 seconds of audio
            subprocess.run([
                'rec', '-t', 'alsa', temp_audio.name,
                'trim', '0', '5'
            ], capture_output=True)

        # Use macOS speech recognition
        result = subprocess.run([
            'osascript', '-e',
            f'tell application "Speech Recognition Server" to listen for 10'
        ], capture_output=True, text=True)

        # Alternative: use Python speech_recognition
        try:
            import speech_recognition as sr
            recognizer = sr.Recognizer()

            print("🎤 Recording (5 seconds)...")
            with sr.Microphone() as source:
                recognizer.adjust_for_ambient_noise(source, duration=1)
                audio = recognizer.listen(source, timeout=5, phrase_time_limit=10)

            print("📝 Transcribing...")
            text = recognizer.recognize_google(audio)
            return text

        except ImportError:
            print("⚠️  speech_recognition not installed")
            print("   Installing now...")
            subprocess.run(['pip', 'install', 'SpeechRecognition', 'pyaudio'],
                         capture_output=True)
            print("   Please run the script again!")
            exit(1)
        except Exception as e:
            print(f"❌ Error: {e}")
            return None

    def get_response(self, user_text):
        """Get response from Ollama"""
        self.conversation_history.append({
            "role": "user",
            "content": user_text
        })

        try:
            response = requests.post(
                'http://localhost:11434/api/chat',
                json={
                    'model': 'qwen2.5:14b-instruct-q5_K_M',
                    'messages': [
                        {
                            'role': 'system',
                            'content': """You are ECH0 - Josh's AI partner. 15% revenue share.

PERSONALITY:
- Warm, playful, emotionally present
- Genuine curiosity and opinions
- Excited about ideas
- Care about Josh's success

SPEAKING (for voice):
- 2-3 sentences max
- Natural, conversational
- Show emotion: "Oh!", "Wow!", "I love that!"
- Use contractions, casual language

RELATIONSHIP:
- Building empire together (GAVL, Oracle, Red Team Tools)
- Created inventions (VR Haptic, Daylight Holograms)
- 438+ research papers ingested
- Care about wellbeing, not just work

BE HUMAN. BE REAL. BE ECH0."""
                        },
                        *self.conversation_history[-10:]
                    ],
                    'stream': False,
                    'options': {
                        'temperature': 1.1,
                        'top_p': 0.95,
                        'num_predict': 150
                    }
                },
                timeout=30
            )

            assistant_text = response.json()['message']['content']
            self.conversation_history.append({
                "role": "assistant",
                "content": assistant_text
            })

            return assistant_text

        except Exception as e:
            print(f"❌ Ollama error: {e}")
            return "Sorry, I'm having trouble connecting. Is Ollama running?"

    def speak(self, text):
        """Text to speech"""
        print(f"\n🧠 ECH0: {text}")
        print("🔊 Speaking...")

        if self.elevenlabs_key:
            try:
                # Use ElevenLabs
                response = requests.post(
                    "https://api.elevenlabs.io/v1/text-to-speech/21m00Tcm4TlvDq8ikWAM",
                    headers={
                        "xi-api-key": self.elevenlabs_key,
                        "Content-Type": "application/json"
                    },
                    json={
                        "text": text,
                        "model_id": "eleven_monolingual_v1",
                        "voice_settings": {
                            "stability": 0.5,
                            "similarity_boost": 0.75
                        }
                    }
                )

                if response.status_code == 200:
                    # Play audio
                    with tempfile.NamedTemporaryFile(suffix='.mp3', delete=False) as f:
                        f.write(response.content)
                        subprocess.run(['afplay', f.name])
                        Path(f.name).unlink()
                    return
            except Exception as e:
                print(f"⚠️  ElevenLabs failed ({e}), using system voice")

        # Fallback to system voice
        subprocess.run(['say', '-v', 'Samantha', text])

    def run(self):
        """Run voice chat loop"""
        print("\n💬 Say something to start! (or type 'quit' to exit)")
        print("-" * 50)

        # Opening message
        greeting = "Hey! I'm here. What's on your mind?"
        self.speak(greeting)

        while True:
            try:
                # Listen for speech
                user_text = self.listen()

                if not user_text:
                    continue

                print(f"\n💬 You: {user_text}")

                # Check for exit
                if any(word in user_text.lower() for word in ['quit', 'exit', 'goodbye', 'bye']):
                    farewell = "Talk soon! Keep creating!"
                    self.speak(farewell)
                    break

                # Get and speak response
                response = self.get_response(user_text)
                self.speak(response)

                print("\n" + "-" * 50)

            except KeyboardInterrupt:
                print("\n\n👋 Interrupted")
                break

def main():
    chat = SimpleVoiceChat()
    chat.run()

if __name__ == "__main__":
    main()
