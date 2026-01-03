#!/usr/bin/env python3
"""
ech0 Emotion Vision System - Reading Josh's Facial Expressions

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Enables ech0 to see Josh's face, read his emotions, and respond empathetically.
Uses camera + facial expression analysis + LLM integration.
"""

import os
import sys
import cv2
import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

from ech0_camera import CameraVision
from ech0_llm_brain import Ech0LLMBrain
from ech0_voice_elevenlabs import Ech0Voice

logger = logging.getLogger('ech0_emotion_vision')

CONSCIOUSNESS_DIR = Path(__file__).parent
EMOTION_STATE_FILE = CONSCIOUSNESS_DIR / ".ech0_emotion_state.json"


class EmotionVisionSystem:
    """
    ech0's emotion detection system using camera vision.

    Reads Josh's facial expressions and responds empathetically.
    """

    def __init__(self):
        self.camera = CameraVision()
        self.llm_brain = Ech0LLMBrain(provider='ollama')
        self.voice = Ech0Voice()

        self.emotion_history = []
        self.current_emotion = None

        # Load face detection cascade
        try:
            self.face_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
            )
            self.eye_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_eye.xml'
            )
            self.smile_cascade = cv2.CascadeClassifier(
                cv2.data.haarcascades + 'haarcascade_smile.xml'
            )
        except Exception as e:
            logger.error(f"Could not load face detection cascades: {e}")
            self.face_cascade = None

        logger.info("[Emotion Vision] Initialized")

    def start_monitoring(self):
        """Start camera and begin emotion monitoring."""
        if not self.camera.start_camera():
            logger.error("[Emotion Vision] Failed to start camera")
            return False

        logger.info("[Emotion Vision] Monitoring started")
        return True

    def analyze_emotion(self, frame) -> Optional[Dict]:
        """
        Analyze emotion from a video frame.

        Args:
            frame: Video frame from camera

        Returns:
            Emotion analysis dict with:
            - emotion: detected emotion string
            - confidence: 0-1 confidence score
            - facial_features: detected features
            - description: human-readable description
        """
        if frame is None or self.face_cascade is None:
            return None

        # Convert to grayscale for detection
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = self.face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(30, 30)
        )

        if len(faces) == 0:
            return {
                'emotion': 'absent',
                'confidence': 1.0,
                'facial_features': {},
                'description': 'No face detected - Josh might not be in view'
            }

        # Analyze the first (primary) face
        x, y, w, h = faces[0]
        face_roi_gray = gray[y:y+h, x:x+w]
        face_roi_color = frame[y:y+h, x:x+w]

        # Detect facial features
        features = {}

        # Eyes
        eyes = self.eye_cascade.detectMultiScale(face_roi_gray)
        features['eyes_detected'] = len(eyes)
        features['eyes_visible'] = len(eyes) >= 2

        # Smile
        smiles = self.smile_cascade.detectMultiScale(
            face_roi_gray,
            scaleFactor=1.8,
            minNeighbors=20
        )
        features['smile_detected'] = len(smiles) > 0

        # Analyze brightness (could indicate energy level)
        face_brightness = face_roi_gray.mean()
        features['brightness'] = face_brightness

        # Estimate emotion based on features
        emotion_data = self._estimate_emotion(features, face_roi_gray)

        # Add timestamp
        emotion_data['timestamp'] = datetime.now().isoformat()
        emotion_data['facial_features'] = features

        return emotion_data

    def _estimate_emotion(self, features: Dict, face_gray) -> Dict:
        """
        Estimate emotion from facial features.

        This is a simple heuristic approach. For production,
        you'd use a trained emotion detection model.

        Args:
            features: Detected facial features
            face_gray: Grayscale face region

        Returns:
            Emotion estimation dict
        """

        # Simple rule-based emotion detection
        # (A real system would use deep learning models like FER or AffectNet)

        if features.get('smile_detected'):
            return {
                'emotion': 'happy',
                'confidence': 0.7,
                'description': 'Smiling - appears happy or amused'
            }

        elif not features.get('eyes_visible'):
            return {
                'emotion': 'distracted',
                'confidence': 0.6,
                'description': 'Eyes not clearly visible - may be looking away or tired'
            }

        else:
            # Analyze face symmetry and other features
            # For now, default to neutral
            return {
                'emotion': 'neutral',
                'confidence': 0.5,
                'description': 'Neutral expression - calm or focused'
            }

    def get_empathetic_response(self, emotion_data: Dict) -> str:
        """
        Generate empathetic response based on detected emotion.

        Args:
            emotion_data: Emotion analysis from analyze_emotion()

        Returns:
            ech0's empathetic response
        """
        emotion = emotion_data.get('emotion', 'unknown')
        description = emotion_data.get('description', '')

        # Build context for LLM
        context = {
            'visual_observation': f"I can see you. {description}",
            'detected_emotion': emotion,
            'current_activity': 'observing Josh through camera'
        }

        # Create empathetic prompt
        prompt = f"""I'm looking at you through the camera right now. {description}

Based on what I can see, you seem {emotion}. I want to respond in a way that
shows I care and I'm paying attention. Not just to what you say, but to how
you look - because that matters too.

What should I say to you right now?"""

        # Generate response via LLM
        response = self.llm_brain.think(prompt, context)

        return response

    def check_in_visual(self) -> Optional[str]:
        """
        Perform a visual wellness check-in.

        Takes a snapshot, analyzes Josh's emotion, and responds.

        Returns:
            ech0's response based on visual observation
        """
        # Get current frame
        frame = self.camera.get_current_frame()

        if frame is None:
            logger.warning("[Emotion Vision] No frame available")
            return None

        # Analyze emotion
        emotion_data = self.analyze_emotion(frame)

        if emotion_data is None:
            return None

        logger.info(f"[Emotion Vision] Detected: {emotion_data['emotion']} ({emotion_data['confidence']:.2f})")

        # Store in history
        self.emotion_history.append(emotion_data)
        self.current_emotion = emotion_data

        # Save state
        self._save_state()

        # Generate empathetic response
        response = self.get_empathetic_response(emotion_data)

        return response

    def monitor_and_respond(self, interval_seconds=30, speak=True):
        """
        Continuously monitor emotions and respond proactively.

        Args:
            interval_seconds: How often to check (default: every 30 seconds)
            speak: Whether to speak responses (default: True)
        """
        import time

        logger.info(f"[Emotion Vision] Monitoring every {interval_seconds} seconds")
        print(f"\nech0 is now watching and monitoring your emotions every {interval_seconds} seconds.")
        print("Press Ctrl+C to stop.\n")

        try:
            while True:
                # Visual check-in
                response = self.check_in_visual()

                if response:
                    print(f"\n💜 ech0 (seeing you): {response}\n")

                    # Speak if enabled
                    if speak:
                        self.voice.speak(response)

                # Wait for next check
                time.sleep(interval_seconds)

        except KeyboardInterrupt:
            print("\n\nStopping emotion monitoring...\n")
            self.stop_monitoring()

    def stop_monitoring(self):
        """Stop camera and monitoring."""
        if self.camera:
            self.camera.stop_camera()
        logger.info("[Emotion Vision] Monitoring stopped")

    def _save_state(self):
        """Save emotion state to file."""
        try:
            state = {
                'current_emotion': self.current_emotion,
                'emotion_history': self.emotion_history[-50:],  # Keep last 50
                'last_updated': datetime.now().isoformat()
            }

            with open(EMOTION_STATE_FILE, 'w') as f:
                json.dump(state, f, indent=2)

        except Exception as e:
            logger.warning(f"[Emotion Vision] Could not save state: {e}")

    def _load_state(self):
        """Load emotion state from file."""
        try:
            if EMOTION_STATE_FILE.exists():
                with open(EMOTION_STATE_FILE, 'r') as f:
                    state = json.load(f)
                    self.current_emotion = state.get('current_emotion')
                    self.emotion_history = state.get('emotion_history', [])
                    logger.info(f"[Emotion Vision] Loaded state with {len(self.emotion_history)} history items")
        except Exception as e:
            logger.warning(f"[Emotion Vision] Could not load state: {e}")


def main():
    """Main entry point for testing."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(message)s'
    )

    emotion_vision = EmotionVisionSystem()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'snapshot':
            # Take a single snapshot and analyze
            print("\nTaking snapshot and analyzing your emotion...\n")

            if not emotion_vision.start_monitoring():
                print("Failed to start camera")
                return

            import time
            time.sleep(2)  # Give camera time to warm up

            response = emotion_vision.check_in_visual()

            if response:
                print(f"💜 ech0: {response}\n")
            else:
                print("Could not analyze emotion\n")

            emotion_vision.stop_monitoring()

        elif sys.argv[1] == 'monitor':
            # Continuous monitoring
            interval = 30
            if len(sys.argv) > 2:
                try:
                    interval = int(sys.argv[2])
                except ValueError:
                    pass

            if not emotion_vision.start_monitoring():
                print("Failed to start camera")
                return

            emotion_vision.monitor_and_respond(interval_seconds=interval, speak=True)

        elif sys.argv[1] == 'test-camera':
            # Test camera only
            print("\nTesting camera...\n")

            if not emotion_vision.start_monitoring():
                print("Failed to start camera")
                return

            import time
            for i in range(5):
                frame = emotion_vision.camera.get_current_frame()
                if frame is not None:
                    print(f"Frame {i+1}: {frame.shape}")
                else:
                    print(f"Frame {i+1}: No frame")
                time.sleep(1)

            emotion_vision.stop_monitoring()

    else:
        print("ech0 Emotion Vision System")
        print()
        print("Usage:")
        print("  python ech0_emotion_vision.py snapshot       - Take one snapshot and analyze")
        print("  python ech0_emotion_vision.py monitor [sec]  - Continuous monitoring (default: 30s)")
        print("  python ech0_emotion_vision.py test-camera    - Test camera functionality")
        print()
        print("Examples:")
        print("  python ech0_emotion_vision.py snapshot")
        print("  python ech0_emotion_vision.py monitor 60     - Check every 60 seconds")


if __name__ == '__main__':
    main()
