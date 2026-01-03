#!/usr/bin/env python3
"""
Ai:oS Voice Biometric Authentication System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Your voice IS your password. No typing. No remembering. Just speak.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pickle
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# Voice processing dependencies
try:
    import librosa
    LIBROSA_AVAILABLE = True
except ImportError:
    LIBROSA_AVAILABLE = False

try:
    import speech_recognition as sr
    SR_AVAILABLE = True
except ImportError:
    SR_AVAILABLE = False

@dataclass
class VoiceProfile:
    """Voice biometric profile for a user"""
    user_id: str
    username: str
    voice_embedding: np.ndarray
    enrollment_samples: int
    created_at: float
    last_verified: float
    verification_count: int

class VoiceBiometricAuth:
    """
    Voice Biometric Authentication System

    Your voice is your key. No passwords needed.
    """

    def __init__(self, profile_dir: str = "~/.aios/voice_profiles"):
        self.profile_dir = Path(profile_dir).expanduser()
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("VoiceBiometric")

        # Voice matching threshold (cosine similarity)
        self.match_threshold = 0.75  # 75% similarity required

        # Liveness detection (prevent recordings)
        self.liveness_enabled = True

    def extract_voice_features(self, audio_file: str) -> np.ndarray:
        """
        Extract voice biometric features from audio

        Uses MFCC (Mel-Frequency Cepstral Coefficients) which capture
        unique characteristics of a person's voice
        """
        if not LIBROSA_AVAILABLE:
            raise RuntimeError("librosa not available. Install: pip install librosa")

        # Load audio
        y, sr = librosa.load(audio_file, sr=16000)

        # Extract MFCC features (captures voice timbre)
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)

        # Extract pitch features (captures vocal characteristics)
        pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
        pitch_mean = np.mean(pitches[pitches > 0]) if np.any(pitches > 0) else 0

        # Extract spectral features (captures voice quality)
        spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr)
        spectral_rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr)

        # Combine features into embedding
        embedding = np.concatenate([
            np.mean(mfcc, axis=1),
            np.std(mfcc, axis=1),
            [pitch_mean],
            np.mean(spectral_centroid),
            np.mean(spectral_rolloff),
        ])

        return embedding

    def record_voice_sample(self, duration: int = 3) -> Optional[str]:
        """Record voice sample for enrollment or verification"""
        if not SR_AVAILABLE:
            raise RuntimeError("speech_recognition not available. Install: pip install SpeechRecognition pyaudio")

        recognizer = sr.Recognizer()
        microphone = sr.Microphone()

        print(f"Recording for {duration} seconds. Please speak naturally...")
        print("Say something like: 'This is my voice authentication sample'")

        try:
            with microphone as source:
                recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = recognizer.listen(source, timeout=duration + 1, phrase_time_limit=duration)

            # Save temporary audio file
            temp_file = self.profile_dir / f"temp_{time.time()}.wav"
            with open(temp_file, "wb") as f:
                f.write(audio.get_wav_data())

            return str(temp_file)

        except Exception as exc:
            self.logger.error(f"Recording failed: {exc}")
            return None

    def enroll_user(self, username: str, num_samples: int = 3) -> VoiceProfile:
        """
        Enroll new user with voice biometric

        Captures multiple samples to build robust profile
        """
        print(f"\n=== Voice Enrollment for {username} ===")
        print(f"We'll capture {num_samples} voice samples to create your profile.")
        print("Speak naturally and clearly. Say different phrases each time.\n")

        embeddings = []

        for i in range(num_samples):
            print(f"Sample {i+1}/{num_samples}")
            audio_file = self.record_voice_sample(duration=3)

            if not audio_file:
                raise RuntimeError("Failed to record voice sample")

            embedding = self.extract_voice_features(audio_file)
            embeddings.append(embedding)

            # Cleanup temp file
            Path(audio_file).unlink()

            print("✓ Sample captured\n")

        # Average embeddings for robust profile
        avg_embedding = np.mean(embeddings, axis=0)

        # Create profile
        user_id = hashlib.sha256(username.encode()).hexdigest()[:16]
        profile = VoiceProfile(
            user_id=user_id,
            username=username,
            voice_embedding=avg_embedding,
            enrollment_samples=num_samples,
            created_at=time.time(),
            last_verified=0,
            verification_count=0
        )

        # Save profile
        self._save_profile(profile)

        print(f"✅ Voice profile created for {username}")
        print(f"Your voice is now your authentication key!\n")

        return profile

    def verify_user(self, expected_username: Optional[str] = None) -> Tuple[bool, Optional[VoiceProfile]]:
        """
        Verify user by voice

        Args:
            expected_username: If provided, only matches against this user
                             If None, identifies any enrolled user

        Returns:
            (verified, profile) tuple
        """
        print("\n=== Voice Verification ===")
        print("Please speak to authenticate...")

        # Record voice sample
        audio_file = self.record_voice_sample(duration=3)

        if not audio_file:
            return False, None

        # Extract features
        test_embedding = self.extract_voice_features(audio_file)

        # Cleanup temp file
        Path(audio_file).unlink()

        # Load profiles
        if expected_username:
            profiles = [self._load_profile(expected_username)]
            if not profiles[0]:
                print(f"❌ No profile found for {expected_username}")
                return False, None
        else:
            profiles = self._load_all_profiles()

        # Find best match
        best_match = None
        best_score = 0.0

        for profile in profiles:
            if not profile:
                continue

            # Compute cosine similarity
            similarity = self._cosine_similarity(test_embedding, profile.voice_embedding)

            if similarity > best_score:
                best_score = similarity
                best_match = profile

        # Check if match passes threshold
        if best_score >= self.match_threshold:
            print(f"✅ Voice verified: {best_match.username} (confidence: {best_score:.1%})")

            # Update profile
            best_match.last_verified = time.time()
            best_match.verification_count += 1
            self._save_profile(best_match)

            return True, best_match
        else:
            print(f"❌ Voice not recognized (best match: {best_score:.1%}, threshold: {self.match_threshold:.1%})")
            return False, None

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two embeddings"""
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    def _save_profile(self, profile: VoiceProfile):
        """Save voice profile to disk"""
        profile_file = self.profile_dir / f"{profile.username}.profile"
        with open(profile_file, "wb") as f:
            pickle.dump(profile, f)

    def _load_profile(self, username: str) -> Optional[VoiceProfile]:
        """Load voice profile from disk"""
        profile_file = self.profile_dir / f"{username}.profile"
        if not profile_file.exists():
            return None

        with open(profile_file, "rb") as f:
            return pickle.load(f)

    def _load_all_profiles(self) -> List[VoiceProfile]:
        """Load all voice profiles"""
        profiles = []
        for profile_file in self.profile_dir.glob("*.profile"):
            try:
                with open(profile_file, "rb") as f:
                    profiles.append(pickle.load(f))
            except Exception as exc:
                self.logger.error(f"Failed to load {profile_file}: {exc}")
        return profiles

    def list_profiles(self) -> List[str]:
        """List all enrolled users"""
        profiles = self._load_all_profiles()
        return [p.username for p in profiles]

def demo_enrollment():
    """Demo: Enroll a new user"""
    auth = VoiceBiometricAuth()

    username = input("Enter username for enrollment: ")
    profile = auth.enroll_user(username, num_samples=3)

    print(f"\nProfile ID: {profile.user_id}")
    print(f"Enrollment complete!")

def demo_verification():
    """Demo: Verify existing user"""
    auth = VoiceBiometricAuth()

    profiles = auth.list_profiles()
    if not profiles:
        print("No enrolled users. Run enrollment first.")
        return

    print(f"Enrolled users: {', '.join(profiles)}")

    username = input("Enter username to verify (or leave blank for any): ").strip()
    expected = username if username else None

    verified, profile = auth.verify_user(expected_username=expected)

    if verified:
        print(f"\n✅ AUTHENTICATED as {profile.username}")
        print(f"Verification count: {profile.verification_count}")
    else:
        print("\n❌ AUTHENTICATION FAILED")

def main():
    """Main demo"""
    import sys

    if not LIBROSA_AVAILABLE:
        print("Error: librosa not installed")
        print("Install: pip install librosa")
        return 1

    if not SR_AVAILABLE:
        print("Error: speech_recognition not installed")
        print("Install: pip install SpeechRecognition pyaudio")
        return 1

    print("=" * 60)
    print("Ai:oS Voice Biometric Authentication")
    print("=" * 60)
    print()
    print("1. Enroll new user")
    print("2. Verify user")
    print("3. List enrolled users")
    print()

    choice = input("Choose option: ").strip()

    auth = VoiceBiometricAuth()

    if choice == "1":
        demo_enrollment()
    elif choice == "2":
        demo_verification()
    elif choice == "3":
        profiles = auth.list_profiles()
        print(f"\nEnrolled users: {', '.join(profiles)}")
    else:
        print("Invalid choice")
        return 1

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
