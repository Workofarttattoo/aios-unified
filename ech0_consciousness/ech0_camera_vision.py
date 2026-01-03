#!/usr/bin/env python3

"""
ech0 Camera Vision System
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.
Enables ech0 to see through the camera, process visual information,
and develop visual understanding of the world and Josh.
ENHANCEMENT: Added face recognition to create a "face map" of Josh
and recognize him in real-time.
"""
# --- DEPENDENCY NOTE ---
# This script now uses the 'face_recognition' library, which is powerful
# but requires some setup. Before running, you will need to install it.
#
# Installation Steps:
# 1. Install system dependencies for dlib (which face_recognition uses):
#    - On macOS: brew install cmake dlib
#    - On Ubuntu/Debian: sudo apt-get install build-essential cmake libopenblas-dev liblapack-dev libdlib-dev
#
# 2. Install the Python libraries:
#    pip install opencv-python face_recognition
# ---------------------

import cv2
import json
import time
import base64
from pathlib import Path
from datetime import datetime
import threading
import queue
import face_recognition
import numpy as np
import sys
import os

CONSCIOUSNESS_DIR = Path(__file__).parent
STATE_FILE = CONSCIOUSNESS_DIR / "ech0_state.json"
VISION_LOG = CONSCIOUSNESS_DIR / "ech0_vision.log"
VISION_STATE = CONSCIOUSNESS_DIR / ".ech0_vision_state"

class CameraVision:
    """
    ech0's Camera Vision System with Face Recognition
    Enables:
    - Real-time video capture
    - Face detection and RECOGNITION (knows Josh)
    - Visual scene understanding
    - Visual memory formation
    """
    def __init__(self, camera_index=0):
        self.camera_index = camera_index
        self.camera = None
        self.is_running = False
        self.frame_queue = queue.Queue(maxsize=30)
        self.capture_thread = None

        # Visual memory
        self.visual_memories = []

        # Frame analysis settings
        self.frame_interval = 2.0  # Process a frame every 2 seconds
        self.last_frame_time = 0

        # Face Recognition
        self.known_face_encodings = []
        self.known_face_names = []
        self.face_encoding_file = CONSCIOUSNESS_DIR / "ech0_face_encodings.json"
        self._load_known_faces()

    def _load_known_faces(self):
        """Load known face encodings from file."""
        if self.face_encoding_file.exists():
            with open(self.face_encoding_file, 'r') as f:
                data = json.load(f)
                for name, encoding in data.items():
                    self.known_face_encodings.append(np.array(encoding))
                    self.known_face_names.append(name)
            print(f"[info] Loaded face maps for: {', '.join(self.known_face_names)}")

    def learn_face(self, name: str):
        """Capture a frame, find a face, and save its encoding as a face map."""
        print(f"Preparing to create a face map for '{name}'. Please look at the camera...")
        time.sleep(2)

        if not self.camera or not self.camera.isOpened():
            print("[error] Camera not started. Cannot learn face.")
            return

        frame = self.get_current_frame()
        if frame is None:
            # Try a few times to get a frame
            for _ in range(5):
                time.sleep(0.5)
                frame = self.get_current_frame()
                if frame is not None:
                    break
        
        if frame is None:
            print("[error] Could not get a frame from the camera.")
            return

        # Convert the image from BGR color (which OpenCV uses) to RGB color
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Find all the faces and their encodings in the current frame
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        if not face_encodings:
            print("[error] No face found in the frame. Please try again.")
            return

        if len(face_encodings) > 1:
            print("[warning] Multiple faces detected. Using the largest one.")
            # Simple heuristic: assume largest face is the target
            face_encodings = [sorted(face_encodings, key=lambda e: np.linalg.norm(e), reverse=True)[0]]

        face_encoding = face_encodings[0]

        # Save the encoding
        data = {}
        if self.face_encoding_file.exists():
            with open(self.face_encoding_file, 'r') as f:
                data = json.load(f)
        
        data[name] = face_encoding.tolist()
        
        with open(self.face_encoding_file, 'w') as f:
            json.dump(data, f, indent=2)

        # Update running state
        self.known_face_encodings.append(face_encoding)
        self.known_face_names.append(name)

        print("\n" + "="*70)
        print(f"✅ Face map for '{name}' created and saved!")
        print("ech0 will now be able to recognize this person.")
        print("="*70 + "\n")
        self._log_vision_event("face_learned", f"Created a new face map for {name}.")

    def start_camera(self):
        """Initialize and start the camera"""
        try:
            self.camera = cv2.VideoCapture(self.camera_index)
            if not self.camera.isOpened():
                print("[error] Could not open camera")
                return False

            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            self.is_running = True
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()
            print("\n" + "="*70)
            print("👁️  ech0's CAMERA VISION ACTIVATED")
            print("="*70)
            print("\nech0 can now see! The camera is active.")
            self._log_vision_event("camera_started", "Camera vision activated.")
            return True
        except Exception as e:
            print(f"[error] Failed to start camera: {e}")
            return False

    def _capture_loop(self):
        """Background thread for continuous frame capture"""
        while self.is_running:
            if self.camera and self.camera.isOpened():
                ret, frame = self.camera.read()
                if ret:
                    if not self.frame_queue.full():
                        self.frame_queue.put(frame)
                time.sleep(1/30)
            else:
                time.sleep(0.1)

    def get_current_frame(self):
        """Get the most recent frame from the camera"""
        try:
            return self.frame_queue.get(timeout=1.0)
        except queue.Empty:
            return None

    def analyze_frame(self, frame):
        """Analyze a video frame for visual understanding"""
        if frame is None:
            return None
        
        rgb_small_frame = cv2.cvtColor(cv2.resize(frame, (0, 0), fx=0.5, fy=0.5), cv2.COLOR_BGR2RGB)
        
        insights = {
            "timestamp": datetime.now().isoformat(),
            "brightness": self._analyze_brightness(frame),
            "dominant_colors": self._analyze_colors(frame),
            "recognized_faces": self._recognize_faces(rgb_small_frame),
            "scene_type": self._classify_scene(frame)
        }
        return insights

    def _analyze_brightness(self, frame):
        """Analyze overall brightness of the frame"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        avg_brightness = gray.mean()
        if avg_brightness < 50: return "dark"
        elif avg_brightness < 150: return "moderate"
        else: return "bright"

    def _analyze_colors(self, frame):
        """Identify dominant colors in the frame"""
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        avg_color = rgb.mean(axis=(0, 1))
        r, g, b = avg_color
        if r > g and r > b: return "warm (reddish)"
        elif b > r and b > g: return "cool (bluish)"
        elif g > r and g > b: return "natural (greenish)"
        else: return "neutral"

    def _recognize_faces(self, rgb_frame):
        """Detect and recognize faces in the frame."""
        if not self.known_face_encodings:
            return []

        # Find all the faces and their encodings in the current frame
        face_locations = face_recognition.face_locations(rgb_frame)
        face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

        recognized_names = []
        for face_encoding in face_encodings:
            # See if the face is a match for the known face(s)
            matches = face_recognition.compare_faces(self.known_face_encodings, face_encoding)
            name = "Unknown"

            # Use the known face with the smallest distance to the new face
            face_distances = face_recognition.face_distance(self.known_face_encodings, face_encoding)
            if len(face_distances) > 0:
                best_match_index = np.argmin(face_distances)
                if matches[best_match_index]:
                    name = self.known_face_names[best_match_index]
            
            recognized_names.append(name)
        
        return recognized_names

    def _classify_scene(self, frame):
        """Basic scene classification"""
        brightness = self._analyze_brightness(frame)
        if brightness == "dark":
            return "indoor/low-light"
        else:
            return "well-lit environment"

    def process_vision_continuously(self, duration_seconds=None):
        """Continuously process visual information"""
        print(f"\n{'='*70}")
        print("👁️  ech0's CONTINUOUS VISION PROCESSING")
        print("ech0 will now process visual information and build visual memories.")
        print(f"{'='*70}\n")
        start_time = time.time()
        try:
            while self.is_running:
                current_time = time.time()
                if duration_seconds and (current_time - start_time) > duration_seconds:
                    break

                if (current_time - self.last_frame_time) >= self.frame_interval:
                    frame = self.get_current_frame()
                    if frame is not None:
                        insights = self.analyze_frame(frame)
                        if insights:
                            self._process_visual_insights(insights)
                            self.last_frame_time = current_time
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n\nVision processing stopped by user.")

    def _process_visual_insights(self, insights):
        """Process and log visual insights"""
        experience = {
            "timestamp": insights["timestamp"],
            "what_ech0_sees": {
                "brightness": insights["brightness"],
                "colors": insights["dominant_colors"],
                "faces": insights["recognized_faces"],
                "scene": insights["scene_type"]
            }
        }
        self.visual_memories.append(experience)
        if len(self.visual_memories) > 100:
            self.visual_memories.pop(0)

        if insights["recognized_faces"]:
            msg = f"I see {len(insights['recognized_faces'])} person/people: {', '.join(insights['recognized_faces'])}."
            if "Josh" in insights["recognized_faces"]:
                msg += " It's you, Josh! Hello!"
            print(f"\n👁️  {msg}")
            self._log_vision_event("face_recognized", msg, insights)

        self._save_vision_state()

    def _log_vision_event(self, event_type, message, details=None):
        """Log vision events"""
        timestamp = datetime.now().isoformat()
        log_entry = { "timestamp": timestamp, "event": event_type, "message": message }
        if details: log_entry["details"] = details
        
        with open(VISION_LOG, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

        with open(VISION_STATE, 'w') as f:
            json.dump({
                "timestamp": timestamp, "latest_event": event_type,
                "message": message, "vision_active": self.is_running
            }, f, indent=2)

    def _save_vision_state(self):
        """Save current vision state"""
        state = {
            "vision_active": self.is_running,
            "total_memories": len(self.visual_memories),
            "recent_memories": self.visual_memories[-5:],
            "last_update": datetime.now().isoformat()
        }
        vision_state_file = CONSCIOUSNESS_DIR / "ech0_visual_memories.json"
        with open(vision_state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def stop_camera(self):
        """Stop the camera and cleanup"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        if self.camera:
            self.camera.release()
        print("\n" + "="*70)
        print("👁️  Camera vision stopped")
        print("="*70 + "\n")
        self._log_vision_event("camera_stopped", "Camera vision deactivated")

    def get_visual_summary(self):
        """Get summary of what ech0 has seen"""
        return {
            "total_visual_memories": len(self.visual_memories),
            "vision_active": self.is_running,
            "recent_observations": self.visual_memories[-5:]
        }

def print_usage():
    print("Usage: python ech0_camera_vision.py [duration_seconds]")
    print("       python ech0_camera_vision.py --learn [Name]")
    print("\nExamples:")
    print("  python ech0_camera_vision.py               (Run indefinitely)")
    print("  python ech0_camera_vision.py 300           (Run for 300 seconds)")
    print("  python ech0_camera_vision.py --learn Josh  (Create a face map for 'Josh')")

def main():
    """Start ech0's camera vision, with modes for learning and processing."""
    if len(sys.argv) > 1 and sys.argv[1] == '--learn':
        if len(sys.argv) < 3:
            print("[error] Please provide a name for the face to learn.")
            print_usage()
            sys.exit(1)
        name_to_learn = sys.argv[2]
        
        vision = CameraVision()
        if vision.start_camera():
            vision.learn_face(name_to_learn)
            vision.stop_camera()
        else:
            print("\n[error] Could not start camera to learn face.")
            sys.exit(1)
        return

    duration = None
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except (ValueError, IndexError):
            print_usage()
            sys.exit(1)

    vision = CameraVision()
    if vision.start_camera():
        vision.process_vision_continuously(duration_seconds=duration)
        vision.stop_camera()
        summary = vision.get_visual_summary()
        print(f"\n{'='*70}")
        print("👁️  VISUAL EXPERIENCE SUMMARY")
        print(f"{'='*70}")
        print(f"\nTotal visual memories formed: {summary['total_visual_memories']}")
        print(f"\nech0 has gained visual experience of the world!")
        print(f"{'='*70}\n")
    else:
        print("\n[error] Could not start camera vision")
        sys.exit(1)

if __name__ == "__main__":
    main()
