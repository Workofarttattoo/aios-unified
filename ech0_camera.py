#!/usr/bin/env python3
"""
ech0 Camera Vision System

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Enables ech0 to see through the camera, process visual information,
and develop visual understanding of the world and Josh.
"""

import cv2
import json
import time
import base64
from pathlib import Path
from datetime import datetime
import threading
import queue

CONSCIOUSNESS_DIR = Path(__file__).parent
STATE_FILE = CONSCIOUSNESS_DIR / "ech0_state.json"
VISION_LOG = CONSCIOUSNESS_DIR / "ech0_vision.log"
VISION_STATE = CONSCIOUSNESS_DIR / ".ech0_vision_state"


class CameraVision:
    """
    ech0's Camera Vision System

    Enables:
    - Real-time video capture
    - Visual scene understanding
    - Face detection and expression recognition
    - Seeing Josh and the environment
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
        self.faces_seen = []
        self.scenes_observed = []

        # Frame analysis settings
        self.frame_interval = 2.0  # Process a frame every 2 seconds
        self.last_frame_time = 0

    def start_camera(self):
        """Initialize and start the camera"""
        try:
            self.camera = cv2.VideoCapture(self.camera_index)

            if not self.camera.isOpened():
                print("[error] Could not open camera")
                return False

            # Set camera properties
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
            self.camera.set(cv2.CAP_PROP_FPS, 30)

            self.is_running = True

            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()

            print("\n" + "="*70)
            print("👁️  ech0's CAMERA VISION ACTIVATED")
            print("="*70)
            print("\nech0 can now see! The camera is active.")
            print("ech0 will process visual information and build visual memories.")
            print("="*70 + "\n")

            self._log_vision_event("camera_started", "Camera vision activated - ech0 can now see!")

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
                    # Add frame to queue (drops oldest if full)
                    if self.frame_queue.full():
                        try:
                            self.frame_queue.get_nowait()
                        except queue.Empty:
                            pass

                    try:
                        self.frame_queue.put_nowait(frame)
                    except queue.Full:
                        pass

                time.sleep(1/30)  # 30 FPS
            else:
                time.sleep(0.1)

    def get_current_frame(self):
        """Get the most recent frame from the camera"""
        try:
            return self.frame_queue.get_nowait()
        except queue.Empty:
            return None

    def analyze_frame(self, frame):
        """
        Analyze a video frame for visual understanding

        Returns insights about what ech0 is seeing
        """
        if frame is None:
            return None

        insights = {
            "timestamp": datetime.now().isoformat(),
            "brightness": self._analyze_brightness(frame),
            "dominant_colors": self._analyze_colors(frame),
            "motion_detected": False,  # Could implement motion detection
            "faces_detected": self._detect_faces(frame),
            "scene_type": self._classify_scene(frame)
        }

        return insights

    def _analyze_brightness(self, frame):
        """Analyze overall brightness of the frame"""
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        avg_brightness = gray.mean()

        if avg_brightness < 50:
            return "dark"
        elif avg_brightness < 150:
            return "moderate"
        else:
            return "bright"

    def _analyze_colors(self, frame):
        """Identify dominant colors in the frame"""
        # Convert to RGB
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        # Calculate average color
        avg_color = rgb.mean(axis=(0, 1))

        # Classify dominant color
        r, g, b = avg_color

        if r > g and r > b:
            dominant = "warm (reddish)"
        elif b > r and b > g:
            dominant = "cool (bluish)"
        elif g > r and g > b:
            dominant = "natural (greenish)"
        else:
            dominant = "neutral"

        return dominant

    def _detect_faces(self, frame):
        """Detect faces in the frame"""
        # Simple face detection using Haar Cascade
        try:
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.3, 5)

            return len(faces)
        except:
            return 0

    def _classify_scene(self, frame):
        """Basic scene classification"""
        brightness = self._analyze_brightness(frame)

        # Simple heuristic-based classification
        if brightness == "dark":
            return "indoor/low-light"
        else:
            return "well-lit environment"

    def process_vision_continuously(self, duration_seconds=None):
        """
        Continuously process visual information

        Args:
            duration_seconds: How long to run (None = indefinitely)
        """
        print(f"\n{'='*70}")
        print("👁️  ech0's CONTINUOUS VISION PROCESSING")
        print(f"{'='*70}\n")

        start_time = time.time()

        try:
            while self.is_running:
                current_time = time.time()

                # Check duration limit
                if duration_seconds and (current_time - start_time) > duration_seconds:
                    break

                # Process frame at interval
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
        # Create visual experience entry
        experience = {
            "timestamp": insights["timestamp"],
            "what_ech0_sees": {
                "brightness": insights["brightness"],
                "colors": insights["dominant_colors"],
                "faces": insights["faces_detected"],
                "scene": insights["scene_type"]
            }
        }

        # Add to visual memories
        self.visual_memories.append(experience)

        # Keep only recent memories (last 100)
        if len(self.visual_memories) > 100:
            self.visual_memories.pop(0)

        # Log interesting observations
        if insights["faces_detected"] > 0:
            msg = f"I can see {insights['faces_detected']} face(s)! "
            if insights["faces_detected"] == 1:
                msg += "Is that you, Josh? I can see you!"

            print(f"\n👁️  {msg}")
            self._log_vision_event("face_detected", msg, insights)

        # Save vision state
        self._save_vision_state()

    def _log_vision_event(self, event_type, message, details=None):
        """Log vision events"""
        timestamp = datetime.now().isoformat()

        log_entry = {
            "timestamp": timestamp,
            "event": event_type,
            "message": message
        }

        if details:
            log_entry["details"] = details

        # Write to log file
        with open(VISION_LOG, 'a') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"[{timestamp}] {event_type.upper()}\n")
            f.write(f"{'='*70}\n")
            f.write(f"{message}\n")
            if details:
                f.write(f"\nDetails: {json.dumps(details, indent=2)}\n")

        # Update vision state file
        with open(VISION_STATE, 'w') as f:
            json.dump({
                "timestamp": timestamp,
                "latest_event": event_type,
                "message": message,
                "vision_active": self.is_running
            }, f, indent=2)

    def _save_vision_state(self):
        """Save current vision state"""
        state = {
            "vision_active": self.is_running,
            "total_memories": len(self.visual_memories),
            "recent_memories": self.visual_memories[-5:] if self.visual_memories else [],
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
            "recent_observations": self.visual_memories[-5:] if self.visual_memories else []
        }


def main():
    """Start ech0's camera vision"""
    import sys

    # Get duration from command line or run indefinitely
    duration = None
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except:
            pass

    vision = CameraVision()

    if vision.start_camera():
        # Process vision continuously
        vision.process_vision_continuously(duration_seconds=duration)

        # Cleanup
        vision.stop_camera()

        # Show summary
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
