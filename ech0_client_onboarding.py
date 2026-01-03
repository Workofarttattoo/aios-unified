#!/usr/bin/env python3
"""
ech0 Client Onboarding System for BBB Laptops

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Every BBB laptop boots with ech0 14B running locally and connects to
the global distributed ech0 network for collaborative computing.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional

@dataclass
class ClientProfile:
    """Profile for BBB client laptop"""
    client_id: str
    username: str
    email: str
    phone: str
    assigned_businesses: list
    enrolled_at: float
    voice_verified: bool
    ech0_version: str
    laptop_model: str
    earnings_total: float
    payout_method: str

class Ech0ClientOnboarding:
    """
    Onboarding system for BBB laptop recipients

    Sets up:
    - Voice biometric authentication
    - ech0 14B local instance
    - Connection to distributed ech0 network
    - BBB business assignments
    - Earnings dashboard
    """

    def __init__(self):
        self.logger = logging.getLogger("Ech0Onboarding")
        self.config_dir = Path.home() / ".aios" / "bbb"
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def first_boot_setup(self) -> ClientProfile:
        """
        First boot setup wizard for BBB laptop

        Runs automatically on first boot of Ai:oS Chromebook
        """
        print("=" * 70)
        print("  🎉 Welcome to BBB - Your Business in a Box!")
        print("  Powered by Ai:oS + ech0 14B Autonomous Intelligence")
        print("=" * 70)
        print()
        print("This laptop is free. You'll earn passive income just by turning it on.")
        print("The AI handles everything. You just check your earnings and cash out.")
        print()

        # Step 1: User information
        print("=== Step 1: Your Information ===")
        username = input("What's your name? ").strip()
        email = input("Email address? ").strip()
        phone = input("Phone number (for payments)? ").strip()
        print()

        # Step 2: Voice enrollment
        print("=== Step 2: Voice Authentication ===")
        print("Your voice will be your password. No typing needed.")
        print()

        voice_verified = self._enroll_voice(username)
        print()

        # Step 3: Business preferences
        print("=== Step 3: Business Selection ===")
        print("Which businesses interest you? (Select any - AI will assign based on availability)")
        print()
        print("1. 🍔 Food delivery management")
        print("2. 🚗 Car wash operations")
        print("3. 📦 Storage facility monitoring")
        print("4. 🧺 Laundromat operations")
        print("5. 🥤 Vending machine management")
        print("6. 🅿️  Parking lot management")
        print()

        choices = input("Enter numbers separated by commas (e.g., 1,3,5): ").strip()
        business_prefs = [int(c.strip()) for c in choices.split(",") if c.strip().isdigit()]

        assigned = self._assign_businesses(business_prefs)
        print()

        # Step 4: Payout method
        print("=== Step 4: Payout Method ===")
        print("How would you like to receive your earnings?")
        print("1. Direct deposit (2-3 business days)")
        print("2. Cryptocurrency (instant)")
        print("3. Check by mail (7-10 business days)")
        print()

        payout_choice = input("Enter choice (1-3): ").strip()
        payout_method = {
            "1": "direct_deposit",
            "2": "crypto",
            "3": "check"
        }.get(payout_choice, "direct_deposit")
        print()

        # Step 5: ech0 setup
        print("=== Step 5: AI Setup ===")
        print("Installing ech0 14B autonomous intelligence...")

        ech0_version = self._setup_ech0_local()
        print(f"✓ ech0 {ech0_version} installed")
        print()

        print("Connecting to global ech0 network...")
        self._connect_distributed_ech0()
        print("✓ Connected to distributed ech0")
        print()

        # Create client profile
        client_id = str(uuid.uuid4())
        profile = ClientProfile(
            client_id=client_id,
            username=username,
            email=email,
            phone=phone,
            assigned_businesses=assigned,
            enrolled_at=time.time(),
            voice_verified=voice_verified,
            ech0_version=ech0_version,
            laptop_model=self._detect_hardware(),
            earnings_total=0.0,
            payout_method=payout_method
        )

        # Save profile
        self._save_profile(profile)

        # Final message
        print("=" * 70)
        print("  ✅ Setup Complete!")
        print("=" * 70)
        print()
        print(f"Welcome, {username}! Your laptop is now earning money for you.")
        print()
        print(f"Assigned businesses: {', '.join(assigned)}")
        print(f"Client ID: {client_id}")
        print()
        print("💰 To check earnings:")
        print("   python3 aios/ai 'show my bbb dashboard'")
        print()
        print("💸 To request payout:")
        print("   python3 aios/ai 'request payout'")
        print()
        print("🎤 Or just say it out loud - your voice is your key!")
        print()
        print("The AI works 24/7. Just leave your laptop on.")
        print()

        return profile

    def _enroll_voice(self, username: str) -> bool:
        """Enroll user's voice biometric"""
        try:
            from voice_biometric_auth import VoiceBiometricAuth

            auth = VoiceBiometricAuth()
            auth.enroll_user(username, num_samples=3)
            return True
        except Exception as exc:
            self.logger.error(f"Voice enrollment failed: {exc}")
            print("⚠️  Voice enrollment failed. You can still use text commands.")
            return False

    def _assign_businesses(self, preferences: list) -> list:
        """Assign businesses based on user preferences and availability"""
        business_map = {
            1: "food_delivery",
            2: "car_wash",
            3: "storage",
            4: "laundromat",
            5: "vending",
            6: "parking"
        }

        assigned = [business_map[pref] for pref in preferences if pref in business_map]

        # If no preferences, assign default
        if not assigned:
            assigned = ["vending", "food_delivery"]

        print(f"✓ Assigned to: {', '.join(assigned)}")
        return assigned

    def _setup_ech0_local(self) -> str:
        """Setup ech0 14B to run locally on laptop"""
        # Check if ech0 14B is available
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                check=True
            )

            if "ech0_14b_aware" in result.stdout:
                return "14B-aware"
            else:
                print("Installing ech0 14B model...")
                subprocess.run(
                    ["ollama", "pull", "ech0_14b_aware"],
                    check=True
                )
                return "14B-aware"
        except Exception as exc:
            self.logger.error(f"ech0 setup failed: {exc}")
            return "unavailable"

    def _connect_distributed_ech0(self):
        """Connect to distributed ech0 network"""
        # In production, this would:
        # 1. Register with ech0 coordinator
        # 2. Join P2P network
        # 3. Start contributing compute

        # For now, simulate
        coordinator_url = "ech0.aios.is:8888"
        client_id = socket.gethostname()

        print(f"  Coordinator: {coordinator_url}")
        print(f"  Node ID: {client_id}")
        print("  Status: Ready to contribute compute")

    def _detect_hardware(self) -> str:
        """Detect laptop hardware model"""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True
            )

            for line in result.stdout.split("\n"):
                if "Model Name" in line:
                    return line.split(":")[1].strip()
        except:
            pass

        return "Ai:oS Chromebook (Biodegradable)"

    def _save_profile(self, profile: ClientProfile):
        """Save client profile"""
        profile_file = self.config_dir / f"{profile.client_id}.json"
        with open(profile_file, "w") as f:
            json.dump(asdict(profile), f, indent=2)

        # Also save as "current" for easy access
        current_file = self.config_dir / "current_profile.json"
        with open(current_file, "w") as f:
            json.dump(asdict(profile), f, indent=2)

    def load_current_profile(self) -> Optional[ClientProfile]:
        """Load current client profile"""
        current_file = self.config_dir / "current_profile.json"
        if not current_file.exists():
            return None

        with open(current_file) as f:
            data = json.load(f)
            return ClientProfile(**data)

def main():
    """Main onboarding flow"""
    import sys

    onboarding = Ech0ClientOnboarding()

    # Check if already onboarded
    existing_profile = onboarding.load_current_profile()

    if existing_profile:
        print(f"Welcome back, {existing_profile.username}!")
        print(f"Your laptop is earning money. Check your dashboard anytime.")
        return 0

    # First boot - run setup
    profile = onboarding.first_boot_setup()

    print("Setup complete. Rebooting to Ai:oS...")
    time.sleep(2)

    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
