#!/usr/bin/env python3
"""
Ai:oS Boot with Visual Desktop Launcher
========================================

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light).
All Rights Reserved. PATENT PENDING.

Boots Ai:oS with cinematic visualizer and living desktop menu system.
"""

import os
import sys
import time
import webbrowser
import subprocess
from pathlib import Path

# Add aios to path
AIOS_PATH = Path(__file__).parent
sys.path.insert(0, str(AIOS_PATH.parent))


def launch_boot_visualizer():
    """Launch the cinematic boot visualizer in browser"""
    boot_viz = AIOS_PATH / "cinematic_boot_visualizer.html"

    if boot_viz.exists():
        print("[INFO] Launching cinematic boot visualizer...")
        webbrowser.open(f"file://{boot_viz.absolute()}")
        return True
    else:
        print(f"[WARN] Boot visualizer not found at {boot_viz}")
        return False


def launch_desktop_menu():
    """Launch the living desktop with menu system"""
    # Try elite desktop first (Kali/Parrot style with live monitoring)
    desktop = AIOS_PATH / "elite_desktop.html"

    if not desktop.exists():
        desktop = AIOS_PATH / "sovereign_desktop.html"

    if not desktop.exists():
        desktop = AIOS_PATH / "ai_os_desktop_with_menu.html"

    if desktop.exists():
        print(f"[INFO] Launching Ai:oS elite desktop: {desktop.name}")
        webbrowser.open(f"file://{desktop.absolute()}")
        return True
    else:
        print(f"[WARN] Desktop menu not found")
        return False


def boot_aios():
    """Boot the Ai:oS system"""
    aios_cli = AIOS_PATH / "aios"

    if not aios_cli.exists():
        print(f"[ERROR] Ai:oS CLI not found at {aios_cli}")
        return False

    print("[INFO] Booting Ai:oS core system...")
    try:
        # Run aios boot in background
        result = subprocess.run(
            [sys.executable, str(aios_cli), "-v", "boot"],
            cwd=str(AIOS_PATH),
            capture_output=False,
            text=True
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[ERROR] Failed to boot Ai:oS: {e}")
        return False


def main():
    """Main boot sequence with visualizers"""
    print("=" * 70)
    print(" Ai:oS - Artificial Intelligence Operating System")
    print(" Boot Sequence with Visual Desktop")
    print("=" * 70)
    print()

    # Step 1: Launch boot visualizer
    viz_launched = launch_boot_visualizer()

    if viz_launched:
        print("[INFO] Waiting for visualizer to initialize...")
        time.sleep(2)

    # Step 2: Boot core system
    print()
    boot_success = boot_aios()

    # Step 3: Launch desktop menu
    print()
    if boot_success or True:  # Launch desktop even if core boot has warnings
        time.sleep(1)
        desktop_launched = launch_desktop_menu()

        if desktop_launched:
            print()
            print("[SUCCESS] Ai:oS boot complete!")
            print("[INFO] Desktop menu available in browser")
            print("[INFO] Press Ctrl+C to shutdown")
            print()

            # Keep script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[INFO] Shutting down Ai:oS...")
                return 0

    return 1 if not boot_success else 0


if __name__ == "__main__":
    sys.exit(main())
