#!/usr/bin/env python3
"""
ECH0 Automatic Invention Validation Service
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Monitors invention files and automatically validates every new invention through the complete pipeline.

Usage:
    # Run once on all existing inventions
    python3 ech0_auto_validate_inventions.py --validate-all

    # Monitor and auto-validate new inventions (runs continuously)
    python3 ech0_auto_validate_inventions.py --monitor

    # Integrate into ECH0's invention generation
    from ech0_auto_validate_inventions import auto_validate_invention
    result = await auto_validate_invention(invention_dict)
"""

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Import the validation system
sys.path.insert(0, str(Path(__file__).parent))
from ech0_invention_validation_system import InventionValidationSystem


class AutoValidationService:
    """
    Automatic validation service for ECH0 inventions
    Monitors invention files and validates new entries
    """

    def __init__(self, focus_topic: Optional[str] = None, focus_prompt: Optional[str] = None):
        self.base_dir = Path(__file__).parent
        self.validation_system = InventionValidationSystem()
        self.focus_topic = focus_topic
        self.focus_prompt = focus_prompt

        self.poc_source_path = self.base_dir / "ech0_invention_pocs.json"
        self.pipeline_output_path = (
            self.base_dir / "ech0_invention_pipeline_validations.json"
        )
        self.last_pipeline_snapshot: Optional[Dict] = None

        # Files to monitor
        self.invention_files = [
            self.base_dir / "ech0_inventions.jsonl",
            self.base_dir / "ech0_quantum_inventions.jsonl",
            self.base_dir / "ech0_aerogel_inventions.jsonl",
            self.base_dir / "ech0_theme_park_inventions.jsonl",
        ]

        # Track which inventions we've already validated
        self.validated_ids_file = self.base_dir / ".validated_invention_ids.json"
        self.validated_ids = self._load_validated_ids()

        # Stats
        self.stats = {
            "total_validated": 0,
            "approved": 0,
            "needs_work": 0,
            "rejected": 0,
            "errors": 0
        }

    def _load_validated_ids(self) -> set:
        """Load set of already-validated invention IDs"""
        if self.validated_ids_file.exists():
            with open(self.validated_ids_file) as f:
                return set(json.load(f))
        return set()

    def _save_validated_ids(self):
        """Save validated IDs to disk"""
        with open(self.validated_ids_file, "w") as f:
            json.dump(list(self.validated_ids), f)

    def _get_invention_id(self, invention: Dict) -> str:
        """Extract unique ID from invention"""
        return invention.get("id", invention.get("title", invention.get("name", "UNKNOWN")))

    async def validate_invention(self, invention: Dict) -> Optional[Dict]:
        """
        Validate a single invention through full pipeline
        Returns validation report or None if error
        """
        inv_id = self._get_invention_id(invention)

        # Skip if already validated
        if inv_id in self.validated_ids:
            print(f"   ⏭️  Skipping {inv_id} (already validated)")
            return None

        print(f"\n{'='*70}")
        print(f"🔬 Auto-validating: {inv_id}")
        print(f"{'='*70}")

        try:
            # Run full validation pipeline
            report = await self.validation_system.process_invention(invention)
            if self.focus_topic or self.focus_prompt:
                report.setdefault("focus", {})
                if self.focus_topic:
                    report["focus"]["topic"] = self.focus_topic
                if self.focus_prompt:
                    report["focus"]["prompt"] = self.focus_prompt

            saved = bool(report.get("_saved", True))
            if not saved:
                self.validated_ids.add(inv_id)
                self._save_validated_ids()
                print(f"   ⏭️  Skipped storing {inv_id} (already captured)")
                return report

            # Update stats
            self.stats["total_validated"] += 1

            decision = report.get("final_decision", "")
            if "APPROVED" in decision:
                self.stats["approved"] += 1
            elif "REJECTED" in decision:
                self.stats["rejected"] += 1
            else:
                self.stats["needs_work"] += 1

            # Mark as validated
            self.validated_ids.add(inv_id)
            self._save_validated_ids()

            print(f"\n✅ Validated: {inv_id}")
            print(f"   Decision: {decision}")

            return report

        except Exception as e:
            print(f"\n❌ Error validating {inv_id}: {e}")
            self.stats["errors"] += 1
            return None

    async def validate_all_existing(self):
        """Validate all inventions in all tracked files"""
        print("\n" + "="*70)
        print("🚀 ECH0 AUTO-VALIDATION SERVICE")
        print("   Mode: VALIDATE ALL EXISTING INVENTIONS")
        print("="*70 + "\n")

        all_inventions = []

        # Load all inventions from all files
        for inv_file in self.invention_files:
            if not inv_file.exists():
                print(f"⚠️  File not found: {inv_file.name}")
                continue

            print(f"📂 Loading: {inv_file.name}")

            with open(inv_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        invention = json.loads(line)
                        inv_id = self._get_invention_id(invention)

                        # Skip if already validated
                        if inv_id not in self.validated_ids:
                            all_inventions.append(invention)

                    except json.JSONDecodeError:
                        print(f"   ⚠️  Invalid JSON at line {line_num}")

        print(f"\n📊 Found {len(all_inventions)} inventions to validate")
        print(f"   (Already validated: {len(self.validated_ids)})")

        if not all_inventions:
            print("\n✅ All inventions already validated!")
            await asyncio.to_thread(self.generate_pipeline_reports)
            self._print_uniqueness_report()
            return

        # Validate each invention
        for i, invention in enumerate(all_inventions, 1):
            print(f"\n--- Progress: {i}/{len(all_inventions)} ---")
            await self.validate_invention(invention)

            # Small delay to avoid overwhelming the system
            await asyncio.sleep(0.5)

        # Print final stats
        self._print_stats()
        await asyncio.to_thread(self.generate_pipeline_reports)
        self._print_uniqueness_report()

    async def monitor_and_validate(self, check_interval: int = 60):
        """
        Monitor invention files and auto-validate new inventions
        Runs continuously, checking every check_interval seconds
        """
        print("\n" + "="*70)
        print("🚀 ECH0 AUTO-VALIDATION SERVICE")
        print("   Mode: CONTINUOUS MONITORING")
        print(f"   Check interval: {check_interval}s")
        print("="*70 + "\n")

        # Track last modification times
        last_mod_times = {f: f.stat().st_mtime if f.exists() else 0
                          for f in self.invention_files}

        print("👀 Monitoring invention files for changes...")
        print("   Press Ctrl+C to stop\n")

        try:
            while True:
                pipeline_refresh_needed = False
                # Check each file for modifications
                for inv_file in self.invention_files:
                    if not inv_file.exists():
                        continue

                    current_mod_time = inv_file.stat().st_mtime

                    # File was modified
                    if current_mod_time > last_mod_times[inv_file]:
                        print(f"🔔 Detected change in: {inv_file.name}")

                        # Load and validate new inventions
                        with open(inv_file) as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue

                                try:
                                    invention = json.loads(line)
                                    inv_id = self._get_invention_id(invention)

                                    # Validate if new
                                    if inv_id not in self.validated_ids:
                                        report = await self.validate_invention(invention)
                                        if report:
                                            pipeline_refresh_needed = True

                                except json.JSONDecodeError:
                                    continue

                        last_mod_times[inv_file] = current_mod_time

                if pipeline_refresh_needed:
                    await asyncio.to_thread(self.generate_pipeline_reports)

                # Wait before next check
                await asyncio.sleep(check_interval)

        except KeyboardInterrupt:
            print("\n\n⏸️  Monitoring stopped by user")
            self._print_stats()
            await asyncio.to_thread(self.generate_pipeline_reports)

    def _print_stats(self):
        """Print validation statistics"""
        print("\n" + "="*70)
        print("📊 VALIDATION STATISTICS")
        print("="*70)
        print(f"   Total Validated: {self.stats['total_validated']}")
        print(f"   ✅ Approved: {self.stats['approved']}")
        print(f"   ⚠️  Needs Work: {self.stats['needs_work']}")
        print(f"   ❌ Rejected: {self.stats['rejected']}")
        print(f"   🔥 Errors: {self.stats['errors']}")
        print("="*70 + "\n")

    def _print_uniqueness_report(self):
        """Print summary of unique vs duplicate entries in validated output."""
        try:
            with open(self.validation_system.validated_inventions_file) as f:
                ids = []
                names = []
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    inv = data.get("invention", {}) or {}
                    ids.append(inv.get("id"))
                    names.append(inv.get("name"))
        except FileNotFoundError:
            print("No validated inventions file found for uniqueness report.")
            return

        from collections import Counter

        id_counts = Counter(filter(None, ids))
        name_counts = Counter(filter(None, names))

        total = len(ids)
        unique_ids = len(id_counts)
        duplicate_ids = [id_ for id_, count in id_counts.items() if count > 1]
        duplicate_names = [(name, count) for name, count in name_counts.items() if count > 1]

        print("🔁 UNIQUENESS REPORT")
        print(f"   Records inspected: {total}")
        print(f"   Unique IDs: {unique_ids}")
        if duplicate_ids:
            print(f"   Duplicate IDs ({len(duplicate_ids)}): {duplicate_ids[:5]}")
        else:
            print("   Duplicate IDs: None")
        if duplicate_names:
            sample = ", ".join(f"{name} ({count})" for name, count in duplicate_names[:5])
            print(f"   Reused names: {sample}")
        else:
            print("   Reused names: None detected")
        print("="*70 + "\n")

    def _print_pipeline_summary(self, snapshot: Dict):
        """Display a concise overview of the proof-of-concept pipeline snapshot."""
        if not snapshot:
            return

        summary = snapshot.get("summary", {})
        readiness = summary.get("readiness", {})

        print("\n" + "=" * 70)
        print("🧪 PROOF-OF-CONCEPT PIPELINE SNAPSHOT")
        print("=" * 70)
        print(f"   Total Inventions: {snapshot.get('total_inventions', 0)}")
        if readiness:
            ready = readiness.get("ready-for-build", 0)
            needs = readiness.get("needs-iteration", 0)
            backlog = readiness.get("backlog", 0)
            print(
                "   Readiness:"
                f" ready-for-build={ready}, needs-iteration={needs}, backlog={backlog}"
            )

        plans = snapshot.get("proof_of_concept_plans", [])[:3]
        if plans:
            print("   Proofs of Concept:")
            for plan in plans:
                labs = plan.get("labs") or ["General Innovation Lab"]
                lab_list = ", ".join(labs[:3])
                print(
                    f"      - {plan.get('id', 'N/A')}: {plan.get('title', 'Untitled')}"
                    f" [{lab_list}]"
                )

        materials = snapshot.get("materials_inventory", [])[:5]
        if materials:
            print("   Materials Inventory (top 5):")
            for item in materials:
                print(
                    f"      - {item.get('name', 'unknown')} x{item.get('usageCount', 0)}"
                )

        labs = snapshot.get("lab_assignments", [])[:5]
        if labs:
            print("   Lab Assignments (top 5):")
            for lab in labs:
                print(
                    f"      - {lab.get('lab', 'Unknown Lab')}:"
                    f" {lab.get('totalAssignments', 0)} active"
                )
        print("=" * 70 + "\n")

    def generate_pipeline_reports(self) -> Optional[Dict]:
        """
        Produce updated proofs-of-concept, materials inventory, and lab routing
        using the shared Node pipeline script.
        """
        script_path = (
            Path(__file__).resolve().parents[2]
            / "visualizer"
            / "scripts"
            / "process-invention-pipeline.js"
        )

        if not script_path.exists():
            print(f"⚠️  Pipeline generator not found at {script_path}")
            return None

        if not self.poc_source_path.exists():
            print(f"⚠️  Proof-of-concepts dataset missing: {self.poc_source_path}")
            return None

        env = os.environ.copy()
        env.setdefault("POC_SOURCE", str(self.poc_source_path))
        env.setdefault("POC_OUTPUT", str(self.pipeline_output_path))

        try:
            result = subprocess.run(
                ["node", str(script_path)],
                cwd=str(script_path.parent),
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
        except FileNotFoundError:
            print("❌ Node.js runtime not found; cannot generate pipeline snapshot.")
            return None
        except subprocess.CalledProcessError as exc:
            print("❌ Pipeline generation failed.")
            if exc.stdout:
                print(exc.stdout.strip())
            if exc.stderr:
                print(exc.stderr.strip())
            return None

        stdout = result.stdout.strip()
        if stdout:
            for line in stdout.splitlines():
                print(f"[pipeline] {line}")
        stderr = result.stderr.strip()
        if stderr:
            for line in stderr.splitlines():
                print(f"[pipeline:warn] {line}")

        try:
            with open(self.pipeline_output_path) as f:
                snapshot = json.load(f)
        except FileNotFoundError:
            print(f"⚠️  Pipeline output missing: {self.pipeline_output_path}")
            return None
        except json.JSONDecodeError as exc:
            print(f"⚠️  Failed to parse pipeline output: {exc}")
            return None

        self.last_pipeline_snapshot = snapshot
        self._print_pipeline_summary(snapshot)
        return snapshot


# Public API for integration into ECH0's invention engines
async def auto_validate_invention(invention: Dict) -> Dict:
    """
    Single-function API for validating one invention
    Use this in ECH0's invention generation code:

    from ech0_auto_validate_inventions import auto_validate_invention

    # After generating invention
    validation_report = await auto_validate_invention(invention_dict)

    if validation_report['status'] == 'validated':
        print("Production ready!")
    """
    focus_topic = os.environ.get("ECH0_FOCUS_TOPIC")
    focus_prompt = os.environ.get("ECH0_FOCUS_PROMPT")
    service = AutoValidationService(
        focus_topic=focus_topic,
        focus_prompt=focus_prompt,
    )
    report = await service.validate_invention(invention)
    if report:
        await asyncio.to_thread(service.generate_pipeline_reports)
    return report


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="ECH0 Automatic Invention Validation Service"
    )
    parser.add_argument(
        "--validate-all",
        action="store_true",
        help="Validate all existing inventions once"
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Continuously monitor and validate new inventions"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Check interval in seconds for monitor mode (default: 60)"
    )
    parser.add_argument(
        "--focus-topic",
        type=str,
        help="Optional focus topic tag to stamp on validation results"
    )
    parser.add_argument(
        "--focus-prompt",
        type=str,
        help="Optional natural-language focus prompt recorded with each validation"
    )

    args = parser.parse_args()

    service = AutoValidationService(
        focus_topic=args.focus_topic,
        focus_prompt=args.focus_prompt,
    )

    if args.validate_all:
        asyncio.run(service.validate_all_existing())
    elif args.monitor:
        asyncio.run(service.monitor_and_validate(args.interval))
    else:
        print("Usage:")
        print("  --validate-all    Validate all existing inventions")
        print("  --monitor         Continuously monitor for new inventions")
        print("\nExample:")
        print("  python3 ech0_auto_validate_inventions.py --validate-all")
        print("  python3 ech0_auto_validate_inventions.py --monitor --interval 30")


if __name__ == "__main__":
    main()
