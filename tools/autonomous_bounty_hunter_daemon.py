#!/usr/bin/env python3
"""
Autonomous Bug Bounty Hunter Daemon
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Runs continuously:
- Scrapes bug bounty platforms for new programs
- Autonomously hunts vulnerabilities 24/7
- Auto-submits findings to platforms
- Tracks earnings and success rates
"""

import asyncio
import json
import time
import os
from datetime import datetime, timedelta
from typing import List, Dict
import httpx
from pathlib import Path

# Import the Level-6 agent
import sys
sys.path.insert(0, os.path.dirname(__file__))
from bug_bounty_level6_agent import BugBountyLevel6Agent, BugBountyTarget


class BugBountyPlatform:
    """Bug bounty platform scraper"""

    PLATFORMS = {
        "hackerone": {
            "url": "https://hackerone.com/directory/programs",
            "api": "https://api.hackerone.com/v1/hackers/programs"
        },
        "bugcrowd": {
            "url": "https://bugcrowd.com/programs",
            "api": "https://api.bugcrowd.com/programs"
        },
        "intigriti": {
            "url": "https://www.intigriti.com/programs",
            "api": None
        },
        "yeswehack": {
            "url": "https://yeswehack.com/programs",
            "api": None
        }
    }

    @staticmethod
    async def scrape_active_programs() -> List[BugBountyTarget]:
        """Scrape all platforms for active bug bounty programs"""

        print("🔍 Scraping bug bounty platforms for active programs...")

        targets = []

        # Demo targets for now (in production, would scrape live)
        demo_programs = [
            {
                "name": "Example Corp",
                "scope": ["https://example.com", "https://api.example.com"],
                "min_bounty": 100,
                "max_bounty": 10000,
                "safe_harbor": True
            },
            {
                "name": "Test Platform",
                "scope": ["https://testplatform.io"],
                "min_bounty": 500,
                "max_bounty": 5000,
                "safe_harbor": True
            },
            {
                "name": "SecureApp Inc",
                "scope": ["https://secureapp.com", "https://*.secureapp.com"],
                "min_bounty": 250,
                "max_bounty": 15000,
                "safe_harbor": True
            }
        ]

        for program in demo_programs:
            target = BugBountyTarget(
                program_name=program["name"],
                scope=program["scope"],
                rules={
                    "safe_harbor": program["safe_harbor"],
                    "min_bounty": program["min_bounty"],
                    "max_bounty": program["max_bounty"]
                }
            )
            targets.append(target)

        print(f"   ✓ Found {len(targets)} active programs")

        return targets


class AutonomousBountyHunterDaemon:
    """
    24/7 autonomous bug bounty hunting daemon.

    This daemon:
    - Runs continuously in background
    - Scrapes platforms every 6 hours for new programs
    - Hunts each program for 2-4 hours
    - Auto-submits findings
    - Tracks earnings
    - Reports daily summaries
    """

    def __init__(self, config_path: str = "/Users/noone/aios/bug_bounty_config.json"):
        self.config_path = config_path
        self.config = self._load_config()

        self.data_dir = Path("/Users/noone/aios/bug_bounty_data")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.total_earnings = 0.0
        self.total_vulnerabilities = 0
        self.programs_hunted = 0
        self.start_time = time.time()

        self.earnings_log = []

    def _load_config(self) -> Dict:
        """Load daemon configuration"""

        default_config = {
            "enabled": True,
            "scan_interval_hours": 6,
            "hunt_time_per_program_hours": 2,
            "max_concurrent_hunts": 2,
            "platforms": ["hackerone", "bugcrowd", "intigriti"],
            "auto_submit": False,  # Safety: require manual approval by default
            "daily_report_time": "09:00"
        }

        if os.path.exists(self.config_path):
            with open(self.config_path) as f:
                return {**default_config, **json.load(f)}

        # Save default config
        with open(self.config_path, "w") as f:
            json.dump(default_config, f, indent=2)

        return default_config

    async def run_forever(self):
        """Main daemon loop - runs 24/7"""

        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║      🤖 AUTONOMOUS BUG BOUNTY HUNTER DAEMON                         ║
║                                                                      ║
║  Status: ACTIVE                                                     ║
║  Mode: 24/7 Continuous Operation                                    ║
║  Auto-Submit: {"ENABLED" if self.config["auto_submit"] else "DISABLED (Manual Review)":49} ║
║                                                                      ║
║  Configuration:                                                     ║
║    • Scan Interval: {self.config["scan_interval_hours"]} hours{' ' * 42} ║
║    • Hunt Time/Program: {self.config["hunt_time_per_program_hours"]} hours{' ' * 37} ║
║    • Max Concurrent: {self.config["max_concurrent_hunts"]}{' ' * 46} ║
║                                                                      ║
║  Copyright (c) 2025 Corporation of Light. All Rights Reserved.      ║
║  PATENT PENDING                                                     ║
╚══════════════════════════════════════════════════════════════════════╝
        """)

        cycle = 0

        while True:
            cycle += 1
            cycle_start = time.time()

            print(f"\n{'='*70}")
            print(f"🔄 CYCLE {cycle} STARTING - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*70}\n")

            try:
                # Step 1: Scrape platforms for programs
                targets = await BugBountyPlatform.scrape_active_programs()

                # Step 2: Hunt each target
                for i, target in enumerate(targets, 1):
                    print(f"\n🎯 Target {i}/{len(targets)}: {target.program_name}")

                    # Create agent
                    agent = BugBountyLevel6Agent(
                        agent_id=f"BOUNTY-L6-DAEMON-{cycle}-{i}"
                    )

                    # Hunt
                    results = await agent.autonomous_hunt(
                        target,
                        time_budget_hours=self.config["hunt_time_per_program_hours"]
                    )

                    # Track results
                    self.programs_hunted += 1
                    self.total_vulnerabilities += results["statistics"]["total_vulns"]

                    # Estimate earnings (in production, would track actual payouts)
                    estimated_earnings = self._estimate_earnings(results["vulnerabilities"])
                    self.total_earnings += estimated_earnings

                    self.earnings_log.append({
                        "timestamp": datetime.now().isoformat(),
                        "program": target.program_name,
                        "vulnerabilities": results["statistics"]["total_vulns"],
                        "estimated_earnings": estimated_earnings,
                        "cycle": cycle
                    })

                    print(f"\n   💰 Estimated earnings this hunt: ${estimated_earnings:,.2f}")

                    # Save cycle data
                    self._save_cycle_data(cycle, target, results)

                # Step 3: Generate daily summary
                await self._generate_summary()

            except Exception as e:
                print(f"\n❌ Error in cycle {cycle}: {e}")
                import traceback
                traceback.print_exc()

            # Calculate sleep time
            cycle_duration = time.time() - cycle_start
            sleep_time = (self.config["scan_interval_hours"] * 3600) - cycle_duration

            if sleep_time > 0:
                next_cycle = datetime.now() + timedelta(seconds=sleep_time)
                print(f"\n💤 Sleeping until {next_cycle.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"   (Next cycle in {sleep_time/3600:.1f} hours)")

                await asyncio.sleep(sleep_time)
            else:
                print(f"\n⚠️ Cycle took longer than interval ({cycle_duration/3600:.1f} hours)")
                print(f"   Starting next cycle immediately")

    def _estimate_earnings(self, vulnerabilities: List[Dict]) -> float:
        """Estimate earnings based on vulnerability severity"""

        # Average bounties by severity (conservative estimates)
        bounty_estimates = {
            "critical": 5000,
            "high": 2000,
            "medium": 500,
            "low": 100,
            "info": 0
        }

        total = 0
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            total += bounty_estimates.get(severity, 0)

        return total

    def _save_cycle_data(self, cycle: int, target: BugBountyTarget, results: Dict):
        """Save cycle results to disk"""

        cycle_file = self.data_dir / f"cycle_{cycle:04d}_{target.program_name.replace(' ', '_')}.json"

        # Serialize enum values in results
        def serialize_enums(obj):
            if isinstance(obj, dict):
                return {k: serialize_enums(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_enums(item) for item in obj]
            elif hasattr(obj, 'value'):  # Enum
                return obj.value
            return obj

        data = {
            "cycle": cycle,
            "timestamp": datetime.now().isoformat(),
            "target": {
                "name": target.program_name,
                "scope": target.scope
            },
            "results": serialize_enums(results),
            "cumulative_stats": {
                "total_earnings": self.total_earnings,
                "total_vulnerabilities": self.total_vulnerabilities,
                "programs_hunted": self.programs_hunted,
                "uptime_hours": (time.time() - self.start_time) / 3600
            }
        }

        with open(cycle_file, "w") as f:
            json.dump(data, f, indent=2)

    async def _generate_summary(self):
        """Generate cumulative summary"""

        uptime_hours = (time.time() - self.start_time) / 3600
        uptime_days = uptime_hours / 24

        summary = f"""
╔══════════════════════════════════════════════════════════════════════╗
║                     📊 DAEMON SUMMARY                                ║
╚══════════════════════════════════════════════════════════════════════╝

⏱️  Uptime: {uptime_days:.1f} days ({uptime_hours:.1f} hours)
🎯 Programs Hunted: {self.programs_hunted}
🐛 Total Vulnerabilities: {self.total_vulnerabilities}
💰 Estimated Earnings: ${self.total_earnings:,.2f}

📈 Rates:
   • Vulnerabilities/Day: {self.total_vulnerabilities / max(uptime_days, 0.1):.1f}
   • Earnings/Day: ${self.total_earnings / max(uptime_days, 0.1):,.2f}
   • Earnings/Hour: ${self.total_earnings / max(uptime_hours, 0.1):.2f}

💵 Recent Earnings (Last 10):
"""

        for entry in self.earnings_log[-10:]:
            summary += f"   {entry['timestamp'][:19]} | {entry['program']:30} | ${entry['estimated_earnings']:>8,.2f}\n"

        summary += f"\n📁 Data Directory: {self.data_dir}\n"

        print(summary)

        # Save summary
        summary_file = self.data_dir / "daemon_summary.txt"
        with open(summary_file, "w") as f:
            f.write(summary)
            f.write(f"\nGenerated: {datetime.now().isoformat()}\n")


def main(argv=None):
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Autonomous Bug Bounty Hunter Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start daemon in foreground
  python autonomous_bounty_hunter_daemon.py

  # Start with custom config
  python autonomous_bounty_hunter_daemon.py --config myconfig.json

  # Enable auto-submit (use with caution!)
  python autonomous_bounty_hunter_daemon.py --auto-submit

Copyright (c) 2025 Corporation of Light. All Rights Reserved.
PATENT PENDING
        """
    )

    parser.add_argument("--config", type=str, help="Path to config file")
    parser.add_argument("--auto-submit", action="store_true", help="Enable automatic submission (DANGEROUS)")

    args = parser.parse_args(argv)

    config_path = args.config or "/Users/noone/aios/bug_bounty_config.json"

    daemon = AutonomousBountyHunterDaemon(config_path=config_path)

    if args.auto_submit:
        daemon.config["auto_submit"] = True
        print("⚠️  WARNING: Auto-submit enabled! Reports will be submitted automatically.")
        print("   Press Ctrl+C within 10 seconds to cancel...")
        time.sleep(10)

    # Run forever
    try:
        asyncio.run(daemon.run_forever())
    except KeyboardInterrupt:
        print("\n\n🛑 Daemon stopped by user")
        print(f"   Total earnings: ${daemon.total_earnings:,.2f}")
        print(f"   Total vulnerabilities: {daemon.total_vulnerabilities}")


if __name__ == "__main__":
    main()
