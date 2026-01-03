"""
StorageAgent - Volume Management & Filesystem Operations

Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
"""

import logging
import subprocess
import platform
import json
import shutil
from typing import Dict, List, Optional
from pathlib import Path

LOG = logging.getLogger(__name__)


class StorageAgent:
    """
    Meta-agent for storage management and filesystem operations.

    Responsibilities:
    - Volume management (mount/unmount, capacity monitoring)
    - Filesystem operations (directory creation, file management)
    - Disk space monitoring and optimization
    - Backup coordination
    - Storage performance metrics
    """

    def __init__(self):
        self.name = "storage"
        self.platform = platform.system()
        LOG.info(f"StorageAgent initialized on {self.platform}")

    def get_disk_usage(self) -> Dict:
        """Get disk usage statistics for all mounted filesystems."""
        try:
            usage_stats = []

            if self.platform == "Darwin":  # macOS
                result = subprocess.run(
                    ["df", "-h"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                for line in result.stdout.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        usage_stats.append({
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_percent": parts[4],
                            "mounted_on": parts[5] if len(parts) == 6 else " ".join(parts[5:]),
                        })

            elif self.platform == "Windows":
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name='Total';Expression={$_.Used+$_.Free}} | ConvertTo-Json"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.stdout:
                    drives = json.loads(result.stdout)
                    if not isinstance(drives, list):
                        drives = [drives]

                    for drive in drives:
                        if drive.get("Used") is not None:
                            total = drive.get("Total", 0)
                            used = drive.get("Used", 0)
                            free = drive.get("Free", 0)
                            use_percent = (used / total * 100) if total > 0 else 0

                            usage_stats.append({
                                "filesystem": f"{drive['Name']}:",
                                "size": f"{total / (1024**3):.1f}GB",
                                "used": f"{used / (1024**3):.1f}GB",
                                "available": f"{free / (1024**3):.1f}GB",
                                "use_percent": f"{use_percent:.0f}%",
                                "mounted_on": f"{drive['Name']}:",
                            })

            else:  # Linux
                result = subprocess.run(
                    ["df", "-h", "--output=source,size,used,avail,pcent,target"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                for line in result.stdout.splitlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        usage_stats.append({
                            "filesystem": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "available": parts[3],
                            "use_percent": parts[4],
                            "mounted_on": parts[5],
                        })

            return {
                "platform": self.platform,
                "filesystems": usage_stats,
                "total_filesystems": len(usage_stats),
            }

        except Exception as e:
            LOG.warning(f"Could not get disk usage: {e}")
            return {"status": "unknown", "error": str(e)}

    def check_space_available(self, path: str, required_gb: float) -> bool:
        """Check if sufficient space is available at the given path."""
        try:
            stat = shutil.disk_usage(path)
            available_gb = stat.free / (1024 ** 3)

            LOG.info(f"Path {path}: {available_gb:.2f}GB available, {required_gb:.2f}GB required")
            return available_gb >= required_gb

        except Exception as e:
            LOG.error(f"Could not check space for {path}: {e}")
            return False

    def optimize_storage(self) -> Dict:
        """Run storage optimization tasks (forensic-safe)."""
        optimizations = []

        try:
            # Check for large files that could be compressed
            if self.platform == "Darwin":
                result = subprocess.run(
                    ["find", "/Users", "-type", "f", "-size", "+1G", "-ls"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                large_files = len(result.stdout.splitlines())
                optimizations.append({
                    "category": "large_files",
                    "count": large_files,
                    "recommendation": "Consider compressing or archiving files >1GB",
                })

            # Check for duplicate files (basic heuristic: same size)
            # This is forensic-safe, read-only operation

            return {
                "platform": self.platform,
                "optimizations": optimizations,
                "forensic_mode": True,
                "status": "analyzed",
            }

        except Exception as e:
            LOG.warning(f"Could not optimize storage: {e}")
            return {"status": "error", "error": str(e)}

    def create_directory(self, path: str, forensic_mode: bool = False) -> bool:
        """Create directory if it doesn't exist."""
        try:
            if forensic_mode:
                LOG.info(f"[Forensic Mode] Would create directory: {path}")
                return True

            Path(path).mkdir(parents=True, exist_ok=True)
            LOG.info(f"Created directory: {path}")
            return True

        except Exception as e:
            LOG.error(f"Could not create directory {path}: {e}")
            return False

    def get_storage_health(self) -> Dict:
        """Get overall storage system health metrics."""
        try:
            usage = self.get_disk_usage()

            # Calculate warnings
            warnings = []
            critical = []

            for fs in usage.get("filesystems", []):
                use_pct_str = fs.get("use_percent", "0%").rstrip("%")
                try:
                    use_pct = float(use_pct_str)

                    if use_pct >= 95:
                        critical.append(f"{fs['mounted_on']}: {use_pct}% full")
                    elif use_pct >= 85:
                        warnings.append(f"{fs['mounted_on']}: {use_pct}% full")
                except ValueError:
                    pass

            status = "critical" if critical else "warn" if warnings else "ok"

            return {
                "tool": "StorageAgent",
                "status": status,
                "summary": f"{len(usage.get('filesystems', []))} filesystems monitored",
                "details": {
                    "filesystems": usage.get("filesystems", []),
                    "warnings": warnings,
                    "critical": critical,
                    "platform": self.platform,
                },
            }

        except Exception as e:
            LOG.error(f"Could not get storage health: {e}")
            return {
                "tool": "StorageAgent",
                "status": "error",
                "summary": f"Error: {str(e)[:100]}",
                "details": {"error": str(e)},
            }


# Standalone functions for Ai:oS integration
def check_disk_space() -> Dict:
    """Check disk space across all filesystems."""
    agent = StorageAgent()
    return agent.get_disk_usage()


def health_check() -> Dict:
    """Health check for StorageAgent."""
    agent = StorageAgent()
    return agent.get_storage_health()


def main(argv=None):
    """Main entrypoint for StorageAgent."""
    import argparse

    parser = argparse.ArgumentParser(description="Storage Agent - Volume Management")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--check", action="store_true", help="Run health check")
    parser.add_argument("--usage", action="store_true", help="Show disk usage")
    parser.add_argument("--optimize", action="store_true", help="Analyze storage optimization opportunities")

    args = parser.parse_args(argv)

    agent = StorageAgent()

    if args.check:
        result = agent.get_storage_health()
    elif args.usage:
        result = agent.get_disk_usage()
    elif args.optimize:
        result = agent.optimize_storage()
    else:
        result = agent.get_storage_health()

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*70}")
        print("STORAGE AGENT")
        print(f"{'='*70}\n")
        print(json.dumps(result, indent=2))
        print()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
