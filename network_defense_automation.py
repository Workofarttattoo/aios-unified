#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Network Defense Automation System
Implements Echo 14B's tactical security recommendations for intrusion response
"""

import subprocess
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

class NetworkDefenseSystem:
    """Automated network defense based on Echo 14B recommendations"""

    def __init__(self):
        self.log_entries = []
        self.blocked_ips = []
        self.firewall_rules = []

    def log(self, level: str, message: str, data: Optional[Dict] = None):
        """Log defense actions"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        self.log_entries.append(entry)
        prefix = {"info": "[info]", "warn": "[warn]", "error": "[error]"}.get(level, "[info]")
        print(f"{prefix} {message}")
        if data:
            print(f"  Data: {json.dumps(data, indent=2)}")

    def check_firewall_status(self) -> bool:
        """Check macOS firewall status (pfctl)"""
        try:
            result = subprocess.run(
                ['sudo', 'pfctl', '-s', 'info'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                enabled = "Status: Enabled" in result.stdout
                self.log("info", f"Firewall status: {'Enabled' if enabled else 'Disabled'}")
                return enabled
            else:
                self.log("warn", "Unable to check firewall status (requires sudo)")
                return False

        except Exception as e:
            self.log("error", f"Firewall check failed: {e}")
            return False

    def block_suspicious_ip(self, ip: str, reason: str = "Intrusion attempt"):
        """Add firewall rule to block IP (requires sudo)"""
        try:
            # macOS pfctl rule
            rule = f"block drop from {ip} to any"

            self.log("info", f"Would block IP: {ip}", {"reason": reason, "rule": rule})
            self.blocked_ips.append({"ip": ip, "reason": reason, "time": datetime.now().isoformat()})

            # Note: Actual blocking requires sudo and active pfctl configuration
            # Command would be: echo "block drop from {ip} to any" | sudo pfctl -f -

        except Exception as e:
            self.log("error", f"Failed to block IP {ip}: {e}")

    def scan_open_ports(self, target: str) -> List[int]:
        """Scan for open ports on target"""
        import socket

        common_ports = [21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443]
        open_ports = []

        self.log("info", f"Scanning ports on {target}")

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                sock.close()

                if result == 0:
                    open_ports.append(port)
                    self.log("warn", f"Open port detected: {target}:{port}")

            except Exception:
                continue

        return open_ports

    def analyze_threat_level(self, device_info: Dict) -> str:
        """Analyze device threat level"""
        mac = device_info.get("mac", "")
        ip = device_info.get("ip", "")

        # Check for locally administered MAC (randomized/spoofed)
        if mac and len(mac) >= 2:
            first_octet = int(mac.split(':')[0], 16)
            if first_octet & 0x02:  # Second bit set = locally administered
                return "suspicious"

        # Check for known Raspberry Pi vendors
        pi_macs = ["b8:27:eb", "dc:a6:32", "e4:5f:01"]
        if any(mac.lower().startswith(pm) for pm in pi_macs):
            return "likely_raspberry_pi"

        # Private IP range check
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "local_network"

        return "unknown"

    def deploy_ids_monitoring(self):
        """Deploy Intrusion Detection System monitoring"""
        self.log("info", "Deploying IDS monitoring")

        # Check if tcpdump is available
        try:
            result = subprocess.run(['which', 'tcpdump'], capture_output=True)
            if result.returncode == 0:
                self.log("info", "tcpdump available for packet capture")

                # Example IDS command (requires sudo)
                ids_cmd = "sudo tcpdump -i en0 -n -c 1000 -w /tmp/network_capture.pcap"
                self.log("info", f"IDS capture command: {ids_cmd}")
            else:
                self.log("warn", "tcpdump not available")

        except Exception as e:
            self.log("error", f"IDS deployment failed: {e}")

    def run_red_team_scan(self, target: str):
        """Run red team security tools on target"""
        self.log("info", f"Running red team reconnaissance on {target}")

        # Scan open ports
        open_ports = self.scan_open_ports(target)

        if open_ports:
            self.log("warn", f"Found {len(open_ports)} open ports on {target}", {
                "ports": open_ports
            })
        else:
            self.log("info", f"No common open ports detected on {target}")

    def generate_report(self) -> Dict:
        """Generate comprehensive defense report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "analyst": "Echo 14B + Claude Code Network Defense",
            "actions_taken": len(self.log_entries),
            "blocked_ips": self.blocked_ips,
            "firewall_rules": self.firewall_rules,
            "log": self.log_entries,
            "recommendations": {
                "immediate": [
                    "Enable pfctl firewall with strict rules",
                    "Monitor /var/log/system.log for intrusion attempts",
                    "Install and configure Little Snitch or LuLu for application firewall",
                    "Enable File Vault encryption",
                    "Review cron jobs and LaunchAgents for persistence"
                ],
                "ongoing": [
                    "Daily log analysis",
                    "Weekly network scans",
                    "Monthly security audits",
                    "Keep macOS and all software updated"
                ]
            }
        }

        return report


def main():
    """Main entry point for network defense automation"""
    print("="*70)
    print("🛡️  Network Defense Automation System")
    print("Based on Echo 14B Tactical Recommendations")
    print("="*70)
    print()

    defense = NetworkDefenseSystem()

    # Analyze detected devices
    detected_devices = {
        "192.168.0.1": {"mac": "ac:4c:a5:3e:90:a3", "type": "router"},
        "192.168.0.122": {"mac": "a2:38:a9:29:54:c2", "type": "unknown"},
        "192.168.0.210": {"mac": "d2:d7:73:43:33:76", "type": "unknown"},
        "192.168.0.223": {"mac": "ca:86:28:60:70:a5", "type": "this_machine"}
    }

    print("\n[Phase 1] Device Analysis")
    print("-" * 70)
    for ip, info in detected_devices.items():
        info['ip'] = ip
        threat_level = defense.analyze_threat_level(info)
        defense.log("info", f"Device {ip}: {threat_level}", info)

        if threat_level == "suspicious":
            # Note: Not blocking Raspberry Pi devices as user confirmed
            defense.log("warn", f"Suspicious device detected but not blocking: {ip}")

    print("\n[Phase 2] Firewall Status")
    print("-" * 70)
    defense.check_firewall_status()

    print("\n[Phase 3] Port Scanning")
    print("-" * 70)
    for ip in ["192.168.0.122", "192.168.0.210"]:
        defense.run_red_team_scan(ip)

    print("\n[Phase 4] IDS Deployment")
    print("-" * 70)
    defense.deploy_ids_monitoring()

    print("\n[Phase 5] Report Generation")
    print("-" * 70)
    report = defense.generate_report()

    report_file = "/tmp/network_defense_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n✅ Defense report saved to: {report_file}")
    print(f"📊 Total actions logged: {len(defense.log_entries)}")
    print(f"🔒 Blocked IPs: {len(defense.blocked_ips)}")

    print("\n" + "="*70)
    print("🤖 Echo 14B Recommendations:")
    print("="*70)
    for rec in report['recommendations']['immediate']:
        print(f"  • {rec}")


if __name__ == "__main__":
    main()
