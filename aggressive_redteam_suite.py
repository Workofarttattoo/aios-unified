#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Aggressive Red Team Security Suite
Authorized by Joshua for defensive network security
Implements Echo 14B's militarized security recommendations
"""

import subprocess
import socket
import json
import time
import threading
import smtplib
from datetime import datetime
from typing import Dict, List, Set, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

class AggressivePortScanner:
    """Aggressive port scanner with service detection"""

    def __init__(self):
        # Extended port list including exploit-prone services
        self.critical_ports = {
            20: "FTP-Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPCbind",
            135: "MSRPC",
            139: "NetBIOS-SSN",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            512: "exec",
            513: "login",
            514: "shell",
            1433: "MSSQL",
            1521: "Oracle",
            2049: "NFS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
            50000: "SAP"
        }

    def aggressive_scan(self, target: str) -> Dict:
        """Perform aggressive port scan with service fingerprinting"""
        print(f"[REDTEAM] Launching aggressive scan on {target}")

        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "open_ports": [],
            "services": {},
            "vulnerabilities": []
        }

        for port, service in self.critical_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))

                if result == 0:
                    results["open_ports"].append(port)

                    # Try banner grabbing
                    banner = self._grab_banner(target, port)
                    results["services"][port] = {
                        "name": service,
                        "banner": banner
                    }

                    # Check for known vulnerabilities
                    vulns = self._check_vulnerabilities(port, service, banner)
                    if vulns:
                        results["vulnerabilities"].extend(vulns)

                    print(f"  [!] OPEN: {port}/{service} - {banner[:50] if banner else 'No banner'}")

                sock.close()

            except Exception as e:
                pass

        return results

    def _grab_banner(self, target: str, port: int) -> Optional[str]:
        """Aggressive banner grabbing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))

            # Send probe data for certain services
            if port == 80:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 21:
                pass  # FTP sends banner automatically

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner

        except Exception:
            return None

    def _check_vulnerabilities(self, port: int, service: str, banner: Optional[str]) -> List[Dict]:
        """Check for known vulnerabilities based on service/banner"""
        vulns = []

        # Known vulnerable configurations
        if port == 23:  # Telnet
            vulns.append({
                "severity": "CRITICAL",
                "description": "Telnet is unencrypted and easily compromised",
                "recommendation": "Disable Telnet, use SSH instead"
            })

        if port == 21 and banner and "vsFTPd 2.3.4" in banner:
            vulns.append({
                "severity": "CRITICAL",
                "description": "vsFTPd 2.3.4 backdoor vulnerability",
                "cve": "CVE-2011-2523",
                "recommendation": "Update vsFTPd immediately"
            })

        if port == 445:  # SMB
            vulns.append({
                "severity": "HIGH",
                "description": "SMB exposed - potential for EternalBlue exploitation",
                "cve": "CVE-2017-0144",
                "recommendation": "Ensure patches applied, restrict SMB access"
            })

        if port == 3389:  # RDP
            vulns.append({
                "severity": "HIGH",
                "description": "RDP exposed - potential BlueKeep vulnerability",
                "cve": "CVE-2019-0708",
                "recommendation": "Update Windows, use VPN for RDP access"
            })

        if port in [6379, 27017]:  # Redis, MongoDB
            vulns.append({
                "severity": "HIGH",
                "description": f"{service} exposed without authentication",
                "recommendation": "Enable authentication, restrict network access"
            })

        return vulns


class NetworkIntrusionDetector:
    """Real-time network intrusion detection"""

    def __init__(self):
        self.baseline_devices = set()
        self.known_good_ips = {"192.168.0.1", "192.168.0.223"}  # Router and your Mac
        self.alert_callbacks = []
        self.running = False

    def add_alert_callback(self, callback):
        """Add callback function for alerts"""
        self.alert_callbacks.append(callback)

    def _trigger_alert(self, alert_type: str, data: Dict):
        """Trigger all registered alert callbacks"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": self._calculate_severity(alert_type, data),
            "data": data
        }

        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"[ERROR] Alert callback failed: {e}")

    def _calculate_severity(self, alert_type: str, data: Dict) -> str:
        """Calculate alert severity"""
        if alert_type == "new_device":
            return "HIGH"
        elif alert_type == "port_scan_detected":
            return "CRITICAL"
        elif alert_type == "suspicious_traffic":
            return "MEDIUM"
        elif alert_type == "vulnerability_found":
            return "CRITICAL"
        return "LOW"

    def scan_network(self) -> Set[str]:
        """Scan network for active devices"""
        devices = set()

        try:
            # Quick ARP scan
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            import re
            for line in result.stdout.split('\n'):
                match = re.search(r'\(([0-9.]+)\)', line)
                if match:
                    ip = match.group(1)
                    if not ip.startswith('224.'):  # Skip multicast
                        devices.add(ip)

        except Exception as e:
            print(f"[ERROR] Network scan failed: {e}")

        return devices

    def monitor_continuous(self, interval: int = 30):
        """Continuous network monitoring"""
        self.running = True
        print(f"[IDS] Starting continuous monitoring (interval: {interval}s)")

        # Establish baseline
        self.baseline_devices = self.scan_network()
        print(f"[IDS] Baseline established: {len(self.baseline_devices)} devices")

        while self.running:
            try:
                current_devices = self.scan_network()

                # Detect new devices
                new_devices = current_devices - self.baseline_devices
                if new_devices:
                    for ip in new_devices:
                        if ip not in self.known_good_ips:
                            self._trigger_alert("new_device", {
                                "ip": ip,
                                "message": f"New unknown device detected: {ip}"
                            })
                            print(f"[!] ALERT: New device detected: {ip}")

                # Detect removed devices
                removed_devices = self.baseline_devices - current_devices
                if removed_devices:
                    for ip in removed_devices:
                        print(f"[INFO] Device disconnected: {ip}")

                # Update baseline
                self.baseline_devices = current_devices

                time.sleep(interval)

            except Exception as e:
                print(f"[ERROR] Monitoring error: {e}")
                time.sleep(interval)

    def stop(self):
        """Stop monitoring"""
        self.running = False
        print("[IDS] Monitoring stopped")


class AlertSystem:
    """Multi-channel alert system"""

    def __init__(self):
        self.alert_log = []
        self.email_alerts_enabled = False
        self.sms_alerts_enabled = False

    def configure_email(self, smtp_server: str, smtp_port: int,
                       email_from: str, email_to: str, password: str):
        """Configure email alerts"""
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.email_from = email_from
        self.email_to = email_to
        self.email_password = password
        self.email_alerts_enabled = True

    def send_alert(self, alert: Dict):
        """Send alert through all enabled channels"""
        self.alert_log.append(alert)

        # Console alert
        self._console_alert(alert)

        # File alert
        self._file_alert(alert)

        # Email alert (if configured)
        if self.email_alerts_enabled:
            self._email_alert(alert)

        # Desktop notification
        self._desktop_notification(alert)

    def _console_alert(self, alert: Dict):
        """Print alert to console"""
        severity_colors = {
            "LOW": "\033[92m",      # Green
            "MEDIUM": "\033[93m",   # Yellow
            "HIGH": "\033[91m",     # Red
            "CRITICAL": "\033[95m"  # Magenta
        }

        color = severity_colors.get(alert["severity"], "\033[0m")
        reset = "\033[0m"

        print(f"\n{'='*70}")
        print(f"{color}[ALERT] {alert['severity']} - {alert['type']}{reset}")
        print(f"Time: {alert['timestamp']}")
        print(f"Data: {json.dumps(alert['data'], indent=2)}")
        print(f"{'='*70}\n")

    def _file_alert(self, alert: Dict):
        """Log alert to file"""
        log_file = "/tmp/security_alerts.log"

        with open(log_file, 'a') as f:
            f.write(f"{json.dumps(alert)}\n")

    def _email_alert(self, alert: Dict):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = self.email_to
            msg['Subject'] = f"[SECURITY ALERT] {alert['severity']} - {alert['type']}"

            body = f"""
Security Alert Detected

Severity: {alert['severity']}
Type: {alert['type']}
Timestamp: {alert['timestamp']}

Details:
{json.dumps(alert['data'], indent=2)}

---
Automated Alert from Echo 14B Network Defense System
            """

            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_from, self.email_password)
            server.send_message(msg)
            server.quit()

            print("[EMAIL] Alert sent successfully")

        except Exception as e:
            print(f"[ERROR] Failed to send email alert: {e}")

    def _desktop_notification(self, alert: Dict):
        """Send macOS desktop notification"""
        try:
            title = f"Security Alert: {alert['severity']}"
            message = f"{alert['type']}: {alert['data'].get('message', 'Security event detected')}"

            # macOS notification
            os.system(f"""
                osascript -e 'display notification "{message}" with title "{title}" sound name "Basso"'
            """)

        except Exception as e:
            print(f"[WARN] Desktop notification failed: {e}")


class AggressiveRedTeamSuite:
    """Main orchestrator for aggressive red team operations"""

    def __init__(self):
        self.scanner = AggressivePortScanner()
        self.ids = NetworkIntrusionDetector()
        self.alert_system = AlertSystem()

        # Register alert callback
        self.ids.add_alert_callback(self.alert_system.send_alert)

        self.scan_results = {}

    def deploy_full_suite(self):
        """Deploy all red team tools aggressively"""
        print("\n" + "="*70)
        print("🔴 AGGRESSIVE RED TEAM DEPLOYMENT")
        print("Authorized by Joshua Hendricks Cole")
        print("Echo 14B Tactical Security Suite")
        print("="*70 + "\n")

        # Scan all detected network devices
        devices = self.ids.scan_network()

        print(f"[SCAN] Found {len(devices)} active devices\n")

        for device_ip in devices:
            if device_ip == "192.168.0.223":  # Skip own machine
                continue

            print(f"\n[TARGET] Scanning {device_ip}")
            print("-" * 70)

            scan_result = self.scanner.aggressive_scan(device_ip)
            self.scan_results[device_ip] = scan_result

            # Alert on vulnerabilities
            if scan_result["vulnerabilities"]:
                self.alert_system.send_alert({
                    "timestamp": datetime.now().isoformat(),
                    "type": "vulnerability_found",
                    "severity": "CRITICAL",
                    "data": {
                        "ip": device_ip,
                        "vulnerabilities": scan_result["vulnerabilities"],
                        "message": f"Vulnerabilities found on {device_ip}"
                    }
                })

        # Save comprehensive report
        self._save_report()

        print("\n" + "="*70)
        print("✅ Aggressive scanning complete")
        print(f"📊 Scanned {len(self.scan_results)} targets")
        print(f"🚨 Total alerts: {len(self.alert_system.alert_log)}")
        print("="*70 + "\n")

    def start_continuous_monitoring(self, interval: int = 30):
        """Start continuous IDS monitoring"""
        print(f"\n[IDS] Launching continuous monitoring (scan every {interval}s)")
        print("[IDS] Press Ctrl+C to stop\n")

        monitor_thread = threading.Thread(
            target=self.ids.monitor_continuous,
            args=(interval,),
            daemon=True
        )
        monitor_thread.start()

        return monitor_thread

    def _save_report(self):
        """Save comprehensive security report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "scan_results": self.scan_results,
            "alerts": self.alert_system.alert_log,
            "summary": {
                "devices_scanned": len(self.scan_results),
                "total_vulnerabilities": sum(
                    len(r["vulnerabilities"]) for r in self.scan_results.values()
                ),
                "total_open_ports": sum(
                    len(r["open_ports"]) for r in self.scan_results.values()
                ),
                "alerts_triggered": len(self.alert_system.alert_log)
            }
        }

        report_file = "/tmp/aggressive_redteam_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Report saved: {report_file}")


def main():
    """Main entry point"""
    suite = AggressiveRedTeamSuite()

    # Deploy aggressive scanning
    suite.deploy_full_suite()

    # Start continuous monitoring
    print("\n🔍 Starting continuous monitoring...")
    monitor_thread = suite.start_continuous_monitoring(interval=30)

    try:
        # Keep running
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[STOP] Shutting down...")
        suite.ids.stop()
        print("[EXIT] Aggressive Red Team Suite terminated")


if __name__ == "__main__":
    main()
