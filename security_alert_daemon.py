#!/usr/bin/env python3
"""
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Security Alert Daemon
Continuous monitoring with automated intrusion alerts
Runs as background service for 24/7 protection
"""

import os
import sys
import time
import json
import subprocess
import signal
from datetime import datetime
from pathlib import Path

class SecurityAlertDaemon:
    """Background daemon for continuous security monitoring"""

    def __init__(self):
        self.pid_file = "/tmp/security_alert_daemon.pid"
        self.log_file = "/tmp/security_daemon.log"
        self.running = False

    def log(self, message: str):
        """Log to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"

        with open(self.log_file, 'a') as f:
            f.write(log_entry)

        print(log_entry.strip())

    def start_daemon(self):
        """Start daemon in background"""
        # Check if already running
        if os.path.exists(self.pid_file):
            with open(self.pid_file, 'r') as f:
                old_pid = f.read().strip()

            print(f"[WARN] Daemon may already be running (PID: {old_pid})")
            print("[INFO] Stopping old instance...")
            self.stop_daemon()

        # Fork process
        try:
            pid = os.fork()
            if pid > 0:
                # Parent process
                print(f"[INFO] Daemon started with PID: {pid}")
                with open(self.pid_file, 'w') as f:
                    f.write(str(pid))
                return

        except OSError as e:
            print(f"[ERROR] Fork failed: {e}")
            sys.exit(1)

        # Child process continues
        os.setsid()
        os.chdir('/')

        # Run daemon
        self.run()

    def stop_daemon(self):
        """Stop running daemon"""
        if not os.path.exists(self.pid_file):
            print("[INFO] Daemon not running")
            return

        with open(self.pid_file, 'r') as f:
            pid = int(f.read().strip())

        try:
            os.kill(pid, signal.SIGTERM)
            print(f"[INFO] Stopped daemon (PID: {pid})")
            os.remove(self.pid_file)
        except ProcessLookupError:
            print("[WARN] Daemon process not found, cleaning up PID file")
            os.remove(self.pid_file)
        except Exception as e:
            print(f"[ERROR] Failed to stop daemon: {e}")

    def run(self):
        """Main daemon loop"""
        self.running = True
        self.log("Security Alert Daemon started")

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)

        baseline_devices = self._scan_network()
        self.log(f"Baseline: {len(baseline_devices)} devices")

        while self.running:
            try:
                current_devices = self._scan_network()

                # Check for new devices
                new_devices = current_devices - baseline_devices
                if new_devices:
                    for ip in new_devices:
                        self._send_alert("NEW_DEVICE", {
                            "ip": ip,
                            "message": f"New device detected: {ip}"
                        })

                # Check for removed devices
                removed = baseline_devices - current_devices
                if removed:
                    self.log(f"Devices disconnected: {removed}")

                baseline_devices = current_devices

                # Sleep for 30 seconds
                time.sleep(30)

            except Exception as e:
                self.log(f"ERROR: {e}")
                time.sleep(60)

    def _handle_sigterm(self, signum, frame):
        """Handle termination signal"""
        self.log("Received termination signal, shutting down...")
        self.running = False
        sys.exit(0)

    def _scan_network(self) -> set:
        """Scan network for devices"""
        devices = set()

        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)

            import re
            for line in result.stdout.split('\n'):
                match = re.search(r'\(([0-9.]+)\)', line)
                if match:
                    ip = match.group(1)
                    if not ip.startswith('224.'):
                        devices.add(ip)

        except Exception as e:
            self.log(f"Scan error: {e}")

        return devices

    def _send_alert(self, alert_type: str, data: dict):
        """Send security alert"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "type": alert_type,
            "severity": "HIGH",
            "data": data
        }

        # Log alert
        self.log(f"ALERT [{alert_type}]: {data['message']}")

        # Save to alerts file
        alerts_file = "/tmp/security_alerts.json"
        alerts = []

        if os.path.exists(alerts_file):
            with open(alerts_file, 'r') as f:
                try:
                    alerts = json.load(f)
                except:
                    alerts = []

        alerts.append(alert)

        with open(alerts_file, 'w') as f:
            json.dump(alerts, f, indent=2)

        # Desktop notification
        try:
            os.system(f"""
                osascript -e 'display notification "{data['message']}" with title "Security Alert: {alert_type}" sound name "Basso"'
            """)
        except:
            pass

    def status(self):
        """Check daemon status"""
        if not os.path.exists(self.pid_file):
            print("[INFO] Daemon is NOT running")
            return False

        with open(self.pid_file, 'r') as f:
            pid = int(f.read().strip())

        try:
            os.kill(pid, 0)  # Check if process exists
            print(f"[INFO] Daemon is RUNNING (PID: {pid})")

            # Check log file
            if os.path.exists(self.log_file):
                print(f"[INFO] Log file: {self.log_file}")
                print("\nRecent log entries:")
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-10:]:
                        print(f"  {line.strip()}")

            return True

        except ProcessLookupError:
            print(f"[WARN] PID file exists but process {pid} not found")
            os.remove(self.pid_file)
            return False


def main():
    """Main entry point"""
    daemon = SecurityAlertDaemon()

    if len(sys.argv) < 2:
        print("Usage: python3 security_alert_daemon.py {start|stop|restart|status}")
        sys.exit(1)

    command = sys.argv[1]

    if command == "start":
        print("🛡️  Starting Security Alert Daemon...")
        daemon.start_daemon()

    elif command == "stop":
        print("🛑 Stopping Security Alert Daemon...")
        daemon.stop_daemon()

    elif command == "restart":
        print("🔄 Restarting Security Alert Daemon...")
        daemon.stop_daemon()
        time.sleep(1)
        daemon.start_daemon()

    elif command == "status":
        daemon.status()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
