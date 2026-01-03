#!/bin/bash
# Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.
#
# Aggressive Red Team Network Scan
# Quick deployment script for immediate threat assessment

echo "========================================================================"
echo "🔴 AGGRESSIVE RED TEAM SECURITY SCAN"
echo "Echo 14B + Claude Code Defensive Suite"
echo "========================================================================"
echo ""

cd /Users/noone/aios

# Check if daemon is running
if python3 security_alert_daemon.py status > /dev/null 2>&1; then
    echo "✅ Alert daemon is running"
else
    echo "🚀 Starting alert daemon..."
    python3 security_alert_daemon.py start
    sleep 2
fi

echo ""
echo "📡 Scanning network for threats..."
echo ""

# Get all devices on network
echo "[Phase 1] Network Device Discovery"
echo "----------------------------------------"
arp -a | grep -v "incomplete"
echo ""

# Aggressive port scan on suspicious devices
echo "[Phase 2] Port Scanning Suspicious Devices"
echo "----------------------------------------"

SUSPICIOUS_IPS="192.168.0.122 192.168.0.210"

for IP in $SUSPICIOUS_IPS; do
    echo ""
    echo "🎯 Targeting: $IP"
    echo ""

    # Check if host is up
    if ping -c 1 -W 1 $IP > /dev/null 2>&1; then
        echo "  [✓] Host is UP"

        # Aggressive nmap scan if available
        if command -v nmap &> /dev/null; then
            echo "  [SCAN] Running nmap aggressive scan..."
            sudo nmap -A -T4 -p- $IP 2>/dev/null | head -50
        else
            # Manual port scan
            echo "  [SCAN] Manual port scanning (common ports)..."

            for PORT in 21 22 23 25 80 443 445 3306 3389 5432 5900 8080; do
                timeout 1 bash -c "echo >/dev/tcp/$IP/$PORT" 2>/dev/null && \
                    echo "    [!] OPEN: $PORT"
            done
        fi

        # Check for common vulnerabilities
        echo "  [VULN] Checking for common exploits..."

        # Check for SMB (EternalBlue)
        timeout 1 bash -c "echo >/dev/tcp/$IP/445" 2>/dev/null && \
            echo "    [!] SMB EXPOSED - Potential EternalBlue target (CVE-2017-0144)"

        # Check for RDP (BlueKeep)
        timeout 1 bash -c "echo >/dev/tcp/$IP/3389" 2>/dev/null && \
            echo "    [!] RDP EXPOSED - Potential BlueKeep vulnerability (CVE-2019-0708)"

        # Check for Telnet
        timeout 1 bash -c "echo >/dev/tcp/$IP/23" 2>/dev/null && \
            echo "    [!] TELNET EXPOSED - Unencrypted access (CRITICAL)"

    else
        echo "  [✗] Host is DOWN or blocking ICMP"
    fi

    echo ""
done

echo ""
echo "[Phase 3] Check Alert Logs"
echo "----------------------------------------"

if [ -f /tmp/security_alerts.json ]; then
    echo "Security Alerts:"
    cat /tmp/security_alerts.json | python3 -m json.tool | tail -50
else
    echo "No alerts triggered yet"
fi

echo ""
echo "========================================================================"
echo "✅ Scan Complete"
echo ""
echo "📊 Reports saved to:"
echo "   - /tmp/security_daemon.log (daemon log)"
echo "   - /tmp/security_alerts.json (alerts)"
echo "   - /tmp/network_defense_report.json (defense report)"
echo ""
echo "🛡️  Continuous monitoring is ACTIVE (PID: $(cat /tmp/security_alert_daemon.pid 2>/dev/null || echo 'N/A'))"
echo "========================================================================"
