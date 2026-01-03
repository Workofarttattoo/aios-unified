#!/bin/bash

# Upload APEX Bug Bounty Hunter to Raspberry Pi
# =============================================

set -e

echo "======================================"
echo "APEX Bug Bounty Hunter - Pi Upload"
echo "======================================"
echo ""

# Try to find Raspberry Pi
echo "Looking for Raspberry Pi..."

# Common Pi hostnames/IPs
PI_HOSTNAMES=("raspberrypi.local" "raspberrypi" "pi@raspberrypi.local" "pi@raspberrypi")

# Try to find Pi on local network
PI_IP=""
for hostname in "${PI_HOSTNAMES[@]}"; do
    if ping -c 1 -W 1 "$hostname" &>/dev/null; then
        PI_IP="$hostname"
        echo "✓ Found Pi at: $PI_IP"
        break
    fi
done

# If not found, try to detect via arp
if [ -z "$PI_IP" ]; then
    echo "Scanning local network for Raspberry Pi..."
    
    # Get local network range
    LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
    
    if [ -n "$LOCAL_IP" ]; then
        NETWORK=$(echo $LOCAL_IP | cut -d'.' -f1-3)
        echo "Scanning $NETWORK.0/24..."
        
        # Try common Pi IPs
        for i in {1..254}; do
            TEST_IP="$NETWORK.$i"
            if ping -c 1 -W 1 "$TEST_IP" &>/dev/null; then
                # Try SSH to see if it's a Pi
                if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no pi@"$TEST_IP" "uname -a" &>/dev/null; then
                    PI_IP="pi@$TEST_IP"
                    echo "✓ Found Pi at: $PI_IP"
                    break
                fi
            fi
        done
    fi
fi

# If still not found, ask user
if [ -z "$PI_IP" ]; then
    echo ""
    echo "Could not automatically find Raspberry Pi."
    echo ""
    echo "Please provide one of:"
    echo "  1. Pi hostname (e.g., raspberrypi.local)"
    echo "  2. Pi IP address (e.g., 192.168.1.100)"
    echo "  3. Full SSH address (e.g., pi@192.168.1.100)"
    echo ""
    read -p "Enter Pi address: " PI_IP
    
    if [ -z "$PI_IP" ]; then
        echo "Error: No address provided"
        exit 1
    fi
fi

# Normalize PI_IP (add pi@ if not present)
if [[ ! "$PI_IP" == *"@"* ]]; then
    PI_IP="pi@$PI_IP"
fi

echo ""
echo "Uploading to: $PI_IP"
echo ""

# Create temporary directory on Pi
echo "[1/4] Creating directory on Pi..."
ssh "$PI_IP" "mkdir -p ~/apex-hunter"

# Copy all files
echo "[2/4] Copying files to Pi..."

# Core Python files
scp bug_bounty_daemon.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_scanner.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_validator.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_reporter.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_submitter.py "$PI_IP:~/apex-hunter/"
scp apex_strategy_engine.py "$PI_IP:~/apex-hunter/"

# Config and scripts
scp bug_bounty_config.json "$PI_IP:~/apex-hunter/"
scp install.sh "$PI_IP:~/apex-hunter/"
scp partnership_dashboard.py "$PI_IP:~/apex-hunter/"

# Documentation
scp README.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp QUICKSTART.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp INSTALL_AND_RUN.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp HOW_TO_POST_REPORTS.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp PARTNERSHIP_AGREEMENT.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp PARTNERSHIP_IMPLEMENTATION_SUMMARY.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true

echo "[3/4] Making install script executable..."
ssh "$PI_IP" "chmod +x ~/apex-hunter/install.sh"

echo "[4/4] Files uploaded successfully!"
echo ""

echo "======================================"
echo "Upload Complete!"
echo "======================================"
echo ""
echo "Next steps on Raspberry Pi:"
echo ""
echo "1. SSH into Pi:"
echo "   ssh $PI_IP"
echo ""
echo "2. Run installer:"
echo "   cd ~/apex-hunter"
echo "   ./install.sh"
echo ""
echo "3. Configure:"
echo "   nano ~/apex-bug-bounty-hunter/bug_bounty_config.json"
echo ""
echo "4. Start hunting:"
echo "   sudo systemctl start apex-bug-bounty"
echo "   sudo systemctl enable apex-bug-bounty"
echo ""
echo "5. Monitor:"
echo "   journalctl -u apex-bug-bounty -f"
echo ""
echo "======================================"


