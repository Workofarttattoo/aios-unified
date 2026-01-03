#!/bin/bash

# Direct upload to Raspberry Pi at 127.0.0.1
# ==========================================

set -e

PI_IP="pi@127.0.0.1"
PROJECT_DIR="/Users/noone/aios/red-team-tools"

echo "======================================"
echo "Uploading APEX Bug Bounty Hunter to Pi"
echo "Target: $PI_IP"
echo "======================================"
echo ""

cd "$PROJECT_DIR"

# Test connection
echo "[1/5] Testing connection to Pi..."
if ! ssh -o ConnectTimeout=5 "$PI_IP" "echo 'Connection OK'" 2>/dev/null; then
    echo "⚠️  Could not connect to $PI_IP"
    echo ""
    echo "Trying common alternatives..."
    
    # Try without pi@ prefix
    if ssh -o ConnectTimeout=5 "pi@localhost" "echo 'Connection OK'" 2>/dev/null; then
        PI_IP="pi@localhost"
        echo "✓ Connected via pi@localhost"
    else
        echo "Please check:"
        echo "  1. Pi is powered on and connected"
        echo "  2. SSH is enabled on Pi"
        echo "  3. Correct IP address"
        echo ""
        read -p "Enter Pi address (e.g., pi@192.168.1.100): " PI_IP
        if [ -z "$PI_IP" ]; then
            echo "Error: No address provided"
            exit 1
        fi
    fi
fi

echo "✓ Connected to: $PI_IP"
echo ""

# Create directory on Pi
echo "[2/5] Creating directory on Pi..."
ssh "$PI_IP" "mkdir -p ~/apex-hunter"

# Upload core Python files
echo "[3/5] Uploading core Python files..."
scp bug_bounty_daemon.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_scanner.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_validator.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_reporter.py "$PI_IP:~/apex-hunter/"
scp bug_bounty_submitter.py "$PI_IP:~/apex-hunter/"
scp apex_strategy_engine.py "$PI_IP:~/apex-hunter/"
scp partnership_dashboard.py "$PI_IP:~/apex-hunter/"

# Upload config and scripts
echo "[4/5] Uploading config and scripts..."
scp bug_bounty_config.json "$PI_IP:~/apex-hunter/"
scp install.sh "$PI_IP:~/apex-hunter/"

# Upload documentation
echo "[5/5] Uploading documentation..."
scp INSTALL_AND_RUN.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp HOW_TO_POST_REPORTS.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp PARTNERSHIP_AGREEMENT.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true
scp QUICKSTART.md "$PI_IP:~/apex-hunter/" 2>/dev/null || true

# Make install script executable
echo "Making install script executable..."
ssh "$PI_IP" "chmod +x ~/apex-hunter/install.sh && chmod +x ~/apex-hunter/*.py"

echo ""
echo "======================================"
echo "✓ Upload Complete!"
echo "======================================"
echo ""
echo "Files uploaded to: ~/apex-hunter/ on Pi"
echo ""
echo "Next steps:"
echo ""
echo "1. SSH into Pi:"
echo "   ssh $PI_IP"
echo ""
echo "2. Run installer:"
echo "   cd ~/apex-hunter"
echo "   ./install.sh"
echo ""
echo "3. Configure (add targets and API tokens):"
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


