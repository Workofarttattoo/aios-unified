#!/bin/bash

# APEX Bug Bounty Hunter - Installation Script
# =============================================
#
# This script sets up the bug bounty hunter for autonomous operation.
#
# COMPATIBLE WITH:
# - Raspberry Pi (4 or 5, recommended)
# - Ubuntu/Debian Linux
# - macOS
#
# DEPLOYMENT MODES:
# 1. Standalone: Local operation
# 2. ECH0-Connected: With strategic intelligence
# 3. Systemd Service: Background daemon (Linux only)

set -e

echo "======================================"
echo "APEX Bug Bounty Hunter - Installation"
echo "======================================"
echo ""

# Detect OS
OS="$(uname -s)"
case "${OS}" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    *)          MACHINE="UNKNOWN:${OS}"
esac

echo "[INFO] Detected OS: ${MACHINE}"
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "[INFO] Python version: ${PYTHON_VERSION}"
echo ""

# Set installation directory
if [ "${MACHINE}" == "Linux" ]; then
    INSTALL_DIR="${HOME}/apex-bug-bounty-hunter"
else
    INSTALL_DIR="${HOME}/apex-bug-bounty-hunter"
fi

echo "[1/7] Creating installation directory..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/logs"
mkdir -p "${INSTALL_DIR}/bug_bounty_results"

# Copy files
echo "[2/7] Copying APEX hunter files..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cp "${SCRIPT_DIR}/bug_bounty_daemon.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/bug_bounty_scanner.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/bug_bounty_validator.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/bug_bounty_reporter.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/bug_bounty_submitter.py" "${INSTALL_DIR}/"
cp "${SCRIPT_DIR}/apex_strategy_engine.py" "${INSTALL_DIR}/"

# Copy config if it doesn't exist
if [ ! -f "${INSTALL_DIR}/bug_bounty_config.json" ]; then
    if [ -f "${SCRIPT_DIR}/bug_bounty_config.json" ]; then
        cp "${SCRIPT_DIR}/bug_bounty_config.json" "${INSTALL_DIR}/"
    else
        # Create default config
        cat > "${INSTALL_DIR}/bug_bounty_config.json" << 'EOF'
{
  "scan_interval_seconds": 3600,
  "hunting_mode": "balanced",
  "monthly_revenue_target": 5000,
  "min_hourly_rate": 50,
  "auto_submit": false,
  "max_concurrent_scans": 2,
  
  "ech0_endpoint": "",
  "ech0_api_key": "",
  
  "targets": [
    {
      "url": "https://example.com",
      "program_name": "Example Program",
      "platforms": ["aios"],
      "min_bounty": 100,
      "max_bounty": 5000,
      "avg_bounty": 1000,
      "response_time_days": 7.0,
      "acceptance_rate": 0.65,
      "difficulty": "medium"
    }
  ],
  
  "platforms": {
    "hackerone": {
      "enabled": false,
      "api_token": "",
      "username": "",
      "program_handle": ""
    },
    "bugcrowd": {
      "enabled": false,
      "api_token": "",
      "program_code": ""
    },
    "aios": {
      "enabled": true,
      "api_endpoint": "https://red-team-tools.aios.is",
      "api_key": ""
    }
  },
  
  "scan_types": {
    "xss": true,
    "sqli": true,
    "ssrf": true,
    "idor": true,
    "auth_bypass": true,
    "csrf": true,
    "rce": false,
    "sensitive_data_exposure": true
  }
}
EOF
    fi
fi

# Create virtual environment
echo "[3/7] Creating Python virtual environment..."
cd "${INSTALL_DIR}"
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "[4/7] Installing Python dependencies..."
pip install --upgrade pip
pip install aiohttp asyncio

# Create run script
echo "[5/7] Creating run script..."
cat > "${INSTALL_DIR}/run.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python3 bug_bounty_daemon.py
EOF
chmod +x "${INSTALL_DIR}/run.sh"

# Setup systemd service (Linux only)
if [ "${MACHINE}" == "Linux" ]; then
    echo "[6/7] Setting up systemd service..."
    
    sudo tee /etc/systemd/system/apex-bug-bounty.service > /dev/null << EOF
[Unit]
Description=APEX Bug Bounty Hunter - Autonomous Security Research
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/bug_bounty_daemon.py
Restart=always
RestartSec=30
StandardOutput=append:${INSTALL_DIR}/logs/apex.log
StandardError=append:${INSTALL_DIR}/logs/apex-error.log

# Resource limits (important for Pi)
MemoryMax=2G
CPUQuota=80%

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF
    
    sudo systemctl daemon-reload
    
    echo ""
    echo "Systemd service created: apex-bug-bounty.service"
else
    echo "[6/7] Skipping systemd setup (not Linux)"
fi

# Create documentation symlinks
echo "[7/7] Finalizing installation..."
if [ -f "${SCRIPT_DIR}/README.md" ]; then
    cp "${SCRIPT_DIR}/README.md" "${INSTALL_DIR}/"
fi
if [ -f "${SCRIPT_DIR}/QUICKSTART.md" ]; then
    cp "${SCRIPT_DIR}/QUICKSTART.md" "${INSTALL_DIR}/"
fi

echo ""
echo "======================================"
echo "Installation Complete!"
echo "======================================"
echo ""
echo "Installation directory: ${INSTALL_DIR}"
echo ""
echo "NEXT STEPS:"
echo ""
echo "1. Configure the hunter:"
echo "   nano ${INSTALL_DIR}/bug_bounty_config.json"
echo ""
echo "2. Add your targets and API keys:"
echo "   - Bug bounty platform tokens"
echo "   - ECH0 endpoint (optional)"
echo "   - AiOS API key"
echo ""
echo "3. Run the hunter:"
if [ "${MACHINE}" == "Linux" ]; then
    echo "   sudo systemctl start apex-bug-bounty"
    echo "   sudo systemctl enable apex-bug-bounty  # Auto-start on boot"
    echo ""
    echo "   Monitor logs:"
    echo "   journalctl -u apex-bug-bounty -f"
    echo "   # OR:"
    echo "   tail -f ${INSTALL_DIR}/logs/apex.log"
else
    echo "   cd ${INSTALL_DIR}"
    echo "   ./run.sh"
    echo ""
    echo "   Monitor logs:"
    echo "   tail -f ${INSTALL_DIR}/bug_bounty_daemon.log"
fi
echo ""
echo "4. Check results:"
echo "   ls -lh ${INSTALL_DIR}/bug_bounty_results/"
echo ""
echo "======================================"
echo "The APEX hunter is ready to deploy."
echo "Never stops. Never gives up. Always learning."
echo "======================================"
echo ""

