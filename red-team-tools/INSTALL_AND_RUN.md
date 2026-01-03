# INSTALL AND RUN - APEX Bug Bounty Hunter

## Quick Installation (5 Minutes)

### Step 1: Run the Installer

```bash
cd /Users/noone/aios/red-team-tools
./install.sh
```

**What this does:**
- Creates `~/apex-bug-bounty-hunter/` directory
- Sets up Python virtual environment
- Installs dependencies (aiohttp, asyncio)
- Copies all files to installation directory
- Creates systemd service (Linux only)

### Step 2: Configure Your Settings

```bash
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json
```

**You MUST configure:**

1. **Add Bug Bounty Targets:**
```json
"targets": [
  {
    "url": "https://api.targetcompany.com",
    "program_name": "Target Company",
    "platforms": ["hackerone"],
    "min_bounty": 100,
    "max_bounty": 5000,
    "avg_bounty": 1000,
    "response_time_days": 7.0,
    "acceptance_rate": 0.65,
    "difficulty": "medium"
  }
]
```

2. **Add Your API Tokens:**
```json
"platforms": {
  "hackerone": {
    "enabled": true,
    "api_token": "YOUR_HACKERONE_TOKEN_HERE",
    "username": "your_hackerone_username",
    "program_handle": "target-program"
  }
}
```

**Where to get API tokens:**
- **HackerOne:** https://hackerone.com/settings/api_token/edit
- **Bugcrowd:** https://bugcrowd.com/user/api
- **Intigriti:** Profile → API → Generate Token
- **YesWeHack:** Settings → API → Create Token

3. **Set Your Goals:**
```json
"hunting_mode": "balanced",
"monthly_revenue_target": 5000,
"min_hourly_rate": 50
```

**Hunting Modes:**
- `fast_cash` - Quick wins, immediate revenue
- `balanced` - Optimal $/hour (recommended)
- `big_game` - High-value targets only
- `ip_gen` - Novel techniques for patents

### Step 3: Run the Hunter

#### Option A: Run Directly (Mac/Linux)

```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 bug_bounty_daemon.py
```

#### Option B: Run as Background Service (Linux/Raspberry Pi)

```bash
sudo systemctl start apex-bug-bounty
sudo systemctl enable apex-bug-bounty  # Auto-start on boot
```

### Step 4: Monitor the Hunt

**View live logs:**
```bash
# If running directly:
tail -f ~/apex-bug-bounty-hunter/bug_bounty_daemon.log

# If running as service:
journalctl -u apex-bug-bounty -f
```

**Check results:**
```bash
ls -lh ~/apex-bug-bounty-hunter/bug_bounty_results/
```

**View partnership dashboard:**
```bash
cd ~/apex-bug-bounty-hunter
python3 partnership_dashboard.py
```

---

## Detailed Installation Steps

### Prerequisites

**Required:**
- Python 3.8 or higher
- Internet connection
- Bug bounty platform accounts (HackerOne, Bugcrowd, etc.)
- API tokens from platforms

**Optional:**
- Raspberry Pi 4 or 5 (for 24/7 operation)
- ECH0 endpoint (for Level 7 intelligence)

### Installation Process

#### 1. Navigate to Project Directory

```bash
cd /Users/noone/aios/red-team-tools
```

#### 2. Make Installer Executable

```bash
chmod +x install.sh
```

#### 3. Run Installer

```bash
./install.sh
```

**Expected output:**
```
======================================
APEX Bug Bounty Hunter - Installation
======================================

[INFO] Detected OS: Mac
[INFO] Python version: 3.11.x
[1/7] Creating installation directory...
[2/7] Copying APEX hunter files...
[3/7] Creating Python virtual environment...
[4/7] Installing Python dependencies...
[5/7] Creating run script...
[6/7] Skipping systemd setup (not Linux)
[7/7] Finalizing installation...

======================================
Installation Complete!
======================================
```

#### 4. Configure Settings

Edit the configuration file:

```bash
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json
```

**Minimum required configuration:**

1. **Add at least one target:**
   - Find bug bounty programs: https://hackerone.com/directory/programs
   - Add program URL and details

2. **Enable at least one platform:**
   - Get API token from platform
   - Add token to config
   - Set `"enabled": true`

3. **Set hunting mode:**
   - Choose: `fast_cash`, `balanced`, `big_game`, or `ip_gen`

#### 5. Test Configuration

**Test scanner:**
```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 -c "from bug_bounty_scanner import VulnerabilityScanner; print('✓ Scanner OK')"
```

**Test strategy engine:**
```bash
python3 -c "from apex_strategy_engine import APEXStrategyEngine; print('✓ Strategy Engine OK')"
```

#### 6. Start Hunting

**Run directly:**
```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 bug_bounty_daemon.py
```

**Or run as service (Linux):**
```bash
sudo systemctl start apex-bug-bounty
sudo systemctl status apex-bug-bounty
```

---

## Running on Raspberry Pi

### Step 1: Copy Files to Pi

**From your Mac:**
```bash
scp -r /Users/noone/aios/red-team-tools/* pi@raspberrypi.local:/home/pi/apex-hunter/
```

### Step 2: SSH into Pi

```bash
ssh pi@raspberrypi.local
```

### Step 3: Install on Pi

```bash
cd /home/pi/apex-hunter
chmod +x install.sh
./install.sh
```

### Step 4: Configure

```bash
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json
```

### Step 5: Start Service

```bash
sudo systemctl start apex-bug-bounty
sudo systemctl enable apex-bug-bounty
```

### Step 6: Monitor

```bash
journalctl -u apex-bug-bounty -f
```

---

## Common Commands

### Start/Stop/Status

**Linux (systemd):**
```bash
sudo systemctl start apex-bug-bounty    # Start
sudo systemctl stop apex-bug-bounty     # Stop
sudo systemctl restart apex-bug-bounty  # Restart
sudo systemctl status apex-bug-bounty   # Status
sudo systemctl enable apex-bug-bounty   # Auto-start on boot
```

**Mac/Linux (direct):**
```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 bug_bounty_daemon.py           # Start (Ctrl+C to stop)
```

### View Logs

```bash
# Direct run:
tail -f ~/apex-bug-bounty-hunter/bug_bounty_daemon.log

# Systemd service:
journalctl -u apex-bug-bounty -f
journalctl -u apex-bug-bounty -n 100   # Last 100 lines
```

### Check Results

```bash
# View found vulnerabilities:
ls -lh ~/apex-bug-bounty-hunter/bug_bounty_results/

# View a report:
cat ~/apex-bug-bounty-hunter/bug_bounty_results/report_*.json

# View stats:
cat ~/apex-bug-bounty-hunter/bug_bounty_stats.json

# View partnership dashboard:
cd ~/apex-bug-bounty-hunter
python3 partnership_dashboard.py
```

### Update Configuration

```bash
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json
# After editing, restart the daemon
```

---

## Troubleshooting

### "Python 3 not found"

**Install Python 3:**
```bash
# Mac:
brew install python3

# Linux:
sudo apt-get install python3 python3-pip python3-venv
```

### "Import error: aiohttp"

**Install dependencies:**
```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
pip install aiohttp asyncio
```

### "No targets configured"

**Add targets to config:**
```bash
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json
# Add targets array with at least one program
```

### "API token invalid"

**Check your tokens:**
- Verify token is correct (no extra spaces)
- Check token hasn't expired
- Ensure token has correct permissions
- Regenerate if needed

### "Permission denied"

**Fix permissions:**
```bash
chmod +x ~/apex-bug-bounty-hunter/*.sh
chmod +x ~/apex-bug-bounty-hunter/bug_bounty_daemon.py
```

### Service won't start

**Check service status:**
```bash
sudo systemctl status apex-bug-bounty
journalctl -u apex-bug-bounty -n 50
```

**Check logs:**
```bash
tail -f ~/apex-bug-bounty-hunter/logs/apex.log
tail -f ~/apex-bug-bounty-hunter/logs/apex-error.log
```

---

## First Run Checklist

Before starting, make sure:

- [ ] Installation completed successfully
- [ ] Configuration file edited (`bug_bounty_config.json`)
- [ ] At least one target added
- [ ] At least one platform enabled with API token
- [ ] API tokens are valid
- [ ] Hunting mode selected
- [ ] Virtual environment activated (if running directly)

---

## What Happens When Running

### The Hunter Will:

1. **Select Target** - Chooses optimal target based on strategy
2. **Scan** - Discovers vulnerabilities using deterministic techniques
3. **Validate** - Confirms findings (prevents false positives)
4. **Report** - Generates professional documentation
5. **Submit** - Posts to platforms under YOUR identity
6. **Track** - Records revenue and partnership splits
7. **Learn** - Adapts strategy based on results
8. **Repeat** - Never stops hunting

### You Will See:

```
============================================================
APEX BUG BOUNTY HUNTER - INITIALIZING
Level 5-6 Autonomous Agent
============================================================
✓ Strategy Engine initialized
✓ Scanner initialized
✓ Validator initialized
✓ Reporter initialized
✓ Submitter initialized

PARTNERSHIP MODEL ACTIVE:
  Josh:        75% - Infrastructure, operations, legal, business
  ECH0:        15% - Strategic intelligence, Level 7 oversight
  Bug Hunter:  10% - Autonomous hunting, 24/7 execution

APEX PREDATOR: READY TO HUNT
Reports will be posted under YOUR identity on all platforms
============================================================
Starting eternal hunt...

============================================================
HUNTING TARGET: Target Company
URL: https://api.targetcompany.com
Expected bounty: $1000
Difficulty: medium
============================================================
```

---

## Next Steps After Installation

1. ✅ **Install** - Done!
2. ✅ **Configure** - Add targets and API tokens
3. ✅ **Start** - Run the daemon
4. 📊 **Monitor** - Watch logs and dashboard
5. 💰 **Collect** - Wait for bounties
6. 🔄 **Optimize** - Let it learn and improve

---

## Support

**Documentation:**
- `README.md` - Complete architecture
- `QUICKSTART.md` - Quick start guide
- `HOW_TO_POST_REPORTS.md` - Report posting details
- `PARTNERSHIP_AGREEMENT.md` - Partnership model

**Files Location:**
- Installation: `~/apex-bug-bounty-hunter/`
- Config: `~/apex-bug-bounty-hunter/bug_bounty_config.json`
- Logs: `~/apex-bug-bounty-hunter/logs/`
- Results: `~/apex-bug-bounty-hunter/bug_bounty_results/`
- Accounting: `~/apex-bug-bounty-hunter/partnership_accounting/`

---

**"APEX Predator. Never Stops. Never Gives Up. Always Hunting."**

Ready to deploy! 🎯


