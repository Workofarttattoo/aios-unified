# APEX Bug Bounty Hunter - Quick Start

## TL;DR - Get Hunting in 5 Minutes

### Option 1: Raspberry Pi Deployment (Recommended)

```bash
# On your computer, copy files to Pi
scp -r /home/claude/* pi@raspberrypi.local:/home/pi/apex-hunter/

# SSH into Pi
ssh pi@raspberrypi.local

# Run installer
cd /home/pi/apex-hunter
./install.sh

# Edit config (add your API keys and targets)
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json

# Start hunting
sudo systemctl start apex-bug-bounty
sudo systemctl enable apex-bug-bounty

# Watch the hunt
tail -f ~/apex-bug-bounty-hunter/logs/apex.log
```

### Option 2: Local Machine (Mac/Linux)

```bash
cd /home/claude
./install.sh

# Edit config
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json

# Run directly
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 bug_bounty_daemon.py
```

---

## Essential Configuration

Edit `bug_bounty_config.json` with:

### 1. Add Targets (Bug Bounty Programs)

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

**Where to find targets:**
- HackerOne: https://hackerone.com/directory/programs
- Bugcrowd: https://bugcrowd.com/programs
- Intigriti: https://www.intigriti.com/programs

### 2. Configure Platforms

```json
"platforms": {
  "hackerone": {
    "enabled": true,
    "api_token": "YOUR_TOKEN",
    "username": "your_username",
    "program_handle": "target-program"
  },
  "aios": {
    "enabled": true,
    "api_endpoint": "https://red-team-tools.aios.is",
    "api_key": "YOUR_AIOS_API_KEY"
  }
}
```

**Get API tokens:**
- HackerOne: Settings → API Tokens
- Bugcrowd: Settings → API Access
- AiOS: Your red-team-tools dashboard

### 3. Connect to ECH0 (Level 7 Intelligence)

```json
"ech0_endpoint": "https://your-ech0-instance.com/api",
"ech0_api_key": "YOUR_ECH0_KEY"
```

This gives your hunter **strategic intelligence** and **creative problem-solving**.

### 4. Set Your Goals

```json
"hunting_mode": "balanced",
"monthly_revenue_target": 5000,
"min_hourly_rate": 50
```

**Modes:**
- `fast_cash`: Quick wins, immediate revenue
- `balanced`: Optimal $/hour (recommended)
- `big_game`: High-value targets only
- `ip_gen`: Novel techniques for patents

---

## First Test Run

Before going autonomous, test the components:

### Test Scanner

```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
python3 bug_bounty_scanner.py https://example.com
```

Should output: "Found X potential vulnerabilities"

### Test Validator

```bash
python3 bug_bounty_validator.py
```

### Test Strategy Engine

```bash
python3 apex_strategy_engine.py
```

If all tests pass, you're ready to go autonomous.

---

## Monitoring

### View Live Logs

```bash
# Systemd (Pi/Linux)
journalctl -u apex-bug-bounty -f

# Or direct file
tail -f ~/apex-bug-bounty-hunter/logs/apex.log
```

### Check Results

```bash
ls -lh ~/apex-bug-bounty-hunter/bug_bounty_results/
cat ~/apex-bug-bounty-hunter/bug_bounty_results/*_report.json
```

### Monitor Performance

```bash
cat ~/apex-bug-bounty-hunter/bug_bounty_stats.json
```

---

## FAQ

### Q: Do I need a small LLM on the Pi?

**A: NO.** 

The hunting is deterministic Python code (fast, reliable). ECH0 provides the intelligence. Running a 2B model on the Pi would:
- Slow everything down
- Drain resources
- Hallucinate false positives
- Cost more power

**ECH0 (already trained on pen testing) + deterministic code = optimal**

### Q: How much will I make?

Depends on mode and time:
- **Fast Cash**: $500-5,000/month
- **Balanced**: $1,500-14,000/month  
- **Big Game**: $2,000-30,000/month
- **IP Gen**: Patents worth $10K-100K+

### Q: Is this legal?

**YES**, if you:
- Only hunt on bug bounty programs (they give permission)
- Stay within program scope
- Don't exploit, just report
- Follow responsible disclosure

### Q: What if it finds nothing?

The hunter is RELENTLESS:
- Tries multiple vectors per target
- Never gives up easily
- Learns from failures
- Adapts strategy dynamically
- Generates novel techniques when stuck

If a target is truly secure (rare), it pivots to new targets automatically.

### Q: How does it integrate with AiOS?

All findings feed to `red-team-tools.aios.is`:
- Centralized intelligence
- IP generation
- Tool coordination
- Sovereign infrastructure

### Q: What about ECH0?

ECH0 provides **Level 7 intelligence**:
- Strategic decision-making
- Report generation
- Novel technique creation
- Business optimization

The hunter is Level 5-6, becomes Level 7 with ECH0.

---

## Troubleshooting

### "No targets configured"

Edit `bug_bounty_config.json` and add targets from bug bounty platforms.

### "API token invalid"

Double-check tokens in config. Make sure they have correct permissions.

### "Import error: aiohttp"

```bash
cd ~/apex-bug-bounty-hunter
source venv/bin/activate
pip install aiohttp asyncio
```

### "Permission denied"

```bash
sudo systemctl restart apex-bug-bounty
sudo chmod +x ~/apex-bug-bounty-hunter/*.sh
```

### Service won't start

```bash
sudo systemctl status apex-bug-bounty
journalctl -u apex-bug-bounty -n 50
```

---

## Next Steps

1. ✅ **Install** (`./install.sh`)
2. ✅ **Configure** (edit `bug_bounty_config.json`)
3. ✅ **Test** (run components individually)
4. ✅ **Deploy** (start as service)
5. 📊 **Monitor** (watch logs)
6. 💰 **Collect** (wait for bounties)
7. 🔄 **Iterate** (let it learn and improve)

---

## Support

**Read the full docs:**
- `README.md` - Complete architecture and explanation
- `LEVEL_7_AGENT_FRAMEWORK.md` - Patent-ready agent framework

**Corporation of Light**
- Las Vegas, NV
- Sovereign AI Infrastructure
- AiOS + ECH0 + Bug Bounty Hunter = Complete Security Ecosystem

---

**"APEX Predator. Never Gives Up. Always Hunting."**

