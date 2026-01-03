# Transfer APEX Bug Bounty Hunter to Raspberry Pi

## Quick Transfer Methods

### Method 1: Find Pi IP and Use SCP (Recommended)

**Step 1: Find your Pi's IP address**

On your Raspberry Pi, run:
```bash
hostname -I
```

Or check your Mac's network settings to see connected devices.

**Step 2: Transfer files**

Once you have the Pi's IP (e.g., 192.168.1.100), run:

```bash
cd /Users/noone/aios/red-team-tools

# Transfer all files
scp bug_bounty_*.py pi@[PI_IP]:~/apex-hunter/
scp apex_strategy_engine.py pi@[PI_IP]:~/apex-hunter/
scp partnership_dashboard.py pi@[PI_IP]:~/apex-hunter/
scp install.sh pi@[PI_IP]:~/apex-hunter/
scp bug_bounty_config.json pi@[PI_IP]:~/apex-hunter/
```

**Replace [PI_IP] with your actual Pi IP address**

### Method 2: Use the Package File

**Step 1: Transfer the package**

```bash
cd /Users/noone/aios/red-team-tools
scp apex-bug-bounty-hunter.tar.gz pi@[PI_IP]:~/
```

**Step 2: On Pi, extract and install**

```bash
cd ~
tar -xzf apex-bug-bounty-hunter.tar.gz -C apex-hunter/
cd apex-hunter
chmod +x install.sh
./install.sh
```

### Method 3: USB/Network Share

**If SSH doesn't work:**

1. Copy files to USB drive
2. Plug into Pi
3. Copy from USB to Pi's home directory
4. Run installer

### Method 4: Find Pi IP Automatically

**Run this on your Mac:**

```bash
cd /Users/noone/aios/red-team-tools

# Get your Mac's IP
YOUR_IP=$(ipconfig getifaddr en0 || ipconfig getifaddr en1)
NETWORK=$(echo $YOUR_IP | cut -d'.' -f1-3)

echo "Scanning $NETWORK.0/24 for Raspberry Pi..."
echo "This will take a minute..."
echo ""

for i in {1..254}; do
    IP="$NETWORK.$i"
    if ping -c 1 -W 1 "$IP" &>/dev/null; then
        if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no pi@"$IP" "echo 'Pi found'" &>/dev/null 2>&1; then
            echo "✓ Found Raspberry Pi at: $IP"
            echo ""
            echo "Transfer files with:"
            echo "  scp bug_bounty_*.py apex_strategy_engine.py partnership_dashboard.py install.sh bug_bounty_config.json pi@$IP:~/apex-hunter/"
            break
        fi
    fi
done
```

---

## Complete Transfer Script

**Create this script and run it:**

```bash
#!/bin/bash

# Get Pi IP from user
read -p "Enter Raspberry Pi IP address (e.g., 192.168.1.100): " PI_IP

if [ -z "$PI_IP" ]; then
    echo "Error: No IP provided"
    exit 1
fi

PI_USER="pi@$PI_IP"
PROJECT_DIR="/Users/noone/aios/red-team-tools"

cd "$PROJECT_DIR"

echo "Uploading to $PI_USER..."

# Create directory
ssh "$PI_USER" "mkdir -p ~/apex-hunter"

# Upload files
scp bug_bounty_daemon.py "$PI_USER:~/apex-hunter/"
scp bug_bounty_scanner.py "$PI_USER:~/apex-hunter/"
scp bug_bounty_validator.py "$PI_USER:~/apex-hunter/"
scp bug_bounty_reporter.py "$PI_USER:~/apex-hunter/"
scp bug_bounty_submitter.py "$PI_USER:~/apex-hunter/"
scp apex_strategy_engine.py "$PI_USER:~/apex-hunter/"
scp partnership_dashboard.py "$PI_USER:~/apex-hunter/"
scp install.sh "$PI_USER:~/apex-hunter/"
scp bug_bounty_config.json "$PI_USER:~/apex-hunter/"

# Make executable
ssh "$PI_USER" "chmod +x ~/apex-hunter/install.sh"

echo "✓ Upload complete!"
echo ""
echo "Next: SSH to Pi and run ./install.sh"
```

---

## Files to Transfer

**Core Python files:**
- bug_bounty_daemon.py
- bug_bounty_scanner.py
- bug_bounty_validator.py
- bug_bounty_reporter.py
- bug_bounty_submitter.py
- apex_strategy_engine.py
- partnership_dashboard.py

**Config and scripts:**
- install.sh
- bug_bounty_config.json

**Documentation (optional):**
- INSTALL_AND_RUN.md
- HOW_TO_POST_REPORTS.md
- PARTNERSHIP_AGREEMENT.md

---

## After Transfer

**On Raspberry Pi:**

```bash
cd ~/apex-hunter
chmod +x install.sh
./install.sh

# Configure
nano ~/apex-bug-bounty-hunter/bug_bounty_config.json

# Start
sudo systemctl start apex-bug-bounty
sudo systemctl enable apex-bug-bounty

# Monitor
journalctl -u apex-bug-bounty -f
```

---

## Troubleshooting

### "Connection refused"

- Check Pi is powered on
- Check SSH is enabled: `sudo systemctl enable ssh`
- Check firewall settings
- Try: `ssh pi@[PI_IP]` manually first

### "Permission denied"

- Default Pi username is usually `pi`
- Default password is usually `raspberry`
- Or use your configured username

### "Host key verification failed"

```bash
ssh-keygen -R [PI_IP]
ssh-keyscan -H [PI_IP] >> ~/.ssh/known_hosts
```

---

## Quick One-Liner Transfer

**If you know the Pi IP (replace 192.168.1.100):**

```bash
cd /Users/noone/aios/red-team-tools && \
scp bug_bounty_*.py apex_strategy_engine.py partnership_dashboard.py install.sh bug_bounty_config.json pi@192.168.1.100:~/apex-hunter/ && \
ssh pi@192.168.1.100 "cd ~/apex-hunter && chmod +x install.sh && echo 'Files ready! Run ./install.sh'"
```


