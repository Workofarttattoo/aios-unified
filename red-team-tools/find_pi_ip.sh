#!/bin/bash
echo "Finding Raspberry Pi IP address..."
echo ""
echo "Checking common Pi hostnames..."
for host in raspberrypi.local raspberrypi pi.local; do
    if ping -c 1 -W 1 "$host" &>/dev/null; then
        echo "✓ Found: $host"
    fi
done
echo ""
echo "Checking local network..."
LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
if [ -n "$LOCAL_IP" ]; then
    NETWORK=$(echo $LOCAL_IP | cut -d'.' -f1-3)
    echo "Your network: $NETWORK.0/24"
    echo "Scanning for Pi (this may take a minute)..."
    for i in {1..50}; do
        TEST_IP="$NETWORK.$i"
        if ping -c 1 -W 1 "$TEST_IP" &>/dev/null 2>&1; then
            if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no pi@"$TEST_IP" "uname -a" &>/dev/null 2>&1; then
                echo "✓ Found Raspberry Pi at: $TEST_IP"
                echo "   Use: pi@$TEST_IP"
            fi
        fi
    done
fi
