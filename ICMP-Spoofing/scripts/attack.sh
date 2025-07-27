#!/bin/bash

# ICMP Spoofing Attack - Attack Script
# This script starts the ICMP spoofing attack and provides demonstration commands

set -e  # Exit on any error

echo "⚔️  Starting ICMP Spoofing Attack..."
echo "=================================="

# Function to check if container is running
container_running() {
    sudo docker ps --format "table {{.Names}}" | grep -q "^$1$"
}

# Verify prerequisites
echo "🔍 Verifying prerequisites..."

# Check if containers exist and are running
for container in victim2 attacker2 router2; do
    if ! container_running "$container"; then
        echo "❌ Container $container is not running"
        echo "   Please run './setup.sh' first to set up the environment"
        exit 1
    fi
done

# Check if attack script exists in attacker container
if ! sudo docker exec attacker2 test -f /root/spoof2.py; then
    echo "❌ Attack script not found in attacker2 container"
    echo "   Please run './setup.sh' first to copy the script"
    exit 1
fi

echo "✅ All prerequisites verified"

# Display current network status
echo ""
echo "📊 Current Network Status:"
echo "========================="
echo "📱 Victim2 (20.10.0.2):"
sudo docker exec victim2 ip route show | head -3

echo "🌐 Router2 (20.20.0.2):"
sudo docker exec router2 ip route show | head -3

echo "👹 Attacker2 (20.10.0.3 & 20.20.0.3):"
sudo docker exec attacker2 ip route show | head -3

echo ""
echo "🧪 Testing baseline connectivity (before attack)..."
echo "================================================="
echo "📡 Starting tcpdump on router2 to monitor ICMP traffic..."

# Start tcpdump in background to monitor router
echo "Starting router2 monitoring in background..."
sudo docker exec -d router2 tcpdump -n -i eth0 icmp

sleep 2

echo ""
echo "📱 Testing baseline ping from victim2 to router2..."
echo "Expected: Normal ping responses with router2 receiving packets"
sudo docker exec victim2 ping -c 3 20.20.0.2

echo ""
echo "⚔️  LAUNCHING ICMP SPOOFING ATTACK..."
echo "===================================="
echo ""
echo "🎯 The attack script will:"
echo "   1. Intercept ICMP Echo Requests from victim to router"
echo "   2. Drop the real packets using iptables"
echo "   3. Send spoofed ICMP Echo Replies back to victim"
echo "   4. Make victim think router is responding normally"
echo ""
echo "📡 Starting attack script on attacker2..."
echo "   Press Ctrl+C to stop the attack"
echo ""

# Trap Ctrl+C to provide clean exit instructions
trap 'echo ""; echo "🛑 Attack interrupted. Use ./cleanup.sh to clean environment."; exit 0' INT

# Start the attack in a way that allows user interaction
echo "Starting spoof2.py on attacker2..."
echo "Attack console output:"
echo "====================="

# Run attack script interactively
sudo docker exec -it attacker2 python3 /root/spoof2.py