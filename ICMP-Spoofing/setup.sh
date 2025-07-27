#!/bin/bash

# ICMP Spoofing Attack - Setup Script
# This script automates the complete setup process for the ICMP spoofing demonstration

set -e  # Exit on any error

echo "🚀 Starting ICMP Spoofing Attack Setup..."
echo "========================================"

# Function to check if container exists
container_exists() {
    sudo docker ps -a --format "table {{.Names}}" | grep -q "^$1$"
}

# Function to check if network exists
network_exists() {
    sudo docker network ls --format "table {{.Name}}" | grep -q "^$1$"
}

# Check if user wants to restart existing containers
if container_exists "victim2" || container_exists "attacker2" || container_exists "router2"; then
    echo "⚠️  Existing containers detected!"
    echo "Do you want to:"
    echo "1) Clean up existing containers and create fresh ones"
    echo "2) Start existing stopped containers"
    echo "3) Exit and manually handle containers"
    read -p "Enter your choice (1/2/3): " choice
    
    case $choice in
        1)
            echo "🧹 Cleaning up existing containers..."
            sudo docker rm -f victim2 attacker2 router2 2>/dev/null || true
            ;;
        2)
            echo "▶️  Starting existing containers..."
            sudo docker start victim2 attacker2 router2 2>/dev/null || true
            echo "✅ Existing containers started. Setup complete!"
            exit 0
            ;;
        3)
            echo "👋 Exiting. Please handle containers manually."
            exit 0
            ;;
        *)
            echo "❌ Invalid choice. Exiting."
            exit 1
            ;;
    esac
fi

# Step 1: Create Docker Networks
echo "📡 Step 1: Creating Docker Networks..."
if ! network_exists "net_vict_att"; then
    sudo docker network create --driver=bridge --subnet=20.10.0.0/24 net_vict_att
    echo "✅ Created network: net_vict_att"
else
    echo "ℹ️  Network net_vict_att already exists"
fi

if ! network_exists "net_att_rout"; then
    sudo docker network create --driver=bridge --subnet=20.20.0.0/24 net_att_rout
    echo "✅ Created network: net_att_rout"
else
    echo "ℹ️  Network net_att_rout already exists"
fi

# Step 2: Launch Containers
echo "🐳 Step 2: Launching Docker Containers..."

# Victim Container
echo "  📱 Launching victim2 container..."
sudo docker run -d --name victim2 \
  --cap-add NET_ADMIN \
  --network net_vict_att --ip 20.10.0.2 \
  ubuntu:22.04 sleep infinity
echo "✅ victim2 container launched (20.10.0.2)"

# Router Container
echo "  🌐 Launching router2 container..."
sudo docker run -d --name router2 \
  --cap-add NET_ADMIN \
  --network net_att_rout --ip 20.20.0.2 \
  ubuntu:22.04 sleep infinity
echo "✅ router2 container launched (20.20.0.2)"

# Attacker Container (dual-homed)
echo "  👹 Launching attacker2 container..."
sudo docker run -d --name attacker2 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --network net_vict_att --ip 20.10.0.3 \
  ubuntu:22.04 sleep infinity
sudo docker network connect --ip 20.20.0.3 net_att_rout attacker2
echo "✅ attacker2 container launched (20.10.0.3 & 20.20.0.3)"

# Step 3: Install Dependencies
echo "📦 Step 3: Installing Dependencies..."

echo "  📱 Installing dependencies on victim2..."
sudo docker exec victim2 bash -lc "apt update && apt install -y iproute2 iputils-ping"

echo "  🌐 Installing dependencies on router2..."
sudo docker exec router2 bash -lc "apt update && apt install -y iproute2 iputils-ping tcpdump"

echo "  👹 Installing dependencies on attacker2..."
sudo docker exec attacker2 bash -lc "apt update && apt install -y iproute2 iptables python3-pip libpcap-dev tcpdump && pip3 install scapy"

echo "✅ All dependencies installed"

# Step 4: Configure Routing
echo "🛣️  Step 4: Configuring Routing..."

echo "  📱 Configuring victim2 routing (gateway: attacker2)..."
sudo docker exec victim2 bash -lc "ip route del default && ip route add default via 20.10.0.3 dev eth0"

echo "  🌐 Configuring router2 routing (gateway: attacker2)..."
sudo docker exec router2 bash -lc "ip route del default && ip route add default via 20.20.0.3 dev eth0"

echo "✅ Routing configured"

# Step 5: Enable IP Forwarding
echo "🔄 Step 5: Enabling IP Forwarding on attacker2..."
sudo docker exec attacker2 bash -lc "sysctl -w net.ipv4.ip_forward=1"
echo "✅ IP forwarding enabled"

# Step 6: Copy Attack Script
echo "📋 Step 6: Copying Attack Script..."
if [ -f "spoof2.py" ]; then
    sudo docker cp spoof2.py attacker2:/root/spoof2.py
    sudo docker exec attacker2 chmod +x /root/spoof2.py
    echo "✅ spoof2.py copied to attacker2:/root/"
else
    echo "⚠️  Warning: spoof2.py not found in current directory"
    echo "   Please ensure spoof2.py exists before running the attack"
fi

# Verification
echo "🔍 Step 7: Verifying Setup..."
echo "  📱 Victim2 IP configuration:"
sudo docker exec victim2 ip addr show eth0 | grep inet

echo "  🌐 Router2 IP configuration:"
sudo docker exec router2 ip addr show eth0 | grep inet

echo "  👹 Attacker2 IP configuration:"
sudo docker exec attacker2 ip addr show | grep inet

echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo "✅ Networks created: net_vict_att (20.10.0.0/24), net_att_rout (20.20.0.0/24)"
echo "✅ Containers running: victim2, attacker2, router2"
echo "✅ Dependencies installed and routing configured"
echo "✅ IP forwarding enabled on attacker2"
echo "✅ Attack script ready"
echo ""
echo "🚀 Next Steps:"
echo "   1. Run './attack.sh' to start the ICMP spoofing attack"
echo "   2. Or manually execute: sudo docker exec attacker2 python3 /root/spoof2.py"
echo "   3. Test with: sudo docker exec victim2 ping -c4 20.20.0.2"
echo "   4. Monitor with: sudo docker exec router2 tcpdump -n icmp"
echo ""
echo "🧹 Cleanup: Run './cleanup.sh' when finished"