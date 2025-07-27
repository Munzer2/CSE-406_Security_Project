#!/bin/bash

# ICMP Redirect Attack - Setup Script
# This script sets up the Docker environment for the ICMP redirect attack demonstration

set -e  # Exit on any error

echo "🚀 Starting ICMP Redirect Attack Setup..."
echo "=========================================="

# Function to check if container exists
container_exists() {
    sudo docker ps -a --format "table {{.Names}}" | grep -q "^$1$"
}

# Function to check if network exists
network_exists() {
    sudo docker network ls --format "table {{.Name}}" | grep -q "^$1$"
}

# Check if user wants to restart existing containers
if container_exists "victim" || container_exists "attacker" || container_exists "router" || container_exists "target"; then
    echo "⚠️  Existing containers detected!"
    echo "Do you want to:"
    echo "1) Clean up existing containers and create fresh ones"
    echo "2) Start existing stopped containers"
    echo "3) Exit and manually handle containers"
    read -p "Enter your choice (1/2/3): " choice
    
    case $choice in
        1)
            echo "🧹 Cleaning up existing containers..."
            sudo docker rm -f victim attacker router target 2>/dev/null || true
            ;;
        2)
            echo "▶️  Starting existing containers..."
            sudo docker start victim attacker router target 2>/dev/null || true
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
if ! network_exists "shared-net"; then
    sudo docker network create --driver=bridge --subnet=10.10.1.0/24 shared-net
    echo "✅ Created network: shared-net"
else
    echo "ℹ️  Network shared-net already exists"
fi

if ! network_exists "target-net"; then
    sudo docker network create --driver=bridge --subnet=10.10.2.0/24 target-net
    echo "✅ Created network: target-net"
else
    echo "ℹ️  Network target-net already exists"
fi

# Step 2: Launch Containers
echo "🐳 Step 2: Launching Docker Containers..."

# Victim Container
echo "  📱 Launching victim container..."
sudo docker run -d --name victim \
  --cap-add NET_ADMIN \
  --network shared-net --ip 10.10.1.10 \
  ubuntu:22.04 sleep infinity
echo "✅ victim container launched (10.10.1.10)"

# Router Container (dual-homed)
echo "  🌐 Launching router container..."
sudo docker run -d --name router \
  --cap-add NET_ADMIN \
  --sysctl net.ipv4.ip_forward=1 \
  --network shared-net --ip 10.10.1.1 \
  ubuntu:22.04 sleep infinity
sudo docker network connect --ip 10.10.2.1 target-net router
echo "✅ router container launched (10.10.1.1 & 10.10.2.1)"

# Target Container
echo "  🎯 Launching target container..."
sudo docker run -d --name target \
  --cap-add NET_ADMIN \
  --network target-net --ip 10.10.2.10 \
  ubuntu:22.04 sleep infinity
echo "✅ target container launched (10.10.2.10)"

# Attacker Container
echo "  👹 Launching attacker container..."
sudo docker run -d --name attacker \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  --network shared-net --ip 10.10.1.20 \
  ubuntu:22.04 sleep infinity
echo "✅ attacker container launched (10.10.1.20)"

# Step 3: Install Dependencies
echo "📦 Step 3: Installing Dependencies..."

echo "  📱 Installing dependencies on victim..."
sudo docker exec victim bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump"

echo "  🌐 Installing dependencies on router..."
sudo docker exec router bash -c "apt update && apt install -y iproute2 iputils-ping net-tools tcpdump iptables"

echo "  🎯 Installing dependencies on target..."
sudo docker exec target bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump"

echo "  👹 Installing dependencies on attacker..."
sudo docker exec attacker bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump iptables"

echo "✅ All dependencies installed"

# Step 4: Configure Routing
echo "🛣️  Step 4: Configuring Routing..."

# Enable IP forwarding on router
echo "  🌐 Enabling IP forwarding on router..."
sudo docker exec router bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

# Configure victim to accept ICMP redirects
echo "  📱 Configuring victim to accept ICMP redirects..."
sudo docker exec victim bash -c "echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects"
sudo docker exec victim bash -c "echo 1 > /proc/sys/net/ipv4/conf/eth0/accept_redirects"

# Add route on victim to target network via router
echo "  📱 Configuring victim routing (via router)..."
sudo docker exec victim bash -c "ip route add 10.10.2.0/24 via 10.10.1.1"

echo "✅ Routing configured"

# Step 5: Copy Attack Scripts
echo "📋 Step 5: Copying Attack Scripts..."

# Copy attack script to attacker
if [ -f "../src/icmp_redirect_attack.py" ]; then
    sudo docker cp ../src/icmp_redirect_attack.py attacker:/root/icmp_redirect_attack.py
    sudo docker exec attacker chmod +x /root/icmp_redirect_attack.py
    echo "✅ icmp_redirect_attack.py copied to attacker:/root/"
else
    echo "⚠️  Warning: icmp_redirect_attack.py not found in ../src/ directory"
fi

# Copy victim traffic script to victim
if [ -f "../src/victim_traffic.py" ]; then
    sudo docker cp ../src/victim_traffic.py victim:/root/victim_traffic.py
    sudo docker exec victim chmod +x /root/victim_traffic.py
    echo "✅ victim_traffic.py copied to victim:/root/"
else
    echo "⚠️  Warning: victim_traffic.py not found in ../src/ directory"
fi

# Copy target host script to target
if [ -f "../src/target_host.py" ]; then
    sudo docker cp ../src/target_host.py target:/root/target_host.py
    sudo docker exec target chmod +x /root/target_host.py
    echo "✅ target_host.py copied to target:/root/"
else
    echo "⚠️  Warning: target_host.py not found in ../src/ directory"
fi

# Step 6: Verify Setup
echo "🔍 Step 6: Verifying Setup..."

# Check if containers are running
echo "  📊 Container status:"
sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E 'victim|router|target|attacker'

# Test connectivity
echo "  🔄 Testing connectivity:"

echo -n "    victim → router: "
if sudo docker exec victim ping -c1 -W1 10.10.1.1 > /dev/null; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    router → target: "
if sudo docker exec router ping -c1 -W1 10.10.2.10 > /dev/null; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    victim → target: "
if sudo docker exec victim ping -c1 -W1 10.10.2.10 > /dev/null; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    attacker → victim: "
if sudo docker exec attacker ping -c1 -W1 10.10.1.10 > /dev/null; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

# Print summary
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo "✅ Networks created: shared-net (10.10.1.0/24), target-net (10.10.2.0/24)"
echo "✅ Containers running: victim, router, target, attacker"
echo "✅ Dependencies installed and routing configured"
echo "✅ Attack scripts copied to containers"
echo ""
echo "🚀 Next Steps:"
echo "   1. Start target host: sudo docker exec -it target python3 /root/target_host.py"
echo "   2. Start victim traffic: sudo docker exec -it victim python3 /root/victim_traffic.py"
echo "   3. Launch attack: sudo docker exec -it attacker python3 /root/icmp_redirect_attack.py"
echo "   4. Monitor with: sudo docker exec victim ip route (to see routing table changes)"
echo ""
echo "🧹 Cleanup: Run './cleanup.sh' when finished"
