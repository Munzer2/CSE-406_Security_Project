#!/bin/bash

# ICMP Redirect Attack - Setup Script (Based on Docker Compose Structure)
# This script sets up the Docker environment for the ICMP redirect attack demonstration
# Following the topology from the reference docker-compose.yml

set -e  # Exit on any error

echo "🚀 Starting ICMP Redirect Attack Setup..."
echo "=========================================="
echo "Based on Docker Compose topology with dual networks"
echo ""

# ═══════════════════════════════════════════════════════════════════════════════════
# NETWORK TOPOLOGY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════════
# Network 1: internal-net (10.9.0.0/24) - Contains victim, attacker, malicious-router
# Network 2: target-net (192.168.60.0/24) - Contains target hosts  
# Router: Dual-homed (10.9.0.11 & 192.168.60.11) - Connects both networks
#
# IP Assignments:
# - Victim: 10.9.0.5 (accepts ICMP redirects)
# - Attacker: 10.9.0.105 (launches ICMP redirect attack)
# - Malicious Router: 10.9.0.111 (alternative attacker position)
# - Router: 10.9.0.11 & 192.168.60.11 (legitimate router)
# - Target Host 1: 192.168.60.5
# - Target Host 2: 192.168.60.6
# ═══════════════════════════════════════════════════════════════════════════════════

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
            sudo docker rm -f victim attacker router target target2 malicious-router 2>/dev/null || true
            ;;
        2)
            echo "▶️  Starting existing containers..."
            sudo docker start victim attacker router target target2 malicious-router 2>/dev/null || true
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

# Step 1: Create Docker Networks (Following Docker Compose structure)
echo "📡 Step 1: Creating Docker Networks..."

# Clean up networks first to avoid address conflicts
echo "  🧹 Cleaning up existing networks..."
if network_exists "internal-net"; then
    sudo docker network rm internal-net || true
    echo "  ✅ Removed network: internal-net"
fi

if network_exists "target-net"; then
    sudo docker network rm target-net || true
    echo "  ✅ Removed network: target-net"
fi

# Wait a moment for network interfaces to be released
sleep 2

# Create networks (matching docker-compose structure)
echo "  🌐 Creating fresh networks..."
sudo docker network create --driver=bridge --subnet=10.9.0.0/24 internal-net
echo "  ✅ Created network: internal-net (10.9.0.0/24)"

sudo docker network create --driver=bridge --subnet=192.168.60.0/24 target-net
echo "  ✅ Created network: target-net (192.168.60.0/24)"

# Step 2: Check for required Ubuntu image
echo "🐳 Step 2: Checking Docker Images..."
if ! sudo docker images | grep -q "ubuntu.*22.04"; then
    echo "⬇️  Downloading Ubuntu 22.04 image..."
    sudo docker pull ubuntu:22.04
    echo "✅ Ubuntu 22.04 image ready"
else
    echo "✅ Ubuntu 22.04 image already available"
fi

# Step 3: Launch Containers (Following Docker Compose structure)
echo "🐳 Step 3: Launching Docker Containers..."

# Victim Container (10.9.0.5) - Accepts ICMP redirects
echo "  📱 Launching victim container..."
sudo docker run -d --name victim \
  --cap-add ALL \
  --privileged \
  --sysctl net.ipv4.conf.all.accept_redirects=1 \
  --network internal-net --ip 10.9.0.5 \
  ubuntu:22.04 sleep infinity
echo "✅ victim container launched (10.9.0.5)"

# Attacker Container (10.9.0.105) - ICMP Redirect Attacker  
echo "  👹 Launching attacker container..."
sudo docker run -d --name attacker \
  --cap-add ALL \
  --privileged \
  --network internal-net --ip 10.9.0.105 \
  ubuntu:22.04 sleep infinity
echo "✅ attacker container launched (10.9.0.105)"

# Malicious Router Container (10.9.0.111) - Alternative attacker position
echo "  🕷️  Launching malicious-router container..."
sudo docker run -d --name malicious-router \
  --cap-add ALL \
  --privileged \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.send_redirects=0 \
  --sysctl net.ipv4.conf.default.send_redirects=0 \
  --network internal-net --ip 10.9.0.111 \
  ubuntu:22.04 sleep infinity
echo "✅ malicious-router container launched (10.9.0.111)"

# Router Container (dual-homed: 10.9.0.11 & 192.168.60.11)
echo "  🌐 Launching router container..."
if ! sudo docker run -d --name router \
  --cap-add ALL \
  --privileged \
  --sysctl net.ipv4.ip_forward=1 \
  --network internal-net --ip 10.9.0.11 \
  ubuntu:22.04 sleep infinity; then
    
    echo "❌ Failed to launch router container. Attempting recovery..."
    
    # Clean up and retry
    sudo docker rm -f router 2>/dev/null || true
    sudo docker network disconnect internal-net router 2>/dev/null || true
    sleep 2
    
    # Try again with a different approach
    if ! sudo docker run -d --name router \
      --cap-add ALL \
      --privileged \
      --sysctl net.ipv4.ip_forward=1 \
      ubuntu:22.04 sleep infinity; then
        echo "❌ Router container launch failed again. Aborting."
        echo "🧹 Cleaning up..."
        sudo docker rm -f victim attacker malicious-router 2>/dev/null || true
        sudo docker network rm internal-net target-net 2>/dev/null || true
        exit 1
    else
        # Connect to networks now that container exists
        sudo docker network connect internal-net --ip 10.9.0.11 router
        echo "✅ router container launched and connected to internal-net (10.9.0.11)"
    fi
fi

# Connect router to target network (making it dual-homed)
echo "  🔗 Connecting router to target network..."
if ! sudo docker network connect --ip 192.168.60.11 target-net router; then
    echo "❌ Failed to connect router to target-net. Attempting recovery..."
    
    # Disconnect if already partially connected
    sudo docker network disconnect target-net router 2>/dev/null || true
    sleep 2
    
    # Try again
    if ! sudo docker network connect --ip 192.168.60.11 target-net router; then
        echo "❌ Router network connection failed again. Aborting."
        echo "🧹 Cleaning up..."
        sudo docker rm -f victim attacker malicious-router router 2>/dev/null || true
        sudo docker network rm internal-net target-net 2>/dev/null || true
        exit 1
    fi
fi
echo "✅ router connected to both networks (10.9.0.11 & 192.168.60.11)"

# Target Host 1 Container (192.168.60.5)
echo "  🎯 Launching target host 1 container..."
sudo docker run -d --name target \
  --cap-add ALL \
  --privileged \
  --network target-net --ip 192.168.60.5 \
  ubuntu:22.04 sleep infinity
echo "✅ target container launched (192.168.60.5)"

# Target Host 2 Container (192.168.60.6) - Optional additional target
echo "  🎯 Launching target host 2 container..."
sudo docker run -d --name target2 \
  --cap-add ALL \
  --privileged \
  --network target-net --ip 192.168.60.6 \
  ubuntu:22.04 sleep infinity
echo "✅ target2 container launched (192.168.60.6)"

# Step 4: Install Dependencies
echo "📦 Step 4: Installing Dependencies..."

echo "  📱 Installing dependencies on victim..."
sudo docker exec victim bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump"

echo "  🌐 Installing dependencies on router..."
sudo docker exec router bash -c "apt update && apt install -y iproute2 iputils-ping net-tools tcpdump iptables"

echo "  🎯 Installing dependencies on target..."
sudo docker exec target bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump"

echo "  🎯 Installing dependencies on target2..."
sudo docker exec target2 bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump"

echo "  👹 Installing dependencies on attacker..."
sudo docker exec attacker bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump iptables"

echo "  🕷️  Installing dependencies on malicious-router..."
sudo docker exec malicious-router bash -c "apt update && apt install -y python3 iproute2 iputils-ping net-tools tcpdump iptables"

echo "✅ All dependencies installed"

# Step 5: Configure Routing and Networking (Following Docker Compose logic)
echo "🛣️  Step 5: Configuring Routing and Networking..."

# Configure router routing
echo "  🌐 Configuring router routing..."
sudo docker exec router bash -c "
  sysctl -w net.ipv4.ip_forward=1 &&
  ip route del default 2>/dev/null || true &&
  ip route add default via 10.9.0.1 2>/dev/null || true
"

# Ensure victim accepts ICMP redirects (critical for attack)
echo "  📱 Configuring victim to accept ICMP redirects..."
sudo docker exec victim bash -c "
  sysctl -w net.ipv4.conf.all.accept_redirects=1 &&
  sysctl -w net.ipv4.conf.default.accept_redirects=1 &&
  sysctl -w net.ipv4.conf.eth0.accept_redirects=1
"

# Configure attacker for packet forwarding
echo "  👹 Configuring attacker for packet forwarding..."
sudo docker exec attacker bash -c "
  sysctl -w net.ipv4.ip_forward=1 &&
  ip route add 192.168.60.0/24 via 10.9.0.11 2>/dev/null || true
"

# Configure malicious router
echo "  🕷️  Configuring malicious router..."
sudo docker exec malicious-router bash -c "
  sysctl -w net.ipv4.ip_forward=1 &&
  sysctl -w net.ipv4.conf.all.send_redirects=0 &&
  sysctl -w net.ipv4.conf.default.send_redirects=0 &&
  ip route add 192.168.60.0/24 via 10.9.0.11 2>/dev/null || true
"

# Configure victim routing
echo "  📱 Adding victim route to target network..."
sudo docker exec victim bash -c "
  ip route add 192.168.60.0/24 via 10.9.0.11 2>/dev/null || true
"

# Configure target hosts routing
echo "  🎯 Configuring target hosts routing..."
sudo docker exec target bash -c "
  ip route del default 2>/dev/null || true &&
  ip route add 10.9.0.0/24 via 192.168.60.11 2>/dev/null || true
"

sudo docker exec target2 bash -c "
  ip route del default 2>/dev/null || true &&
  ip route add 10.9.0.0/24 via 192.168.60.11 2>/dev/null || true
"

echo "✅ Routing configured"

# Step 6: Copy Attack Scripts
echo "📋 Step 6: Copying Attack Scripts..."

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
    
    # Also copy to target2
    sudo docker cp ../src/target_host.py target2:/root/target_host.py
    sudo docker exec target2 chmod +x /root/target_host.py
    echo "✅ target_host.py copied to target2:/root/"
else
    echo "⚠️  Warning: target_host.py not found in ../src/ directory"
fi

# Copy scripts to malicious router as well
if [ -f "../src/icmp_redirect_attack.py" ]; then
    sudo docker cp ../src/icmp_redirect_attack.py malicious-router:/root/icmp_redirect_attack.py
    sudo docker exec malicious-router chmod +x /root/icmp_redirect_attack.py
    echo "✅ icmp_redirect_attack.py copied to malicious-router:/root/"
fi

# Step 7: Verify Setup
echo "🔍 Step 7: Verifying Setup..."

# Check if containers are running
echo "  📊 Container status:"
sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E 'victim|router|target|target2|attacker|malicious-router'

# Test connectivity
echo "  🔄 Testing connectivity:"

echo -n "    victim → router: "
if sudo docker exec victim ping -c1 -W1 10.9.0.11 > /dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    router → target: "
if sudo docker exec router ping -c1 -W1 192.168.60.5 > /dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    victim → target: "
if sudo docker exec victim ping -c1 -W1 192.168.60.5 > /dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    attacker → victim: "
if sudo docker exec attacker ping -c1 -W1 10.9.0.5 > /dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

echo -n "    attacker → target: "
if sudo docker exec attacker ping -c1 -W1 192.168.60.5 > /dev/null 2>&1; then
    echo "✅ Success"
else
    echo "❌ Failed"
fi

# Display routing tables
echo ""
echo "  📋 Current Routing Tables:"
echo "    Victim routing table:"
sudo docker exec victim ip route | sed 's/^/      /'
echo "    Attacker routing table:"
sudo docker exec attacker ip route | sed 's/^/      /'

# Print summary
echo ""
echo "🎉 Setup Complete!"
echo "=================="
echo "✅ Networks created: internal-net (10.9.0.0/24), target-net (192.168.60.0/24)"
echo "✅ Containers running:"
echo "   📱 victim (10.9.0.5) - ICMP redirects enabled"
echo "   👹 attacker (10.9.0.105) - Can launch ICMP redirect attack"
echo "   🕷️  malicious-router (10.9.0.111) - Alternative attack position"
echo "   🌐 router (10.9.0.11 & 192.168.60.11) - Dual-homed legitimate router"
echo "   🎯 target (192.168.60.5) - Primary target host"
echo "   🎯 target2 (192.168.60.6) - Secondary target host"
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
