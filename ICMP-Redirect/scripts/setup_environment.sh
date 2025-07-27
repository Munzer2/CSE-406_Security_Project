#!/bin/bash
# Docker Setup Script for ICMP Redirect Attack Demonstration
# CRITICAL: Network configured for packet sniffing and race conditions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================"
echo -e "ICMP Redirect Attack - REACTIVE DESIGN"
echo -e "======================================================${NC}"
echo -e "Network Design:"
echo -e "- Victim sends packets to Router (via longer path)"
echo -e "- Attacker sniffs packets on shared network segment"
echo -e "- Attacker sends ICMP redirects REACTIVELY"
echo -e "- Race condition: Attacker vs Router response"
echo -e "======================================================${NC}"

# Function to print status messages
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

# 1. Clean up existing containers and networks
print_status "Cleaning up existing containers and networks..."
docker stop victim router target attacker intermediate-router 2>/dev/null || true
docker rm victim router target attacker intermediate-router 2>/dev/null || true
docker network rm icmp-redirect-net target-net 2>/dev/null || true

# 2. Create Docker networks - CRITICAL FOR SNIFFING
print_status "Creating Docker networks for packet sniffing..."

# Main shared network - ALL containers connected (enables sniffing)
# This acts like a HUB/shared segment where attacker can sniff victim traffic
docker network create \
  --driver=bridge \
  --subnet=10.10.1.0/24 \
  --gateway=10.10.1.254 \
  --opt com.docker.network.bridge.enable_ip_masquerade=false \
  --opt com.docker.network.bridge.enable_icc=true \
  icmp-redirect-net

# Target network - isolated from main network 
docker network create \
  --driver=bridge \
  --subnet=10.10.2.0/24 \
  --gateway=10.10.2.254 \
  target-net

if [ $? -eq 0 ]; then
    print_status "Network created successfully"
else
    print_error "Failed to create network"
    exit 1
fi

# 3. Start containers - DESIGNED FOR RACE CONDITIONS AND SNIFFING
print_status "Starting containers with sniffing-enabled topology..."

# START CONTAINERS WITH DEFAULT BRIDGE FIRST FOR INTERNET ACCESS
print_status "Starting containers with default bridge for package installation..."

# Victim - start with default bridge first
print_status "Starting Victim container..."
docker run -dit \
  --name victim \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --privileged \
  ubuntu:22.04 bash

# Attacker - start with default bridge first
print_status "Starting Attacker container..."
docker run -dit \
  --name attacker \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --privileged \
  ubuntu:22.04 bash

# Router - start with default bridge first
print_status "Starting Router container..."
docker run -dit \
  --name router \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --privileged \
  ubuntu:22.04 bash

# Intermediate router - start with default bridge first
print_status "Starting Intermediate Router container..."
docker run -dit \
  --name intermediate-router \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --privileged \
  ubuntu:22.04 bash

# Target - start with default bridge first
print_status "Starting Target container..."
docker run -dit \
  --name target \
  --cap-add=NET_RAW \
  ubuntu:22.04 bash

# Wait for containers to start
sleep 3

# 4. Install dependencies - INCLUDE PACKET CAPTURE TOOLS
print_status "Installing dependencies with packet capture capabilities..."

print_status "Installing dependencies in Victim..."
docker exec victim bash -c "
apt update -qq && 
apt install -y python3 iproute2 iputils-ping net-tools tcpdump
"

print_status "Installing dependencies in Attacker..."
docker exec attacker bash -c "
apt update -qq && 
apt install -y python3 iproute2 iputils-ping net-tools tcpdump iptables
"

print_status "Installing dependencies in Routers..."
docker exec router bash -c "
apt update -qq && 
apt install -y iproute2 iputils-ping iptables tcpdump net-tools iproute2-tc &&
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
"

docker exec intermediate-router bash -c "
apt update -qq && 
apt install -y iproute2 iputils-ping iptables tcpdump net-tools iproute2-tc &&
# Enable IP forwarding  
echo 1 > /proc/sys/net/ipv4/ip_forward
"

print_status "Installing dependencies in Target..."
docker exec target bash -c "
apt update -qq && 
apt install -y python3 iproute2 iputils-ping net-tools
"

# 5. RECONFIGURE NETWORKS - DISCONNECT FROM DEFAULT, CONNECT TO CUSTOM
print_status "Reconfiguring containers to custom networks for sniffing..."

# Disconnect all containers from default bridge
print_status "Disconnecting from default bridge..."
docker network disconnect bridge victim
docker network disconnect bridge attacker
docker network disconnect bridge router
docker network disconnect bridge intermediate-router
docker network disconnect bridge target

# Connect to custom networks with proper IPs
print_status "Connecting Victim to shared network (10.10.1.10)..."
docker network connect --ip 10.10.1.10 icmp-redirect-net victim

print_status "Connecting Attacker to shared network (10.10.1.20)..."
docker network connect --ip 10.10.1.20 icmp-redirect-net attacker

print_status "Connecting Router to both networks (10.10.1.1 <-> 10.10.2.1)..."
docker network connect --ip 10.10.1.1 icmp-redirect-net router
docker network connect --ip 10.10.2.1 target-net router

print_status "Connecting Intermediate Router to target network (10.10.2.5)..."
docker network connect --ip 10.10.2.5 target-net intermediate-router

print_status "Connecting Target to target network (10.10.2.10)..."
docker network connect --ip 10.10.2.10 target-net target

# Wait for network changes to propagate
sleep 2

# 5. Copy attack scripts to containers
print_status "Copying attack scripts to containers..."

# Copy util.py to all containers that need it
docker cp src/util.py victim:/root/util.py
docker cp src/util.py attacker:/root/util.py
docker cp src/util.py target:/root/util.py

# Copy victim script
if [ -f "src/victim.py" ]; then
    docker cp src/victim.py victim:/root/victim.py
    docker exec victim chmod +x /root/victim.py
fi

# Copy reactive attacker script
docker cp src/reactive_attacker.py attacker:/root/reactive_attacker.py
docker exec attacker chmod +x /root/reactive_attacker.py

# Copy target script (if exists)
if [ -f "src/target.py" ]; then
    docker cp src/target.py target:/root/target.py
    docker exec target chmod +x /root/target.py
fi

# 6. Configure routing and network settings 
print_status "Configuring network routing for attack scenario..."

# Configure victim routing - route to target via router
docker exec victim bash -c "
# Enable ICMP redirects acceptance (critical for attack)
echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 1 > /proc/sys/net/ipv4/conf/eth0/accept_redirects
# Add route to target network via router
ip route add 10.10.2.0/24 via 10.10.1.1
"

# Configure router routing - direct path to target (simpler)
docker exec router bash -c "
# Direct route to target (no intermediate router for now)
# ip route add 10.10.2.10/32 via 10.10.2.5
echo 'Router routing configured for direct access'
"

# Configure intermediate router (optional delay)
docker exec intermediate-router bash -c "
# Optional: This can add delay later
echo 'Intermediate router available for delay'
"

# Disable ICMP redirects in attacker (prevent loops)
docker exec attacker bash -c "
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects
"

# 7. Test basic connectivity and sniffing capability
print_status "Testing connectivity and sniffing capability..."

echo -n "  Victim -> Router: "
if docker exec victim ping -c1 -W2 10.10.1.1 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Router -> Target: "
if docker exec router ping -c1 -W2 10.10.2.10 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Victim -> Target (via router): "
if docker exec victim ping -c1 -W3 10.10.2.10 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Attacker can sniff victim network: "
if docker exec attacker ping -c1 -W2 10.10.1.10 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

print_status "Environment setup complete!"

echo -e "\n${BLUE}======================================================"
echo -e "Container Information:"
echo -e "======================================================${NC}"
echo -e "Shared Network (10.10.1.0/24) - Sniffing enabled:"
echo -e "  Victim:   10.10.1.10 (Target of attack)"
echo -e "  Router:   10.10.1.1  (Legitimate gateway)"  
echo -e "  Attacker: 10.10.1.20 (Can sniff victim traffic)"
echo -e ""
echo -e "Target Network (10.10.2.0/24) - Isolated:"
echo -e "  Router:         10.10.2.1 (Gateway to targets)"
echo -e "  Intermediate:   10.10.2.5 (Adds delay/hops)"
echo -e "  Target:         10.10.2.10 (Final destination)"

echo -e "\n${BLUE}Attack Flow:${NC}"
echo -e "1. Victim sends packets to Target (10.10.2.10)"
echo -e "2. Attacker sniffs victim traffic on shared network"
echo -e "3. Attacker races to send ICMP redirect before router responds"
echo -e "4. Victim's routing table is poisoned to use attacker as gateway"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "1. Start target:         ${YELLOW}docker exec -it target python3 /root/target.py${NC}"
echo -e "2. Start victim traffic: ${YELLOW}docker exec -it victim python3 /root/victim.py${NC}"
echo -e "3. Launch attack:        ${YELLOW}docker exec -it attacker python3 /root/reactive_attacker.py${NC}"

echo -e "\n${BLUE}Monitoring Commands:${NC}"
echo -e "Check victim routes:     ${YELLOW}docker exec victim ip route${NC}"
echo -e "Sniff victim traffic:    ${YELLOW}docker exec attacker tcpdump -i eth0 host 10.10.1.10${NC}"
echo -e "Monitor ICMP redirects:  ${YELLOW}docker exec victim tcpdump -i eth0 icmp[icmptype]==icmp-redirect${NC}"

print_warning "Remember: Attacker is NOT on path initially, but CAN sniff packets!"
