#!/bin/bash
"""
Docker Setup Script for ICMP Redirect Attack Demonstration
This script sets up the complete Docker environment for the attack demo.
"""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================"
echo -e "ICMP Redirect Attack - Docker Environment Setup"
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
docker stop victim router target attacker 2>/dev/null || true
docker rm victim router target attacker 2>/dev/null || true
docker network rm icmp-redirect-net 2>/dev/null || true

# 2. Create Docker network
print_status "Creating Docker network 'icmp-redirect-net'..."
docker network create \
  --driver=bridge \
  --subnet=10.0.0.0/24 \
  --gateway=10.0.0.254 \
  icmp-redirect-net

if [ $? -eq 0 ]; then
    print_status "Network created successfully"
else
    print_error "Failed to create network"
    exit 1
fi

# 3. Start Router container
print_status "Starting Router container (10.0.0.1)..."
docker run -dit \
  --name router \
  --network icmp-redirect-net --ip 10.0.0.1 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  ubuntu:22.04 bash

# 4. Start Victim container
print_status "Starting Victim container (10.0.0.2)..."
docker run -dit \
  --name victim \
  --network icmp-redirect-net --ip 10.0.0.2 \
  --cap-add=NET_RAW \
  ubuntu:22.04 bash

# 5. Start Attacker container
print_status "Starting Attacker container (10.0.0.3)..."
docker run -dit \
  --name attacker \
  --network icmp-redirect-net --ip 10.0.0.3 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  ubuntu:22.04 bash

# 6. Start Target container
print_status "Starting Target container (10.0.0.4)..."
docker run -dit \
  --name target \
  --network icmp-redirect-net --ip 10.0.0.4 \
  --cap-add=NET_RAW \
  ubuntu:22.04 bash

# Wait for containers to start
sleep 3

# 7. Install dependencies in all containers
print_status "Installing dependencies in Router..."
docker exec router bash -c "
apt update -qq && 
apt install -y iproute2 iputils-ping iptables tcpdump net-tools
"

print_status "Installing dependencies in Victim..."
docker exec victim bash -c "
apt update -qq && 
apt install -y python3 python3-pip iproute2 iputils-ping net-tools &&
pip3 install --quiet scapy
"

print_status "Installing dependencies in Attacker..."
docker exec attacker bash -c "
apt update -qq && 
apt install -y python3 python3-pip libpcap-dev tcpdump iproute2 net-tools &&
pip3 install --quiet scapy
"

print_status "Installing dependencies in Target..."
docker exec target bash -c "
apt update -qq && 
apt install -y python3 python3-pip iproute2 iputils-ping net-tools &&
pip3 install --quiet scapy
"

# 8. Copy attack scripts to containers
print_status "Copying attack scripts to containers..."

# Copy to victim
docker cp ../src/victim.py victim:/root/victim.py
docker cp ../src/util.py victim:/root/util.py
docker exec victim chmod +x /root/victim.py

# Copy to attacker
docker cp ../src/attacker.py attacker:/root/attacker.py
docker cp ../src/util.py attacker:/root/util.py
docker exec attacker chmod +x /root/attacker.py

# Copy to target
docker cp ../src/target.py target:/root/target.py
docker cp ../src/util.py target:/root/util.py
docker exec target chmod +x /root/target.py

# 9. Configure IP forwarding and routing
print_status "Configuring network settings..."

# Enable IP forwarding in router
docker exec router bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

# Enable ICMP redirects acceptance in victim (makes attack more effective)
docker exec victim bash -c "
echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 1 > /proc/sys/net/ipv4/conf/eth0/accept_redirects
"

# Disable ICMP redirects in attacker (prevent loops)
docker exec attacker bash -c "
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects
"

# 10. Test basic connectivity
print_status "Testing basic connectivity..."

echo -n "  Router -> Victim: "
if docker exec router ping -c1 -W2 10.0.0.2 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Victim -> Target: "
if docker exec victim ping -c1 -W2 10.0.0.4 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Attacker -> All: "
if docker exec attacker ping -c1 -W2 10.0.0.2 >/dev/null 2>&1 && \
   docker exec attacker ping -c1 -W2 10.0.0.4 >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

print_status "Environment setup complete!"

echo -e "\n${BLUE}======================================================"
echo -e "Container Information:"
echo -e "======================================================${NC}"
echo -e "Router:   10.0.0.1 (Legitimate gateway)"
echo -e "Victim:   10.0.0.2 (Target of attack)"
echo -e "Attacker: 10.0.0.3 (Malicious host)"
echo -e "Target:   10.0.0.4 (Destination host)"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "1. Start target host:    ${YELLOW}sudo docker exec -it target python3 /root/target.py${NC}"
echo -e "2. Start victim traffic: ${YELLOW}sudo docker exec -it victim python3 /root/victim.py${NC}"
echo -e "3. Launch attack:        ${YELLOW}sudo docker exec -it attacker python3 /root/attacker.py${NC}"

echo -e "\n${BLUE}Monitoring Commands:${NC}"
echo -e "Monitor victim:   ${YELLOW}sudo docker exec -it victim python3 /root/victim.py --monitor${NC}"
echo -e "Check routes:     ${YELLOW}sudo docker exec -it victim ip route${NC}"
echo -e "Network capture:  ${YELLOW}sudo docker exec -it attacker tcpdump -i eth0 icmp${NC}"

print_warning "Remember to run commands in separate terminals!"
