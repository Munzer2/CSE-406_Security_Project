#!/bin/bash

# ICMP Redirect Attack Demo Script
# This script automates the complete attack demonstration

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}======================================================"
    echo -e "$1"
    echo -e "======================================================${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP $1]${NC} $2"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_header "ICMP Redirect Attack - Automated Demo"

# Check if environment is set up
if ! docker ps | grep -q "victim\|attacker\|target\|router"; then
    echo -e "${RED}[ERROR]${NC} Docker environment not set up. Run setup_environment.sh first."
    exit 1
fi

print_step "1" "Verifying packet crafting functions..."
python3 ../src/verify_packets.py
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Packet verification failed. Check implementation."
    exit 1
fi

print_step "2" "Checking initial network state..."
print_info "Initial routing table on victim:"
sudo docker exec victim ip route | grep -v "linkdown\|169.254"

print_info "Testing victim -> target connectivity:"
if sudo docker exec victim ping -c2 -W3 10.0.0.4 >/dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Victim can reach target"
else
    echo -e "${RED}✗${NC} Victim cannot reach target"
    exit 1
fi

print_step "3" "Starting target host server..."
# Start target in background
sudo docker exec -d target python3 /root/target.py
sleep 2

print_step "4" "Starting victim traffic monitor..."
# Start victim monitor in background
sudo docker exec -d victim python3 /root/victim.py --monitor

print_step "5" "Generating initial victim traffic..."
# Send a few pings to establish baseline
sudo docker exec victim python3 /root/victim.py --single
sleep 1
sudo docker exec victim python3 /root/victim.py --single

print_step "6" "Launching ICMP redirect attack..."
print_info "Sending manual ICMP redirect to demonstrate attack..."

# Send manual redirect
sudo docker exec attacker python3 /root/attacker.py --manual
sleep 2

print_step "7" "Checking attack results..."
print_info "Routing table after attack:"
sudo docker exec victim ip route | grep -v "linkdown\|169.254"

print_info "Testing traffic flow after attack..."
# Generate more traffic to see if it's redirected
sudo docker exec victim python3 /root/victim.py --single
sleep 1

print_step "8" "Network traffic analysis..."
print_info "Capturing ICMP traffic for 5 seconds..."
timeout 5 sudo docker exec attacker tcpdump -i eth0 -n icmp 2>/dev/null || true

print_header "Attack Demonstration Complete"

echo -e "${YELLOW}Summary:${NC}"
echo -e "1. Victim initially routes traffic normally through 10.0.0.254 gateway"
echo -e "2. Attacker sends spoofed ICMP redirect from router (10.0.0.1)"
echo -e "3. Victim updates routing table to use attacker (10.0.0.3) as gateway"
echo -e "4. Subsequent traffic flows through attacker instead of legitimate path"

echo -e "\n${YELLOW}Defense:${NC} Disable ICMP redirects with:"
echo -e "  echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects"

echo -e "\n${BLUE}For manual testing:${NC}"
echo -e "  Monitor: sudo docker exec -it victim python3 /root/victim.py --monitor"
echo -e "  Traffic: sudo docker exec -it victim python3 /root/victim.py"
echo -e "  Attack:  sudo docker exec -it attacker python3 /root/attacker.py"
