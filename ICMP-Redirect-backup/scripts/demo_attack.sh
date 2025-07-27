#!/bin/bash

# ICMP Redirect Attack Demonstration Script
# This script demonstrates the complete ICMP redirect attack flow

echo "ICMP Redirect Attack Demonstration"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if containers are running
containers=("victim" "router" "attacker" "external-server")
for container in "${containers[@]}"; do
    if ! docker ps -q -f name="$container" | grep -q .; then
        print_error "Container $container is not running"
        print_info "Please run the setup script first: sudo ./setup_environment.sh"
        exit 1
    fi
done

print_status "All containers are running"

# Copy enhanced attack script
print_info "Copying enhanced attack script to attacker..."
if [ -f "/home/sowdha/Desktop/L4T1/CSE-406_Security_Project/ICMP-Redirect/src/enhanced_attack_test.py" ]; then
    docker cp /home/sowdha/Desktop/L4T1/CSE-406_Security_Project/ICMP-Redirect/src/enhanced_attack_test.py attacker:/root/enhanced_attack_test.py 2>/dev/null || true
fi

echo ""
echo "Attack Demonstration Flow:"
echo "========================="
echo "1. Show initial network configuration"
echo "2. Test normal connectivity (victim -> external server via router)"
echo "3. Start packet monitoring on victim"
echo "4. Launch ICMP redirect attack from attacker"
echo "5. Test redirected connectivity (victim -> external server via attacker)"
echo "6. Show modified routing tables"
echo ""

read -p "Press Enter to continue..."

# Step 1: Show initial configuration
print_status "Step 1: Initial Network Configuration"
echo ""

print_info "Victim routing table:"
docker exec victim ip route show
echo ""

print_info "Victim ARP table:"
docker exec victim arp -a
echo ""

print_info "Router configuration:"
docker exec router ip addr show | grep "inet " | grep -v "127.0.0.1"
echo ""

read -p "Press Enter to continue..."

# Step 2: Test normal connectivity
print_status "Step 2: Testing Normal Connectivity"
echo ""

print_info "Testing ping from victim to external server (10.0.0.100):"
echo "This should go through the router (192.168.1.1)"
echo ""

# Run ping in background and capture output
docker exec victim ping -c 3 10.0.0.100

echo ""
read -p "Press Enter to continue..."

# Step 3: Start packet monitoring
print_status "Step 3: Starting Packet Monitoring"
echo ""

print_info "Starting tcpdump on victim to monitor ICMP traffic..."
echo "This will capture ICMP redirect messages from the attacker"
echo ""

# Start tcpdump in background
docker exec -d victim tcpdump -i eth0 -n icmp

sleep 2
print_status "Packet monitoring started"

read -p "Press Enter to continue..."

# Step 4: Launch attack
print_status "Step 4: Launching ICMP Redirect Attack"
echo ""

print_info "Starting attacker script..."
echo "The attacker will:"
echo "  - Send ICMP redirect messages to victim"
echo "  - Redirect victim's traffic through attacker"
echo ""

# Run enhanced attack test
print_warning "Running enhanced ICMP redirect attack..."
docker exec attacker python3 /root/enhanced_attack_test.py

sleep 3
print_status "Attack completed"

read -p "Press Enter to continue..."

# Step 5: Test redirected connectivity
print_status "Step 5: Testing Redirected Connectivity"
echo ""

print_info "Generating traffic from victim to trigger redirect..."
print_info "Sending ping to external server (this should trigger the attack):"
echo ""

# Send traffic to trigger redirect
docker exec victim ping -c 5 10.0.0.100

echo ""
print_status "Traffic sent - checking for redirect effects..."

sleep 2

# Check if routing table has changed
print_info "Victim routing table after attack:"
docker exec victim ip route show
echo ""

print_info "Victim ARP table after attack:"
docker exec victim arp -a
echo ""

read -p "Press Enter to continue..."

# Step 6: Show results
print_status "Step 6: Attack Results Analysis"
echo ""

print_info "Checking attacker logs:"
docker logs attacker 2>/dev/null | tail -20
echo ""

print_info "Checking for ICMP redirect messages in victim's tcpdump:"
# Stop tcpdump and show captured packets
docker exec victim pkill tcpdump 2>/dev/null || true
sleep 1

# Check if redirect was successful
print_info "Network configuration summary:"
echo ""
echo "Original route: victim -> router (192.168.1.1) -> external server"
echo "After attack:   victim -> attacker (192.168.1.20) -> external server"
echo ""

# Verify attack success
print_status "Verifying attack success..."

# Check if victim's ARP table now has attacker's MAC for router IP
arp_entry=$(docker exec victim arp -n | grep "192.168.1.1" || echo "No entry found")
print_info "ARP entry for router IP (192.168.1.1): $arp_entry"

# Test final connectivity
print_info "Final connectivity test:"
docker exec victim ping -c 3 10.0.0.100

echo ""
print_status "Attack demonstration completed!"
echo ""
print_warning "To clean up:"
echo "  - Stop containers: docker stop victim router attacker external-server"
echo "  - Remove containers: docker rm victim router attacker external-server"
echo "  - Remove networks: docker network rm internal-net external-net"
echo ""
print_warning "To reset the environment:"
echo "  - Run: sudo ./cleanup_docker_environment.sh"
echo "  - Then: sudo ./setup_environment.sh"
