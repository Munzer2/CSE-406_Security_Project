#!/bin/bash
"""
Docker Setup Script for ICMP Redirect Attack Demonstration
This script sets up a dual-subnet Docker environment for the attack demo.

Network Topology:
  Victim Network (192.168.1.0/24)    Router    Target Network (192.168.2.0/24)
       |                                |                     |
   Victim (192.168.1.10)               |                Target (192.168.2.10)
   Attacker (192.168.1.20)             |
                                Router (192.168.1.1 <-> 192.168.2.1)

This forces traffic from victim to target to go through the router,
allowing the attacker to intercept and redirect it.
"""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Network configuration
VICTIM_NETWORK="victim-net"
TARGET_NETWORK="target-net"
VICTIM_SUBNET="192.168.1.0/24"
TARGET_SUBNET="192.168.2.0/24"

# IP assignments
ROUTER_VICTIM_IP="192.168.1.1"
ROUTER_TARGET_IP="192.168.2.1"
VICTIM_IP="192.168.1.10"
ATTACKER_IP="192.168.1.20"
TARGET_IP="192.168.2.10"

# Gateway IPs (different from router IPs to avoid conflicts)
VICTIM_GATEWAY="192.168.1.254"
TARGET_GATEWAY="192.168.2.254"

echo -e "${BLUE}======================================================"
echo -e "ICMP Redirect Attack - Dual Subnet Environment Setup"
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

# 1. Check existing containers and clean up only if needed
print_status "Checking existing containers..."

# Function to check if container is running
container_running() {
    docker ps -q -f name="$1" | grep -q .
}

# Function to check if container exists (running or stopped)
container_exists() {
    docker ps -a -q -f name="$1" | grep -q .
}

# Only remove stopped containers, leave running ones alone
containers_to_check=("victim" "router" "target" "attacker")
for container in "${containers_to_check[@]}"; do
    if container_running "$container"; then
        print_status "Container $container is already running, skipping..."
    elif container_exists "$container"; then
        print_status "Removing stopped container $container..."
        docker rm "$container" 2>/dev/null || true
    fi
done

# Clean up old networks (only if not in use)
print_status "Cleaning up unused networks..."
docker network rm victim-net target-net icmp-redirect-net 2>/dev/null || true

# 2. Create dual Docker networks (only if they don't exist)
print_status "Checking and creating networks..."

# Function to check if network exists
network_exists() {
    docker network ls -q -f name="$1" | grep -q .
}

if network_exists "$VICTIM_NETWORK"; then
    print_status "Victim network '$VICTIM_NETWORK' already exists, skipping creation..."
else
    print_status "Creating victim network '$VICTIM_NETWORK' ($VICTIM_SUBNET)..."
    docker network create \
      --driver=bridge \
      --subnet=$VICTIM_SUBNET \
      --gateway=$VICTIM_GATEWAY \
      $VICTIM_NETWORK

    if [ $? -eq 0 ]; then
        print_status "Victim network created successfully"
    else
        print_error "Failed to create victim network"
        exit 1
    fi
fi

if network_exists "$TARGET_NETWORK"; then
    print_status "Target network '$TARGET_NETWORK' already exists, skipping creation..."
else
    print_status "Creating target network '$TARGET_NETWORK' ($TARGET_SUBNET)..."
    docker network create \
      --driver=bridge \
      --subnet=$TARGET_SUBNET \
      --gateway=$TARGET_GATEWAY \
      $TARGET_NETWORK

    if [ $? -eq 0 ]; then
        print_status "Target network created successfully"
    else
        print_error "Failed to create target network"
        exit 1
    fi
fi

# 3. Start Router container (dual-homed) - only if not running
if container_running "router"; then
    print_status "Router container is already running, skipping creation..."
else
    print_status "Starting Router container with dual interfaces..."
    docker run -dit \
      --name router \
      --network $VICTIM_NETWORK --ip $ROUTER_VICTIM_IP \
      --cap-add=NET_RAW \
      --cap-add=NET_ADMIN \
      --privileged \
      ubuntu:22.04 bash

    # Connect router to target network as well
    docker network connect --ip $ROUTER_TARGET_IP $TARGET_NETWORK router
fi

# 4. Start Victim container on victim network - only if not running
if container_running "victim"; then
    print_status "Victim container is already running, skipping creation..."
else
    print_status "Starting Victim container ($VICTIM_IP)..."
    docker run -dit \
      --name victim \
      --network $VICTIM_NETWORK --ip $VICTIM_IP \
      --cap-add=NET_RAW \
      --cap-add=NET_ADMIN \
      ubuntu:22.04 bash
fi

# 5. Start Attacker container on victim network (same subnet as victim) - only if not running
if container_running "attacker"; then
    print_status "Attacker container is already running, skipping creation..."
else
    print_status "Starting Attacker container ($ATTACKER_IP)..."
    docker run -dit \
      --name attacker \
      --network $VICTIM_NETWORK --ip $ATTACKER_IP \
      --cap-add=NET_RAW \
      --cap-add=NET_ADMIN \
      --privileged \
      ubuntu:22.04 bash
fi

# 6. Start Target container on target network - only if not running
if container_running "target"; then
    print_status "Target container is already running, skipping creation..."
else
    print_status "Starting Target container ($TARGET_IP)..."
    docker run -dit \
      --name target \
      --network $TARGET_NETWORK --ip $TARGET_IP \
      --cap-add=NET_RAW \
      --cap-add=NET_ADMIN \
      ubuntu:22.04 bash
fi

# Wait for containers to start
sleep 3

# 7. Install dependencies in all containers (only if needed)
print_status "Checking and installing dependencies..."

# Function to check if a package is installed in a container
package_installed() {
    docker exec "$1" bash -c "command -v $2 >/dev/null 2>&1"
}

# Function to check if Python package is installed
python_package_installed() {
    docker exec "$1" bash -c "python3 -c 'import $2' >/dev/null 2>&1"
}

if container_running "router"; then
    if package_installed "router" "iptables"; then
        print_status "Router dependencies already installed, skipping..."
    else
        print_status "Installing dependencies in Router..."
        docker exec router bash -c "
        apt update -qq && 
        apt install -y iproute2 iputils-ping iptables tcpdump net-tools
        "
    fi
fi

if container_running "victim"; then
    if package_installed "victim" "python3" && python_package_installed "victim" "scapy"; then
        print_status "Victim dependencies already installed, skipping..."
    else
        print_status "Installing dependencies in Victim..."
        docker exec victim bash -c "
        apt update -qq && 
        apt install -y python3 python3-pip iproute2 iputils-ping net-tools &&
        pip3 install --quiet scapy
        "
    fi
fi

if container_running "attacker"; then
    if package_installed "attacker" "python3" && python_package_installed "attacker" "scapy"; then
        print_status "Attacker dependencies already installed, skipping..."
    else
        print_status "Installing dependencies in Attacker..."
        docker exec attacker bash -c "
        apt update -qq && 
        apt install -y python3 python3-pip libpcap-dev tcpdump iproute2 net-tools &&
        pip3 install --quiet scapy
        "
    fi
fi

if container_running "target"; then
    if package_installed "target" "python3" && python_package_installed "target" "scapy"; then
        print_status "Target dependencies already installed, skipping..."
    else
        print_status "Installing dependencies in Target..."
        docker exec target bash -c "
        apt update -qq && 
        apt install -y python3 python3-pip iproute2 iputils-ping net-tools &&
        pip3 install --quiet scapy
        "
    fi
fi

# 8. Copy attack scripts to containers (only if needed)
print_status "Checking and copying attack scripts to containers..."

# Get the absolute path to the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$PROJECT_DIR/src"

print_status "Project directory: $PROJECT_DIR"
print_status "Source directory: $SRC_DIR"

# Copy all Python files to all containers for maximum flexibility
containers=("victim" "attacker" "target" "router")
files=("victim.py" "attacker.py" "target.py" "util.py" "verify_packets.py")

for container in "${containers[@]}"; do
    if container_running "$container"; then
        print_status "Checking Python files in $container..."
        
        # Ensure /root directory exists and has proper permissions
        docker exec "$container" bash -c "mkdir -p /root && chmod 755 /root"
        
        files_to_copy=()
        for file in "${files[@]}"; do
            if [ -f "$SRC_DIR/$file" ]; then
                # Check if file already exists and is recent
                if docker exec "$container" test -f "/root/$file" 2>/dev/null; then
                    print_status "  $file already exists in $container, skipping..."
                else
                    files_to_copy+=("$file")
                fi
            else
                print_warning "  File $SRC_DIR/$file not found, skipping"
            fi
        done
        
        # Copy only files that don't exist
        if [ ${#files_to_copy[@]} -gt 0 ]; then
            print_status "Copying ${#files_to_copy[@]} files to $container..."
            for file in "${files_to_copy[@]}"; do
                print_status "  Copying $file to $container"
                docker cp "$SRC_DIR/$file" "$container:/root/$file"
                if [ $? -eq 0 ]; then
                    print_status "  ✓ Successfully copied $file"
                else
                    print_error "  ✗ Failed to copy $file"
                fi
            done
        else
            print_status "All files already exist in $container, skipping copy..."
        fi
        
        # Make Python files executable
        docker exec "$container" bash -c 'chmod +x /root/*.py' 2>/dev/null || true
    else
        print_warning "Container $container is not running, skipping file copy..."
    fi
done

print_status "File copying check complete"

# Verify files were copied successfully (only check running containers)
print_status "Verifying file copying..."
copy_failures=0
for container in "${containers[@]}"; do
    if container_running "$container"; then
        for file in "${files[@]}"; do
            if ! docker exec "$container" test -f "/root/$file" 2>/dev/null; then
                print_error "  $file missing in $container"
                ((copy_failures++))
            fi
        done
    fi
done

if [ $copy_failures -eq 0 ]; then
    print_status "✓ All Python files successfully verified in running containers"
else
    print_warning "⚠ $copy_failures file copy failures detected"
fi

# 9. Configure network routing and forwarding (only if containers are running)
print_status "Configuring network routing..."

# Function to check if route exists
route_exists() {
    docker exec "$1" bash -c "ip route | grep -q '$2'" 2>/dev/null
}

# Enable IP forwarding in router
if container_running "router"; then
    print_status "Configuring router forwarding..."
    docker exec router bash -c "
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
    "

    # Set up iptables forwarding rules in router
    docker exec router bash -c "
    iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    " 2>/dev/null || true
fi

# Configure victim routing - target subnet via router
if container_running "victim"; then
    if route_exists "victim" "$TARGET_SUBNET"; then
        print_status "Victim routing already configured, skipping..."
    else
        print_status "Configuring victim routing..."
        docker exec victim bash -c "
        ip route add $TARGET_SUBNET via $ROUTER_VICTIM_IP 2>/dev/null || true
        " 2>/dev/null || true
    fi
fi

# Configure target routing - victim subnet via router  
if container_running "target"; then
    if route_exists "target" "$VICTIM_SUBNET"; then
        print_status "Target routing already configured, skipping..."
    else
        print_status "Configuring target routing..."
        docker exec target bash -c "
        ip route add $VICTIM_SUBNET via $ROUTER_TARGET_IP 2>/dev/null || true
        " 2>/dev/null || true
    fi
fi

# Configure attacker routing - target subnet via router
if container_running "attacker"; then
    if route_exists "attacker" "$TARGET_SUBNET"; then
        print_status "Attacker routing already configured, skipping..."
    else
        print_status "Configuring attacker routing..."
        docker exec attacker bash -c "
        ip route add $TARGET_SUBNET via $ROUTER_VICTIM_IP 2>/dev/null || true
        " 2>/dev/null || true
    fi
fi

# Enable ICMP redirects acceptance in victim (makes attack more effective)
if container_running "victim"; then
    docker exec victim bash -c "
    echo 1 > /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || true
    echo 1 > /proc/sys/net/ipv4/conf/eth0/accept_redirects 2>/dev/null || true
    " 2>/dev/null || true
fi

# Disable ICMP redirects in attacker to prevent loops
if container_running "attacker"; then
    docker exec attacker bash -c "
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects 2>/dev/null || true
    " 2>/dev/null || true
fi

# 10. Test connectivity
print_status "Testing network connectivity..."

echo -n "  Victim -> Router (victim interface): "
if docker exec victim ping -c1 -W2 $ROUTER_VICTIM_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Victim -> Target (via router): "
if docker exec victim ping -c1 -W2 $TARGET_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Target -> Router (target interface): "
if docker exec target ping -c1 -W2 $ROUTER_TARGET_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Target -> Victim (via router): "
if docker exec target ping -c1 -W2 $VICTIM_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Attacker -> Victim (same subnet): "
if docker exec attacker ping -c1 -W2 $VICTIM_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

echo -n "  Attacker -> Target (via router): "
if docker exec attacker ping -c1 -W2 $TARGET_IP >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
fi

# 11. Display routing information
print_status "Verifying routing tables..."
echo -e "\n${BLUE}Router interfaces:${NC}"
docker exec router ip addr show | grep -E "(inet|eth)"

echo -e "\n${BLUE}Victim routing table:${NC}"
docker exec victim ip route

echo -e "\n${BLUE}Target routing table:${NC}"
docker exec target ip route

echo -e "\n${BLUE}Attacker routing table:${NC}"
docker exec attacker ip route

print_status "Environment setup complete!"

echo -e "\n${BLUE}======================================================"
echo -e "Network Topology Summary:"
echo -e "======================================================${NC}"
echo -e "Victim Network ($VICTIM_SUBNET):"
echo -e "  Router (victim side): $ROUTER_VICTIM_IP"
echo -e "  Victim:               $VICTIM_IP"
echo -e "  Attacker:             $ATTACKER_IP"
echo -e ""
echo -e "Target Network ($TARGET_SUBNET):"
echo -e "  Router (target side): $ROUTER_TARGET_IP"
echo -e "  Target:               $TARGET_IP"
echo -e ""
echo -e "Traffic Flow: Victim -> Router -> Target"
echo -e "Attack Vector: Attacker sends ICMP redirects to victim"

echo -e "\n${BLUE}Next Steps:${NC}"
echo -e "1. Start target host:    ${YELLOW}sudo docker exec -it target python3 /root/target.py${NC}"
echo -e "2. Start victim traffic: ${YELLOW}sudo docker exec -it victim python3 /root/victim.py${NC}"
echo -e "3. Launch attack:        ${YELLOW}sudo docker exec -it attacker python3 /root/attacker.py${NC}"

echo -e "\n${BLUE}Monitoring Commands:${NC}"
echo -e "Check victim routes:  ${YELLOW}sudo docker exec victim ip route${NC}"
echo -e "Monitor traffic:      ${YELLOW}sudo docker exec attacker tcpdump -i eth0 icmp${NC}"
echo -e "Verify packets:       ${YELLOW}sudo docker exec attacker python3 /root/verify_packets.py${NC}"

print_warning "Remember to run commands in separate terminals!"
