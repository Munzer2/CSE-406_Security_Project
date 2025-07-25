#!/bin/bash

# ICMP Redirect Attack - Environment Status Script
# This script shows the current status of the Docker environment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}======================================================"
    echo -e "$1"
    echo -e "======================================================${NC}"
}

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header "ICMP Redirect Attack - Environment Status"

# Check Docker daemon
echo -n "Docker daemon: "
if docker info >/dev/null 2>&1; then
    echo -e "${GREEN}Running${NC}"
else
    echo -e "${RED}Not running${NC}"
    print_error "Docker daemon is not running. Please start Docker first."
    exit 1
fi

# Check containers
print_status "Container Status:"
CONTAINERS="victim router target attacker"
container_count=0
running_count=0

for container in $CONTAINERS; do
    if docker ps -a -q -f name=$container | grep -q .; then
        status=$(docker ps -a --format "{{.Status}}" -f name=$container)
        if docker ps -q -f name=$container | grep -q .; then
            echo -e "  $container: ${GREEN}$status${NC}"
            ((running_count++))
        else
            echo -e "  $container: ${YELLOW}$status${NC}"
        fi
        ((container_count++))
    else
        echo -e "  $container: ${RED}Not found${NC}"
    fi
done

echo -e "  Summary: $running_count/$container_count containers running"

# Check networks
print_status "Network Status:"
NETWORKS="icmp-redirect-net icmpnet"
network_count=0

for network in $NETWORKS; do
    if docker network ls -q -f name=$network | grep -q .; then
        driver=$(docker network ls --format "{{.Driver}}" -f name=$network)
        scope=$(docker network ls --format "{{.Scope}}" -f name=$network)
        echo -e "  $network: ${GREEN}Exists${NC} (driver: $driver, scope: $scope)"
        ((network_count++))
    else
        echo -e "  $network: ${RED}Not found${NC}"
    fi
done

# Check network connectivity (if containers are running)
if [ $running_count -eq 4 ]; then
    print_status "Network Connectivity Test:"
    
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
    
    echo -n "  Attacker -> Victim: "
    if docker exec attacker ping -c1 -W2 10.0.0.2 >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
    
    echo -n "  Attacker -> Target: "
    if docker exec attacker ping -c1 -W2 10.0.0.4 >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi
else
    print_warning "Connectivity test skipped (not all containers running)"
fi

# Check routing table on victim (if running)
if docker ps -q -f name=victim | grep -q .; then
    print_status "Victim Routing Table:"
    victim_routes=$(docker exec victim ip route 2>/dev/null | grep -v "linkdown\|169.254" || echo "  No routes found")
    echo "$victim_routes" | sed 's/^/  /'
fi

# Docker system info
print_status "Docker System Status:"
echo -n "  Total containers: "
echo "$(docker ps -a | wc -l | xargs expr -1 +)"

echo -n "  Running containers: "
echo "$(docker ps | wc -l | xargs expr -1 +)"

echo -n "  Total networks: "
echo "$(docker network ls | wc -l | xargs expr -1 +)"

echo -n "  Total volumes: "
echo "$(docker volume ls | wc -l | xargs expr -1 +)"

# Files status
print_status "Project Files:"
PROJECT_FILES=(
    "scripts/setup_environment.sh"
    "scripts/cleanup_docker_environment.sh" 
    "scripts/demo_attack.sh"
    "scripts/check_environment.sh"
    "src/attacker.py"
    "src/victim.py"
    "src/target.py"
    "src/verify_packets.py"
    "src/util.py"
    "README.md"
)

for file in "${PROJECT_FILES[@]}"; do
    if [ -f "$file" ]; then
        if [ -x "$file" ]; then
            echo -e "  $file: ${GREEN}Exists (executable)${NC}"
        else
            echo -e "  $file: ${GREEN}Exists${NC}"
        fi
    else
        echo -e "  $file: ${RED}Missing${NC}"
    fi
done

echo ""

# Environment recommendations
if [ $container_count -eq 0 ]; then
    print_warning "Environment not set up. Run: sudo ./scripts/setup_environment.sh"
elif [ $running_count -lt 4 ]; then
    print_warning "Some containers are not running. Try restarting them or run setup again."
elif [ $network_count -eq 0 ]; then
    print_warning "Networks not found. Run: sudo ./scripts/setup_environment.sh"
else
    echo -e "${GREEN}✓ Environment appears to be ready for demonstration${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo -e "  1. Run demo: ${YELLOW}sudo ./scripts/demo_attack.sh${NC}"
    echo -e "  2. Manual testing: See README.md for detailed instructions"
    echo -e "  3. Cleanup when done: ${YELLOW}sudo ./scripts/cleanup_docker_environment.sh${NC}"
fi
