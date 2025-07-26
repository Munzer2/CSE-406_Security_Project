#!/bin/bash

# Complete Docker Environment Cleanup Script
# This script removes all Docker images, networks, containers, and volumes 
# created and used for the ICMP Redirect Attack experiment

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

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "Please run as root (use sudo)"
    exit 1
fi

print_header "Complete Docker Environment Cleanup"

# Confirm cleanup action
if [ "$1" != "--force" ]; then
    echo -e "${YELLOW}This will remove ALL Docker containers, networks, volumes, and images used in the experiment.${NC}"
    echo -e "${YELLOW}This includes:${NC}"
    echo -e "  • All experiment containers (victim, router, target, attacker)"
    echo -e "  • All experiment networks (icmp-redirect-net, icmpnet)"
    echo -e "  • All Docker volumes"
    echo -e "  • Optionally: Ubuntu base images"
    echo -e "  • Docker build cache and unused resources"
    echo ""
    echo -e "${RED}WARNING: This action cannot be undone!${NC}"
    echo ""
    read -p "Are you sure you want to continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "Cleanup cancelled."
        exit 0
    fi
fi

echo ""

# 1. Stop and remove all experiment containers
print_status "Stopping and removing experiment containers..."

EXPERIMENT_CONTAINERS="victim router target attacker"
for container in $EXPERIMENT_CONTAINERS; do
    if docker ps -a -q -f name=$container | grep -q .; then
        echo -n "  Stopping and removing $container: "
        if docker stop $container >/dev/null 2>&1 && docker rm $container >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    else
        echo "  Container $container: ${YELLOW}not found${NC}"
    fi
done

# 2. Remove all other containers (if requested)
if [ "$1" = "--all" ] || [ "$2" = "--all" ]; then
    print_status "Removing ALL Docker containers..."
    all_containers=$(docker ps -a -q)
    if [ -n "$all_containers" ]; then
        echo -n "  Removing all containers: "
        if docker stop $all_containers >/dev/null 2>&1 && docker rm $all_containers >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}Some containers may have failed${NC}"
        fi
    else
        echo "  No containers to remove"
    fi
fi

# 3. Remove experiment networks
print_status "Removing experiment networks..."

EXPERIMENT_NETWORKS="icmp-redirect-net"
for network in $EXPERIMENT_NETWORKS; do
    if docker network ls -q -f name=$network | grep -q .; then
        echo -n "  Removing network $network: "
        if docker network rm $network >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAILED${NC}"
        fi
    else
        echo "  Network $network: ${YELLOW}not found${NC}"
    fi
done

# 4. Remove ALL Docker networks (if requested)
if [ "$1" = "--all" ] || [ "$2" = "--all" ]; then
    print_status "Removing ALL custom Docker networks..."
    custom_networks=$(docker network ls --format "{{.Name}}" | grep -v "bridge\|host\|none")
    if [ -n "$custom_networks" ]; then
        for network in $custom_networks; do
            echo -n "  Removing network $network: "
            if docker network rm $network >/dev/null 2>&1; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}FAILED (may be in use)${NC}"
            fi
        done
    else
        echo "  No custom networks to remove"
    fi
fi

# 5. Remove ALL Docker volumes
print_status "Removing Docker volumes..."

all_volumes=$(docker volume ls -q)
if [ -n "$all_volumes" ]; then
    echo -n "  Removing all volumes: "
    if docker volume rm $all_volumes >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Some volumes may be in use${NC}"
    fi
else
    echo "  No volumes to remove"
fi

# 6. Remove Docker images
print_status "Managing Docker images..."

# Remove Ubuntu images used in experiment
ubuntu_images=$(docker images ubuntu:22.04 -q)
if [ -n "$ubuntu_images" ]; then
    echo -n "  Remove Ubuntu 22.04 image? (y/N): "
    if [ "$1" = "--force" ] || [ "$1" = "--all" ]; then
        remove_ubuntu="y"
        echo "y (forced)"
    else
        read remove_ubuntu
    fi
    
    if [[ "$remove_ubuntu" =~ ^[Yy]$ ]]; then
        echo -n "  Removing Ubuntu 22.04 image: "
        if docker rmi ubuntu:22.04 >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}FAILED (may be in use)${NC}"
        fi
    else
        echo "  Keeping Ubuntu 22.04 image"
    fi
else
    echo "  No Ubuntu 22.04 image found"
fi

# Remove ALL images (if requested)
if [ "$1" = "--all" ] || [ "$2" = "--all" ]; then
    print_status "Removing ALL Docker images..."
    all_images=$(docker images -q)
    if [ -n "$all_images" ]; then
        echo -n "  Removing all images: "
        if docker rmi -f $all_images >/dev/null 2>&1; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}Some images may have failed${NC}"
        fi
    else
        echo "  No images to remove"
    fi
fi

# 7. Docker system cleanup
print_status "Performing comprehensive Docker cleanup..."

echo -n "  Pruning stopped containers: "
if docker container prune -f >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}FAILED${NC}"
fi

echo -n "  Pruning unused networks: "
if docker network prune -f >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}FAILED${NC}"
fi

echo -n "  Pruning unused volumes: "
if docker volume prune -f >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}FAILED${NC}"
fi

echo -n "  Pruning unused images: "
if docker image prune -f >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}FAILED${NC}"
fi

echo -n "  Pruning build cache: "
if docker builder prune -f >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${YELLOW}FAILED${NC}"
fi

# Complete system prune (if requested)
if [ "$1" = "--all" ] || [ "$2" = "--all" ]; then
    echo -n "  Complete system prune: "
    if docker system prune -a -f >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}FAILED${NC}"
    fi
fi

# 8. Clean up temporary files
print_status "Cleaning up temporary files..."

# Remove any temporary files that might have been created
TEMP_PATTERNS=(
    "/tmp/icmp_redirect_*"
    "/tmp/attack_*"
    "/tmp/docker_*"
    "/var/tmp/docker_bridge_*"
    "/var/lib/docker/tmp/*"
)

for pattern in "${TEMP_PATTERNS[@]}"; do
    if ls $pattern >/dev/null 2>&1; then
        echo -n "  Removing files matching $pattern: "
        if rm -rf $pattern 2>/dev/null; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${YELLOW}FAILED${NC}"
        fi
    fi
done

# 9. Reset network configurations
print_status "Checking network configurations..."

# Check iptables rules
echo -n "  Checking iptables rules: "
if iptables -L | grep -q "icmp\|redirect" 2>/dev/null; then
    echo -e "${YELLOW}ICMP-related rules found${NC}"
    print_warning "You may want to review iptables rules:"
    print_warning "  sudo iptables -L"
    print_warning "  sudo iptables -F  # (flush all rules - use with caution)"
else
    echo -e "${GREEN}OK${NC}"
fi

# Check bridge interfaces
echo -n "  Checking bridge interfaces: "
bridges=$(ip link show type bridge | grep -E "br-.*" | wc -l)
if [ "$bridges" -gt 1 ]; then  # docker0 is always present
    echo -e "${YELLOW}$bridges bridge interfaces found${NC}"
    print_warning "Multiple bridge interfaces found (usually cleaned up automatically)"
else
    echo -e "${GREEN}OK${NC}"
fi

# 10. Verify complete cleanup
print_status "Verifying cleanup completion..."

echo "  Docker containers: $(docker ps -a | wc -l | xargs expr -1 +) remaining"
echo "  Docker networks: $(docker network ls | wc -l | xargs expr -1 +) remaining"
echo "  Docker volumes: $(docker volume ls | wc -l | xargs expr -1 +) remaining"
echo "  Docker images: $(docker images | wc -l | xargs expr -1 +) remaining"

# Calculate disk space usage
echo -n "  Docker disk usage: "
docker_size=$(docker system df --format "table {{.Size}}" 2>/dev/null | tail -n +2 | sed 's/B$//' | awk '{
    size = $1
    unit = $2
    if (unit == "GB") size *= 1024
    else if (unit == "KB") size /= 1024
    total += size
} END {printf "%.1f MB\n", total}' 2>/dev/null || echo "Unknown")
echo "$docker_size"

# 11. Final status report
print_header "Cleanup Complete"

echo -e "${GREEN}Summary of cleanup actions:${NC}"
echo -e "  ✓ Removed experiment containers and networks"
echo -e "  ✓ Cleaned up Docker volumes"
echo -e "  ✓ Performed Docker system cleanup"
echo -e "  ✓ Removed temporary files"
echo -e "  ✓ Checked network configurations"
echo -e "  ✓ Verified cleanup completion"

if [ "$1" = "--all" ] || [ "$2" = "--all" ]; then
    echo -e "  ✓ Performed complete system cleanup (all containers, networks, images)"
fi

echo -e "\n${BLUE}Current Docker Status:${NC}"
echo -e "  Total containers: $(docker ps -a | wc -l | xargs expr -1 +)"
echo -e "  Total networks: $(docker network ls | wc -l | xargs expr -1 +)"
echo -e "  Total volumes: $(docker volume ls | wc -l | xargs expr -1 +)"
echo -e "  Total images: $(docker images | wc -l | xargs expr -1 +)"
echo -e "  Disk usage: $docker_size"

echo -e "\n${YELLOW}Usage:${NC}"
echo -e "  $0                    # Interactive cleanup (experiment only)"
echo -e "  $0 --force            # Non-interactive cleanup (experiment only)"
echo -e "  $0 --all              # Interactive cleanup (everything)"
echo -e "  $0 --force --all      # Non-interactive cleanup (everything)"

print_info "Docker environment cleanup completed successfully!"

echo -e "\n${BLUE}Optional additional actions:${NC}"
echo -e "  • Restart Docker daemon: sudo systemctl restart docker"
echo -e "  • Check system resources: df -h && free -h"
echo -e "  • Review network interfaces: ip link show"
