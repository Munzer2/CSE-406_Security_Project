#!/bin/bash

# ICMP Redirect Attack - Macvlan Cleanup Script
# ==============================================
# This script cleans up the macvlan-based attack environment

echo "🧹 ICMP Redirect Attack Lab - Macvlan Cleanup"
echo "=============================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

# Stop and remove containers
echo "🛑 Stopping and removing containers..."

containers=("victim" "attacker" "router" "target" "target2" "malicious-router")
for container in "${containers[@]}"; do
    if docker ps -a --format "table {{.Names}}" | grep -q "^$container$"; then
        echo "  Removing container: $container"
        docker rm -f "$container" 2>/dev/null || true
    fi
done

print_status "All containers removed"

# Remove macvlan network
echo "🌐 Removing macvlan network..."

if docker network ls --format "table {{.Name}}" | grep -q "^attack-net$"; then
    echo "  Removing network: attack-net"
    docker network rm attack-net 2>/dev/null || true
    print_status "Macvlan network removed"
else
    print_warning "Network attack-net not found"
fi

# Remove any lingering networks from old setups
echo "🧹 Cleaning up any old networks..."
old_networks=("internal-net" "target-net")
for network in "${old_networks[@]}"; do
    if docker network ls --format "table {{.Name}}" | grep -q "^$network$"; then
        echo "  Removing old network: $network"
        docker network rm "$network" 2>/dev/null || true
    fi
done

# Verify cleanup
echo "🔍 Verifying cleanup..."

remaining_containers=$(docker ps -a --format "table {{.Names}}" | grep -E '^(victim|attacker|router|target|target2|malicious-router)$' | wc -l)
remaining_networks=$(docker network ls --format "table {{.Name}}" | grep -E '^(attack-net|internal-net|target-net)$' | wc -l)

if [ "$remaining_containers" -eq 0 ] && [ "$remaining_networks" -eq 0 ]; then
    print_status "Cleanup completed successfully"
    echo ""
    echo "📊 Final Status:"
    echo "   ✅ All attack containers removed"
    echo "   ✅ All attack networks removed"
    echo "   ✅ System restored to clean state"
else
    print_warning "Cleanup may be incomplete"
    echo ""
    echo "📊 Remaining:"
    if [ "$remaining_containers" -gt 0 ]; then
        echo "   ⚠️  Containers: $remaining_containers"
        docker ps -a --format "table {{.Names}}\t{{.Status}}" | grep -E '(victim|attacker|router|target|malicious-router)'
    fi
    if [ "$remaining_networks" -gt 0 ]; then
        echo "   ⚠️  Networks: $remaining_networks"
        docker network ls --format "table {{.Name}}\t{{.Driver}}" | grep -E '(attack-net|internal-net|target-net)'
    fi
fi

echo ""
print_status "Macvlan cleanup complete!"
echo ""
print_warning "Note: Host interface settings (promiscuous mode, etc.) are preserved"
echo "      If you need to reset host networking, you may need to reboot or"
echo "      manually reset interface configurations."
