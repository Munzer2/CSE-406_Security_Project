#!/bin/bash

# ICMP Spoofing Attack - Cleanup Script
# This script cleans up all containers, networks, and resources created for the demonstration

echo "🧹 Starting ICMP Spoofing Attack Cleanup..."
echo "==========================================="

# Function to check if container exists
container_exists() {
    sudo docker ps -a --format "table {{.Names}}" | grep -q "^$1$" 2>/dev/null
}

# Function to check if network exists
network_exists() {
    sudo docker network ls --format "table {{.Name}}" | grep -q "^$1$" 2>/dev/null
}

# Ask for confirmation
echo "⚠️  This will remove all containers and networks created for the ICMP spoofing demo."
echo "   Containers to be removed: victim2, attacker2, router2"
echo "   Networks to be removed: net_vict_att, net_att_rout"
echo ""
read -p "Are you sure you want to continue? (y/N): " confirm

case $confirm in
    [yY]|[yY][eE][sS])
        echo "🗑️  Proceeding with cleanup..."
        ;;
    *)
        echo "👋 Cleanup cancelled."
        exit 0
        ;;
esac

# Stop and remove containers
echo ""
echo "🛑 Step 1: Stopping and removing containers..."

containers=("victim2" "attacker2" "router2")
for container in "${containers[@]}"; do
    if container_exists "$container"; then
        echo "  🗑️  Removing container: $container"
        sudo docker rm -f "$container" 2>/dev/null || true
        echo "  ✅ Container $container removed"
    else
        echo "  ℹ️  Container $container does not exist"
    fi
done

# Remove networks
echo ""
echo "🌐 Step 2: Removing networks..."

networks=("net_vict_att" "net_att_rout")
for network in "${networks[@]}"; do
    if network_exists "$network"; then
        echo "  🗑️  Removing network: $network"
        sudo docker network rm "$network" 2>/dev/null || true
        echo "  ✅ Network $network removed"
    else
        echo "  ℹ️  Network $network does not exist"
    fi
done

# Clean up any orphaned resources
echo ""
echo "🧽 Step 3: Cleaning up orphaned resources..."
echo "  🗑️  Pruning unused Docker resources..."
sudo docker system prune -f --volumes 2>/dev/null || true

# Verify cleanup
echo ""
echo "🔍 Step 4: Verifying cleanup..."

echo "  📋 Remaining containers:"
remaining_containers=$(sudo docker ps -a --filter "name=victim2" --filter "name=attacker2" --filter "name=router2" --format "table {{.Names}}" | tail -n +2)
if [ -z "$remaining_containers" ]; then
    echo "  ✅ No demo containers remaining"
else
    echo "  ⚠️  Some containers still exist: $remaining_containers"
fi

echo "  📋 Remaining networks:"
remaining_networks=$(sudo docker network ls --filter "name=net_vict_att" --filter "name=net_att_rout" --format "table {{.Name}}" | tail -n +2)
if [ -z "$remaining_networks" ]; then
    echo "  ✅ No demo networks remaining"
else
    echo "  ⚠️  Some networks still exist: $remaining_networks"
fi

# Final status
echo ""
echo "🎉 Cleanup Complete!"
echo "==================="
echo "✅ All demo containers removed"
echo "✅ All demo networks removed"
echo "✅ Orphaned resources cleaned"
echo ""
echo "💡 The environment is now clean and ready for a fresh setup."
echo "   Run './setup.sh' to set up the demonstration again."
echo ""
echo "📁 Files preserved:"
echo "   - setup.sh, attack.sh, cleanup.sh"
echo "   - spoof2.py, spoof.py"
echo "   - README.md"