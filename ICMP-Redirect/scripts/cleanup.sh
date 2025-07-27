#!/bin/bash

# ICMP Redirect Attack - Cleanup Script
# This script cleans up all containers and networks created for the demonstration

echo "🧹 Starting ICMP Redirect Attack Cleanup..."
echo "==========================================="

# Function to check if container exists
container_exists() {
    sudo docker ps -a --format "table {{.Names}}" | grep -q "^$1$" 2>/dev/null
}

# Function to check if network exists
network_exists() {
    sudo docker network ls --format "table {{.Name}}" | grep -q "^$1$" 2>/dev/null
}

# Ask for confirmation if auto mode not specified
if [ "$1" != "--force" ]; then
    echo "⚠️  This will remove all containers and networks created for the ICMP redirect demo."
    echo "   Containers to be removed: victim, attacker, router, target, target2, malicious-router"
    echo "   Networks to be removed: internal-net, target-net"
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
else
    echo "🔄 Running in automatic mode, skipping confirmation..."
fi

# Stop and remove containers
echo ""
echo "🛑 Step 1: Stopping and removing containers..."

containers=("victim" "attacker" "router" "target" "target2" "malicious-router")
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

networks=("internal-net" "target-net")
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
echo "  🗑️  Disconnecting containers from networks (if any)..."
for container in "${containers[@]}"; do
    if container_exists "$container"; then
        for network in "${networks[@]}"; do
            if network_exists "$network"; then
                sudo docker network disconnect "$network" "$container" 2>/dev/null || true
            fi
        done
    fi
done

# Wait a moment for network interfaces to be released
sleep 2

echo "  🗑️  Pruning unused Docker resources..."
sudo docker system prune -f --volumes 2>/dev/null || true

# Verify cleanup
echo ""
echo "🔍 Step 4: Verifying cleanup..."

echo "  📋 Remaining containers:"
remaining_containers=$(sudo docker ps -a --filter "name=victim" --filter "name=attacker" --filter "name=router" --filter "name=target" --filter "name=target2" --filter "name=malicious-router" --format "table {{.Names}}" | tail -n +2)
if [ -z "$remaining_containers" ]; then
    echo "  ✅ No demo containers remaining"
else
    echo "  ⚠️  Some containers still exist: $remaining_containers"
fi

echo "  📋 Remaining networks:"
remaining_networks=$(sudo docker network ls --filter "name=internal-net" --filter "name=target-net" --format "table {{.Name}}" | tail -n +2)
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
