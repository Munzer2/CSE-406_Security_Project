#!/bin/bash
set -e

# ====== CONFIGURATION ======
IMG="ubuntu:22.04"
BRIDGE="bridge"
MACVLAN="attack-net"
HOST_IF="wlp1s0"     # Replace with your real interface if needed
VICTIM_IP="10.9.0.5"
ATTACKER_IP="10.9.0.105"
ROUTER_IP="10.9.0.11"
TARGET_IP="10.9.0.200"
TARGET2_IP="10.9.0.201"

# ====== PHASE 1: LAUNCH ON BRIDGE ======
echo "🚦 [Phase 1] Launching containers on bridge (with internet)..."
echo "📦 Installing all packages including dsniff for ARP spoofing..."
for name in victim attacker router target target2; do
  docker rm -f $name 2>/dev/null || true
  docker run -d --name $name \
    --cap-add ALL \
    --privileged \
    --network $BRIDGE \
    $IMG sleep infinity
done
sleep 3

# OPTIONAL: Pull latest image if not present
docker pull $IMG

for c in victim attacker router target target2; do
  echo "🛠️  Installing packages in $c..."
  docker exec $c apt update
  if [ "$c" = "attacker" ]; then
    # Install additional packages for attacker including dsniff (arpspoof)
    echo "🎭 Installing ARP spoofing tools (dsniff) for attacker..."
    docker exec $c apt install -y python3 python3-pip iproute2 iputils-ping net-tools tcpdump iptables dnsutils curl wget dsniff
  else
    docker exec $c apt install -y python3 python3-pip iproute2 iputils-ping net-tools tcpdump iptables dnsutils curl wget
  fi
done

echo "✅ All packages installed while containers have internet access"

# Copy lab scripts if you have them
# Determine the correct path to src directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")/src"

if [ -f "$SRC_DIR/packet_craft.py" ]; then
  echo "📋 Copying packet_craft.py library to all containers..."
  for c in victim attacker router target target2; do
    docker cp "$SRC_DIR/packet_craft.py" $c:/root/packet_craft.py
  done
fi

# Copy attack scripts (now using main filenames)
if [ -f "$SRC_DIR/icmp_redirect_attack.py" ]; then
  echo "📋 Copying ICMP redirect attack script..."
  docker cp "$SRC_DIR/icmp_redirect_attack.py" attacker:/root/icmp_redirect_attack.py
fi

if [ -f "$SRC_DIR/victim_traffic.py" ]; then
  echo "📋 Copying victim traffic script..."
  docker cp "$SRC_DIR/victim_traffic.py" victim:/root/victim_traffic.py
fi

if [ -f "$SRC_DIR/target_host.py" ]; then
  echo "📋 Copying target host scripts..."
  docker cp "$SRC_DIR/target_host.py" target:/root/target_host.py
  docker cp "$SRC_DIR/target_host.py" target2:/root/target_host.py
fi

# ====== PHASE 2: SWITCH TO MACVLAN ======
echo "🌐 [Phase 2] Switching to macvlan network (no internet access)..."
echo "🎭 ARP spoofing tools already installed in attacker container"

docker network rm $MACVLAN 2>/dev/null || true
docker network create -d macvlan --subnet=10.9.0.0/24 --gateway=10.9.0.1 -o parent=$HOST_IF $MACVLAN

for entry in \
  "victim:$VICTIM_IP" \
  "attacker:$ATTACKER_IP" \
  "router:$ROUTER_IP" \
  "target:$TARGET_IP" \
  "target2:$TARGET2_IP"
do
  name=${entry%%:*}; ip=${entry##*:}
  # Add macvlan
  docker network connect --ip $ip $MACVLAN $name
done

# Remove bridge IP (optional but recommended for isolation)
for name in victim attacker router target target2; do
  docker network disconnect $BRIDGE $name || true
done

# Wait a second for network transition
sleep 2

# Set resolv.conf for local DNS (internet not needed for lab)
for c in victim attacker router target target2; do
  docker exec $c bash -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'
done

# Set sysctls, routing, and L2 options
echo "🔧 Configuring victim container..."
docker exec victim bash -c '
  sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || echo "Note: Could not set accept_redirects (may already be set)"
  sysctl -w net.ipv4.conf.default.accept_redirects=1 2>/dev/null || echo "Note: Could not set default accept_redirects"
  sysctl -w net.ipv4.conf.eth1.accept_redirects=1 2>/dev/null || echo "Note: Could not set eth1 accept_redirects (using eth1 for macvlan)"
  sysctl -w net.ipv4.conf.all.secure_redirects=0 2>/dev/null || echo "Note: Could not disable secure_redirects"
  sysctl -w net.ipv4.conf.eth1.secure_redirects=0 2>/dev/null || echo "Note: Could not disable eth1 secure_redirects"
  sysctl -w net.ipv4.conf.all.log_martians=1 2>/dev/null || echo "Note: Could not enable log_martians"
  ip route del default 2>/dev/null || true
  ip route add default via 10.9.0.11 dev eth1 2>/dev/null || echo "Note: Could not add default route"
'

echo "🔧 Configuring attacker container..."
docker exec attacker bash -c '
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "Note: Could not enable IP forwarding"
  ip link set eth1 promisc on 2>/dev/null || echo "Note: Could not set promiscuous mode on eth1"
  ip route del default 2>/dev/null || true
  ip route add default via 10.9.0.11 dev eth1 2>/dev/null || echo "Note: Could not add default route"
'

echo "🔧 Configuring router container..."
docker exec router bash -c '
  sysctl -w net.ipv4.ip_forward=1 2>/dev/null || echo "Note: Could not enable IP forwarding"
  sysctl -w net.ipv4.conf.all.send_redirects=1 2>/dev/null || echo "Note: Could not enable send_redirects"
  sysctl -w net.ipv4.conf.eth1.send_redirects=1 2>/dev/null || echo "Note: Could not enable eth1 send_redirects"
'

echo ""
echo "✅ Environment ready! All containers are now isolated on macvlan:"
echo "   - Victim:      $VICTIM_IP"
echo "   - Attacker:    $ATTACKER_IP"
echo "   - Router:      $ROUTER_IP"
echo "   - Target(1/2): $TARGET_IP $TARGET2_IP"
echo ""
echo "🚩 Next steps:"
echo "  - Start your victim/attacker scripts with:"
echo "      docker exec -it attacker python3 /root/icmp_redirect_attack.py"
echo "      docker exec -it victim python3 /root/victim_traffic.py"
echo "      docker exec -it target python3 /root/target_host.py"
echo ""
echo "  - Monitor traffic: docker exec -it attacker tcpdump -i eth1"
echo "  - Check routing: docker exec -it victim ip route"
echo "  - Test connectivity: docker exec -it victim ping 10.9.0.200"
echo ""
echo "🛑 To clean up: run "
echo "      docker rm -f victim attacker router target target2"
echo "      docker network rm $MACVLAN"
