# ICMP Redirect Attack Demo

This repository demonstrates an ICMP Redirect attack using Docker containers and custom Python scripts. The attacker sniffs traffic between a victim and a target, then sends ICMP redirect messages to poison the victim's routing table, enabling a Man-in-the-Middle (MITM) attack.

## Network Topology

```
                           ICMP Redirect Attack Lab Environment
                           ═══════════════════════════════════

    Network: internal-net                    Network: target-net
    Subnet: 10.9.0.0/24                     Subnet: 192.168.60.0/24
    ┌─────────────────────────┐             ┌─────────────────────────┐
    │                         │             │                         │
    │  ┌─────────────┐        │             │        ┌─────────────┐  │
    │  │   VICTIM    │        │             │        │   TARGET    │  │
    │  │  (victim)   │        │             │        │  (target)   │  │
    │  │ 10.9.0.5    │        │             │        │192.168.60.5 │  │
    │  └─────┬───────┘        │             │        └─────┬───────┘  │
    │        │ eth0           │             │              │ eth0     │
    │        │                │             │              │          │
    │   ─────┼────────────    │             │         ─────┼────────  │
    │        │                │             │              │          │
    │        │                │             │              │          │
    │  ┌─────▼───────┐        │             │        ┌─────▼───────┐  │
    │  │  ATTACKER   │        │             │        │   TARGET2   │  │
    │  │ (attacker)  │        │             │        │  (target2)  │  │
    │  │ 10.9.0.105  │        │             │        │192.168.60.6 │  │
    │  └─────────────┘        │             │        └─────────────┘  │
    │                         │             │                         │
    │  ┌─────────────┐        │             │                         │
    │  │ MALICIOUS   │        │             │                         │
    │  │  ROUTER     │        │             │                         │
    │  │(mal-router) │        │             │                         │
    │  │ 10.9.0.111  │        │             │                         │
    │  └─────┬───────┘        │             │                         │
    │        │                │             │                         │
    │        │                │    ┌────────┼────────┐                │
    │   ─────┼────────────    │    │        │        │                │
    │        │                │    │   ┌────▼────┐   │                │
    │        │ eth0           │    │   │ ROUTER  │   │                │
    │        │                │    │   │(router) │   │                │
    │  ┌─────▼───────┐        │    │   │         │   │                │
    │  │   ROUTER    │◄───────┼────┤   │10.9.0.11│   │                │
    │  │  (router)   │        │    │   │192.168. │   │                │
    │  │ 10.9.0.11   │        │    │   │ 60.11   │   │                │
    │  │             │        │    │   └─────────┘   │                │
    │  └─────────────┘        │    └─────────────────┘                │
    │                         │                                       │
    └─────────────────────────┘                                       │
                                                                      │
                              ═══════════════════════════════════════════

📡 Attack Flow:
──────────────
1. Victim (10.9.0.5) sends packets to Target (192.168.60.5) via Router (10.9.0.11)
2. Attacker (10.9.0.105) sniffs victim traffic on internal network (10.9.0.0/24)
3. Attacker sends ICMP redirect to victim, pretending to be Router
4. ICMP redirect tells victim: "Use me (Attacker) as gateway for Target network"
5. Victim updates routing table to use Attacker as gateway for 192.168.60.0/24
6. Future packets to Target go through Attacker → MITM position achieved!

🔧 Key Configuration:
────────────────────
• Victim has ICMP redirects enabled (net.ipv4.conf.all.accept_redirects=1)
• Router is dual-homed (10.9.0.11 & 192.168.60.11) with IP forwarding
• Attacker has packet sniffing and crafting capabilities
• All containers run with --cap-add ALL for raw socket access
```

## Prerequisites

* Docker (with root/sudo access)
* Python 3
* Linux environment

## Quick Start

This repository includes automation scripts for easy setup and execution:

### Available Scripts

| Script | Purpose | Description |
|--------|---------|-------------|
| `scripts/setup.sh` | Environment Setup | Creates networks, containers, installs dependencies, configures routing |
| `scripts/cleanup.sh` | Environment Cleanup | Removes all containers and networks |

### Complete Attack Demo (From Scratch)

```bash
# 1. Navigate to scripts directory
cd scripts/

# 2. Setup the complete environment
./setup.sh

# 3. Start the target server (in a new terminal)
sudo docker exec -it target python3 /root/target_host.py

# 4. Start victim traffic generator (in another terminal)
sudo docker exec -it victim python3 /root/victim_traffic.py

# 5. Launch the ICMP redirect attack (in another terminal)
sudo docker exec -it attacker python3 /root/icmp_redirect_attack.py

# 6. Monitor routing table changes on victim (in another terminal)
sudo docker exec victim ip route
# Before attack: 192.168.60.0/24 via 10.9.0.11 dev eth0
# After attack:  192.168.60.5 via 10.9.0.105 dev eth0  <-- Redirected to attacker!

# 7. Cleanup when done
./cleanup.sh
```

### Manual Step-by-Step Attack

If you want to understand each step:

#### Step 1: Environment Setup
```bash
cd scripts/
./setup.sh
```

#### Step 2: Verify Initial State
```bash
# Check victim's routing table (should route to target via router)
sudo docker exec victim ip route
# Output: 192.168.60.0/24 via 10.9.0.11 dev eth0

# Test normal connectivity
sudo docker exec victim ping -c 2 192.168.60.5
# Should work: packets go victim → router → target
```

#### Step 3: Start Target Service
```bash
# Terminal 1: Start target host service
sudo docker exec -it target python3 /root/target_host.py
# This creates a simple HTTP server on the target
```

#### Step 4: Generate Victim Traffic  
```bash
# Terminal 2: Start victim traffic to monitor network
sudo docker exec -it victim python3 /root/victim_traffic.py
# This generates periodic traffic to the target and shows routing info
```

#### Step 5: Launch Attack
```bash
# Terminal 3: Execute ICMP redirect attack
sudo docker exec -it attacker python3 /root/icmp_redirect_attack.py
# The attacker will:
# 1. Sniff for victim → target traffic
# 2. Send ICMP redirect messages to victim
# 3. Poison victim's routing table
```

#### Step 6: Verify Attack Success
```bash
# Check victim's routing table after attack
sudo docker exec victim ip route
# You should see a new route: 192.168.60.5 via 10.9.0.105 dev eth0
# This means traffic to target now goes through attacker!

# Check victim's ARP table
sudo docker exec victim arp -a
# Should show attacker's MAC for target's IP
```

## Attack Details

The ICMP Redirect attack works as follows:

### Pre-Attack State:
```
Victim (10.9.0.5) → Router (10.9.0.11) → Target (192.168.60.5)
```

### Attack Process:
1. **Traffic Sniffing**: Attacker monitors the internal network (10.9.0.0/24)
2. **Packet Detection**: When victim sends packets to target network, attacker detects them
3. **ICMP Redirect Crafting**: Attacker creates ICMP Type 5 (Redirect) messages
4. **Source Spoofing**: ICMP redirect appears to come from the legitimate router (10.9.0.11)
5. **Route Poisoning**: Victim receives redirect and updates its routing table
6. **Traffic Hijacking**: Future packets to target are routed through attacker

### Post-Attack State:
```
Victim (10.9.0.5) → Attacker (10.9.0.105) → Target (192.168.60.5)
```

### ICMP Redirect Message Structure:
- **Type**: 5 (Redirect)
- **Code**: 1 (Redirect for Host)
- **Gateway**: Attacker's IP (10.9.0.105)
- **Target**: Destination being redirected (192.168.60.5)
- **Original Packet**: Copy of victim's original packet

## Container Architecture

### Network Layout:
- **internal-net** (10.9.0.0/24): Main attack network
  - victim: 10.9.0.5
  - attacker: 10.9.0.105  
  - malicious-router: 10.9.0.111
  - router: 10.9.0.11 (also connected to target-net)

- **target-net** (192.168.60.0/24): Target network
  - target: 192.168.60.5
  - target2: 192.168.60.6
  - router: 192.168.60.11 (dual-homed)

### Container Capabilities:
- **ALL**: --cap-add ALL for raw socket access
- **Privileged**: Required for packet crafting and network manipulation
- **Sysctls**: Custom network configurations (ICMP redirects, IP forwarding)

## Files Structure

```
ICMP-Redirect/
├── scripts/
│   ├── setup.sh                    # Complete environment setup
│   ├── cleanup.sh                  # Environment cleanup
│   └── setup.sh.backup            # Backup of setup script
├── src/
│   ├── icmp_redirect_attack.py     # Main attack script (raw sockets)
│   ├── victim_traffic.py           # Victim traffic generator
│   └── target_host.py              # Target service (HTTP server)
├── docker-compose.yml              # Docker compose reference
└── README.md                       # This file
```

## Monitoring Commands

### Real-time Monitoring:
```bash
# Monitor victim's routing table changes
watch -n 1 'sudo docker exec victim ip route'

# Monitor ICMP redirect messages on victim
sudo docker exec victim tcpdump -i eth0 -n 'icmp[icmptype]==5'

# Monitor all traffic between victim and target
sudo docker exec attacker tcpdump -i eth0 -n 'host 10.9.0.5 and host 192.168.60.5'

# Watch ARP table changes on victim
watch -n 1 'sudo docker exec victim arp -a'
```

### Post-Attack Analysis:
```bash
# Check final routing table
sudo docker exec victim ip route show

# Check ARP table for MAC address changes
sudo docker exec victim arp -a

# Test connectivity (should still work but through attacker)
sudo docker exec victim ping -c 3 192.168.60.5

# Check if attacker can see the traffic
sudo docker exec attacker netstat -i
```

## Security Implications

### What the Attacker Achieves:
1. **Traffic Interception**: All victim→target traffic passes through attacker
2. **Man-in-the-Middle Position**: Can read, modify, or drop packets
3. **Credential Harvesting**: Can capture login credentials if unencrypted
4. **Service Impersonation**: Can respond as the target service
5. **Data Exfiltration**: Can copy sensitive data in transit

### Detection Indicators:
- Unexpected ICMP redirect messages
- Routing table changes without admin intervention
- ARP table inconsistencies
- Performance degradation (extra hop through attacker)
- Network traffic going to unexpected next-hop

## Mitigation Strategies

### System-Level Protection:
```bash
# Disable ICMP redirects (recommended for servers)
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Make permanent in /etc/sysctl.conf:
echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
```

### Network-Level Protection:
1. **Static ARP Entries**: Prevent ARP poisoning
2. **Network Segmentation**: Isolate critical systems
3. **VLANs**: Separate broadcast domains
4. **Switch Port Security**: Limit MAC addresses per port
5. **Monitoring**: Detect unusual ICMP/ARP traffic

### Application-Level Protection:
1. **HTTPS/TLS**: Encrypt application traffic
2. **VPN**: Tunnel traffic securely
3. **Certificate Pinning**: Prevent certificate spoofing
4. **Mutual Authentication**: Verify both client and server

## Troubleshooting

### Container Issues:
```bash
# Check all containers are running
docker ps

# Check setup script logs
./setup.sh

# Restart specific container
docker restart <container_name>

# Access container for debugging
docker exec -it <container_name> bash
```

### Network Issues:
```bash
# Test basic connectivity
docker exec victim ping 10.9.0.11    # Router
docker exec victim ping 192.168.60.5  # Target

# Check routing tables
docker exec victim ip route show
docker exec router ip route show

# Check network interfaces
docker exec victim ip addr show
docker exec router ip addr show
```

### Attack Issues:
```bash
# Verify victim accepts redirects
docker exec victim sysctl net.ipv4.conf.all.accept_redirects

# Check if scripts are present
docker exec attacker ls -la /root/
docker exec victim ls -la /root/
docker exec target ls -la /root/

# Test manual packet generation
docker exec victim ping -c 1 192.168.60.5

# Check Python script syntax
docker exec attacker python3 -m py_compile /root/icmp_redirect_attack.py
```

### Permission Issues:
```bash
# Ensure Docker has sufficient privileges
sudo docker exec attacker id

# Check raw socket capabilities
docker exec attacker python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); print('Raw socket OK')"
```

## Educational Use Only

⚠️ **Important Legal Notice**: This demonstration is for educational and research purposes only.

### Appropriate Use:
- Security education and training
- Penetration testing in controlled environments
- Network security research
- Red team exercises with proper authorization

### Legal Requirements:
- Only use in networks you own or have explicit written permission to test
- Ensure all participants are aware and consent to the testing
- Follow responsible disclosure if vulnerabilities are discovered
- Comply with local laws and regulations regarding network security testing

**Unauthorized network attacks are illegal and may result in criminal charges.**

## Implementation Details

### Raw Socket Programming:
This implementation uses Python's raw socket capabilities to:
- Craft custom ICMP packets without external libraries
- Sniff network traffic at the packet level
- Manipulate packet headers (IP, ICMP)
- Calculate network checksums manually

### No External Dependencies:
The attack scripts use only Python standard library:
- `socket` module for raw packet operations
- `struct` module for binary data packing
- Built-in networking functions for IP operations

### Container Networking:
- Docker bridge networks for isolated environments
- Custom subnet configurations
- Inter-container routing setup
- Network namespace isolation

## Cleanup

### Quick Cleanup:
```bash
./scripts/cleanup.sh
```

### Manual Cleanup:
```bash
# Stop all containers
docker stop victim attacker router target target2 malicious-router

# Remove containers
docker rm victim attacker router target target2 malicious-router

# Remove networks
docker network rm internal-net target-net

# Remove any orphaned resources
docker system prune -f
```

### Verify Cleanup:
```bash
# Should show no demo containers
docker ps -a | grep -E "(victim|attacker|router|target)"

# Should show no demo networks
docker network ls | grep -E "(internal-net|target-net)"
```

## License

This project is for educational use only. Use responsibly and ethically in controlled environments with proper authorization.
