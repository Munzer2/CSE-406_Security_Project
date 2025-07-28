# ICMP Redirect Attack Lab - Macvlan Implementation

## Overview

This lab demonstrates ICMP redirect attacks in a realistic network environment using Docker's macvlan networking. Unlike traditional bridge networks, macvlan provides true Layer 2 visibility, allowing the attacker to see and intercept traffic between other containers - exactly as would happen on a real shared Ethernet segment.

## Key Improvements in Macvlan Version

### ✅ Realistic Traffic Visibility
- **Traditional Docker bridge**: Acts as a switch, only forwards packets to intended recipients
- **Macvlan network**: All containers share the same L2 segment with unique MAC addresses
- **Attacker benefit**: Can see all traffic in promiscuous mode, just like on real networks

### ✅ Standards-Compliant Attack
- No need for ARP spoofing or artificial traffic generation
- Attacker reacts to real victim traffic as it observes it
- ICMP redirects reference actual packets that were sent
- Modern kernels more likely to accept legitimate-looking redirects

### ✅ Common Packet Crafting Library
- Shared `packet_craft.py` library eliminates code duplication
- Consistent packet structure across all scripts
- Easier to maintain and extend attack techniques

## Network Topology

```
Macvlan Network: 10.9.0.0/24 (shared L2 segment)
├── victim (10.9.0.5)          # Target of ICMP redirect attack
├── attacker (10.9.0.105)      # Performs attack, sees all traffic
├── router (10.9.0.11)         # Legitimate gateway (spoofed source)
├── target (10.9.0.200)        # Primary target server
└── target2 (10.9.0.201)       # Secondary target server
```

All containers share the same Ethernet segment through macvlan, enabling realistic packet sniffing and interception.

## Files Structure

```
ICMP-Redirect/
├── src/
│   ├── packet_craft.py              # Common packet crafting library
│   ├── icmp_redirect_attack.py      # Main attack script
│   ├── victim_traffic.py            # Victim traffic generator
│   └── target_host.py               # Target server simulation
├── scripts/
│   ├── setup.sh                     # Environment setup
│   └── cleanup.sh                   # Environment cleanup
└── README.md                        # This file
```

## Prerequisites

### System Requirements
- Linux host with Docker installed
- Root/sudo privileges (required for macvlan)
- Host network interface for macvlan parent (usually eth0)
- Kernel with macvlan support (most modern Linux systems)

### Potential Limitations
- **VM/Cloud environments**: Some cloud providers restrict macvlan networking
- **Host networking**: Macvlan can affect host network connectivity
- **Interface conflicts**: Cannot have host and containers on same subnet without special setup

## Quick Start

### 1. Setup Environment
```bash
cd ICMP-Redirect/scripts
sudo ./setup.sh
```

The setup script will:
- Auto-detect your host network interface
- Create macvlan network with subnet 10.9.0.0/24
- Launch all containers with proper IP assignments
- Configure network settings for attack success
- Install dependencies and copy scripts

### 2. Start Target Services
```bash
# Terminal 1: Start primary target server
sudo docker exec -it target python3 /root/target_host.py

# Terminal 2: Start secondary target server  
sudo docker exec -it target2 python3 /root/target_host.py
```

### 3. Start Victim Traffic Generation
```bash
# Terminal 3: Generate victim traffic
sudo docker exec -it victim python3 /root/victim_traffic.py
```

### 4. Launch ICMP Redirect Attack
```bash
# Terminal 4: Start the attack
sudo docker exec -it attacker python3 /root/icmp_redirect_attack.py
```

### 5. Monitor Results
```bash
# Watch victim's routing table for changes
watch 'sudo docker exec victim ip route'

# Monitor network traffic
sudo docker exec attacker tcpdump -i eth0 -n host 10.9.0.5
```

## How the Attack Works

### Phase 1: Traffic Observation
1. **Victim generates traffic** to target servers (10.9.0.200, 10.9.0.201)
2. **Attacker interface in promiscuous mode** sees all L2 traffic
3. **Attack script parses packets** and identifies victim→target flows

### Phase 2: ICMP Redirect Injection
1. **Attacker crafts ICMP redirect** using `packet_craft.py` library
2. **Redirect spoofed from router** (10.9.0.11) to victim (10.9.0.5)
3. **Redirect contains original packet** that triggered the response
4. **Victim processes redirect** and updates routing table

### Phase 3: Traffic Interception
1. **Victim's routing table modified** to send traffic via attacker
2. **Subsequent packets flow** through attacker instead of router
3. **Attacker can log, modify, or forward** the intercepted traffic

### Success Indicators
- Victim's routing table shows routes via attacker IP (10.9.0.105)
- Attack script reports successful redirect injection
- Traffic monitoring shows packets flowing through attacker

## Troubleshooting

### Setup Issues

**Macvlan network creation fails:**
```bash
# Check available interfaces
ip link show

# Try with specific interface
HOST_INTERFACE=ens3 sudo ./setup.sh

# Verify Docker macvlan support
docker network ls --filter driver=macvlan
```

**Container networking problems:**
```bash
# Verify containers can communicate
sudo docker exec victim ping 10.9.0.11
sudo docker exec victim ping 10.9.0.200

# Check network configuration
sudo docker exec victim ip addr show
sudo docker exec victim ip route
```

### Attack Issues

**Attacker cannot see traffic:**
```bash
# Verify promiscuous mode
sudo docker exec attacker cat /sys/class/net/eth0/flags
# Should show IFF_PROMISC flag

# Test packet capture
sudo docker exec attacker tcpdump -i eth0 -c 5
```

**ICMP redirects not accepted:**
```bash
# Check victim ICMP redirect settings
sudo docker exec victim sysctl net.ipv4.conf.all.accept_redirects
sudo docker exec victim sysctl net.ipv4.conf.all.secure_redirects

# Enable redirect acceptance
sudo docker exec victim sysctl -w net.ipv4.conf.all.accept_redirects=1
sudo docker exec victim sysctl -w net.ipv4.conf.all.secure_redirects=0
```

**No victim traffic generated:**
```bash
# Manually test connectivity
sudo docker exec victim ping 10.9.0.200

# Check target services
sudo docker exec target netstat -tlnp
```

### Network Analysis

**Monitor all traffic:**
```bash
# On attacker (sees all L2 traffic)
sudo docker exec attacker tcpdump -i eth0 -n

# Specific to victim traffic
sudo docker exec attacker tcpdump -i eth0 -n host 10.9.0.5

# ICMP redirects only
sudo docker exec attacker tcpdump -i eth0 -n 'icmp[icmptype] = 5'
```

**Check routing changes:**
```bash
# Before attack
sudo docker exec victim ip route

# During attack (should show new routes via attacker)
watch 'sudo docker exec victim ip route'

# Verify redirect was processed
sudo docker exec victim ip route get 10.9.0.200
```

## Advanced Usage

### Custom Target Networks
Modify the attack script to target different subnets:
```python
# In icmp_redirect_attack.py
TARGET_NETWORKS = ["192.168.1.0/24", "172.16.0.0/16"]
```

### Multiple Attackers
Launch additional attacker containers:
```bash
sudo docker run -d --name attacker2 \
  --cap-add ALL --privileged \
  --network attack-net --ip 10.9.0.106 \
  ubuntu:22.04 sleep infinity
```

### External Target Simulation
Redirect traffic destined for external networks:
```python
# Target any non-local traffic
if not dst_ip.startswith("10.9.0."):
    send_icmp_redirect(ip_packet, victim_ip)
```

## Security Implications

### Attack Effectiveness
- **Realistic environment**: Macvlan provides authentic L2 behavior
- **Persistent redirects**: Route changes survive until manual removal
- **Difficult detection**: Legitimate-looking ICMP traffic
- **Wide impact**: Can redirect entire subnets

### Defensive Measures
1. **Disable ICMP redirects**: `sysctl -w net.ipv4.conf.all.accept_redirects=0`
2. **Enable secure redirects**: `sysctl -w net.ipv4.conf.all.secure_redirects=1`
3. **Network monitoring**: Detect unusual routing table changes
4. **Static routes**: Use explicit routing instead of dynamic redirects

### Real-World Applicability
This lab demonstrates techniques that work on:
- Traditional Ethernet networks
- Wi-Fi networks with client isolation disabled
- Network segments without proper VLAN isolation
- Legacy networks with permissive ICMP policies

## Cleanup

### Automatic Cleanup
```bash
cd ICMP-Redirect/scripts
sudo ./cleanup.sh
```

### Manual Cleanup
```bash
# Remove containers
sudo docker rm -f victim attacker router target target2

# Remove macvlan network
sudo docker network rm attack-net

# Check for remaining resources
sudo docker ps -a | grep -E '(victim|attacker|router|target)'
sudo docker network ls | grep attack-net
```

### Host Network Reset
If macvlan affects host networking:
```bash
# Reset interface (replace eth0 with your interface)
sudo ip link set eth0 down
sudo ip link set eth0 up

# Or reboot if necessary
sudo reboot
```

## Learning Objectives

After completing this lab, you should understand:

1. **Layer 2 network behavior** and how macvlan provides realistic traffic visibility
2. **ICMP redirect mechanics** and proper packet structure requirements
3. **Raw socket programming** for packet crafting and injection
4. **Network reconnaissance** through passive traffic monitoring
5. **Attack detection** and defensive countermeasures

## Further Reading

- [RFC 792: ICMP Protocol Specification](https://tools.ietf.org/html/rfc792)
- [Docker Macvlan Networking](https://docs.docker.com/network/drivers/macvlan/)
- [Linux Raw Socket Programming](https://man7.org/linux/man-pages/man7/raw.7.html)
- [Network Security Attack Vectors](https://attack.mitre.org/techniques/T1557/)

---

**⚠️ DISCLAIMER**: This lab is for educational and authorized security testing purposes only. Do not use these techniques on networks you do not own or have explicit permission to test.
