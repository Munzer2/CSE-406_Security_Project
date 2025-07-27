# ICMP Redirect Attack Demo

This repository demonstrates an ICMP Redirect attack using Docker containers and custom Python scripts. The attacker sniffs traffic between a victim and a target, then sends ICMP redirect messages to poison the victim's routing table.

## Network Topology

```
                              ICMP Redirect Attack Topology
                              ══════════════════════════════

    Network: shared-net                      Network: target-net
    Subnet: 10.10.1.0/24                    Subnet: 10.10.2.0/24
    ┌─────────────────────┐                 ┌─────────────────────┐
    │                     │                 │                     │
    │                     │                 │                     │
    │  ┌─────────────┐    │                 │    ┌─────────────┐  │
    │  │   VICTIM    │    │                 │    │   TARGET    │  │
    │  │  (victim)   │    │                 │    │  (target)   │  │
    │  │             │    │                 │    │             │  │
    │  │ 10.10.1.10  │    │                 │    │ 10.10.2.10  │  │
    │  └─────┬───────┘    │                 │    └─────┬───────┘  │
    │        │            │                 │          │          │
    │        │ eth0       │                 │          │ eth0     │
    │        │            │                 │          │          │
    │   ─────┼────────    │                 │     ─────┼────────  │
    │        │            │                 │          │          │
    │        │            │                 │          │          │
    └────────┼────────────┘                 └──────────┼──────────┘
             │                                         │
             │                                         │
             │                                         │
          ┌──▼──┐                                   ┌──▼──┐
          │eth0 │                                   │eth0 │
          └──┬──┘                                   └──┬──┘
             │                                         │
       ┌─────▼─────────────┐               ┌───────────▼───────────┐
       │     ATTACKER      │               │         ROUTER        │
       │    (attacker)     │               │        (router)       │
       │                   │               │                       │
       │    10.10.1.20     │               │  10.10.1.1 (eth0)     │
       │                   │               │  10.10.2.1 (eth1)     │
       └───────────────────┘               └───────────────────────┘
    
    ═══════════════════════════════════════════════════════════════════
    
    📡 Attack Flow:
    ──────────────
    1. Victim sends packets to Target (10.10.2.10) via Router (10.10.1.1)
    2. Attacker sniffs victim traffic on shared network
    3. Attacker sends ICMP redirect to victim, pretending to be Router
    4. Victim updates routing table to use Attacker as gateway for Target
    5. Future packets to Target go through Attacker (MITM position)
    
    🔧 Key Configuration:
    ────────────────────
    • Victim routes to target network (10.10.2.0/24) via Router (10.10.1.1)
    • Victim has ICMP redirects enabled (required for attack)
    • Router has IP forwarding enabled to route traffic
    • Attacker has IP forwarding + packet capturing capabilities
```

## Prerequisites

* Docker
* Python 3

## Quick Start

This repository includes automation scripts for easy setup and execution:

### Available Scripts

| Script | Purpose | Description |
|--------|---------|-------------|
| `setup.sh` | Environment Setup | Creates networks, containers, installs dependencies, configures routing |
| `cleanup.sh` | Environment Cleanup | Removes all containers and networks |

### Demo Steps

```bash
# 1. Setup the environment
./scripts/setup.sh

# 2. Start the target server (in a new terminal)
sudo docker exec -it target python3 /root/target_host.py

# 3. Start the victim traffic (in another terminal)
sudo docker exec -it victim python3 /root/victim_traffic.py

# 4. Launch the attack (in another terminal)
sudo docker exec -it attacker python3 /root/icmp_redirect_attack.py

# 5. Check routing table changes on victim
sudo docker exec victim ip route

# 6. Cleanup when done
./scripts/cleanup.sh
```

## Attack Details

The ICMP Redirect attack works as follows:

1. The victim normally sends traffic to the target via the router
2. The attacker sniffs the victim's traffic on the shared network
3. The attacker crafts ICMP redirect messages that appear to come from the router
4. These messages tell the victim "use me (attacker) as a better route to the target"
5. The victim updates its routing table, redirecting traffic through the attacker
6. The attacker can now intercept, modify, or just monitor all traffic

## Implementation

This demo uses raw sockets to:

1. Sniff packets on the network
2. Craft custom ICMP redirect messages
3. Monitor victim's routing table changes

The attack does not use Scapy or other external libraries - all packet crafting is done manually with Python's socket module.

## Monitoring Commands

```bash
# Check victim's routing table (before and after attack)
sudo docker exec victim ip route

# Monitor ICMP redirect messages on victim
sudo docker exec victim tcpdump -i eth0 icmp[icmptype]==5

# Watch all traffic between victim and target
sudo docker exec attacker tcpdump -i eth0 host 10.10.1.10 and host 10.10.2.10
```

## Cleanup

```bash
./scripts/cleanup.sh
```

*End of README.md*
   - ICMP redirect tells victim: "Use attacker as gateway for external server"

3. **Post-Attack**:
   ```
   Victim -> Attacker -> External Server
   ```

## Quick Start

### 1. Setup Environment
```bash
cd scripts/
sudo ./setup_environment.sh
```

### 2. Verify Setup
```bash
# Test normal connectivity
docker exec victim ping -c 3 10.0.0.100

# Check routing tables
docker exec victim ip route show
docker exec attacker ip route show
```

### 3. Run Attack Demo
```bash
sudo ./demo_attack.sh
```

### 4. Manual Attack Steps

#### Terminal 1 - Monitor victim traffic
```bash
docker exec -it victim bash
tcpdump -i eth0 -n icmp
```

#### Terminal 2 - Run attacker
```bash
docker exec -it attacker bash
python3 /root/attacker.py
```

#### Terminal 3 - Generate victim traffic
```bash
docker exec -it victim bash
python3 /root/victim.py
# or simply:
ping 10.0.0.100
```

### 5. Observe Results
- Check victim's routing table: `docker exec victim ip route show`
- Check victim's ARP table: `docker exec victim arp -a`
- Monitor traffic flow changes

## Files Structure

```
ICMP-Redirect/
├── scripts/
│   ├── setup_environment.sh        # 3-container setup script
│   ├── demo_attack.sh              # Automated demo
│   └── cleanup_docker_environment.sh # Cleanup script
├── src/
│   ├── attacker.py                 # ICMP redirect attacker
│   ├── victim.py                   # Victim traffic generator
│   └── util.py                     # Utility functions
└── README.md                       # This file
```

## Technical Details

### ICMP Redirect Message
- **Type**: 5 (Redirect)
- **Code**: 1 (Redirect for Host)
- **Gateway**: Attacker's IP (192.168.1.20)
- **Original Packet**: Copy of victim's original packet

### Network Configuration
- **Internal Network**: 192.168.1.0/24
- **External Network**: 10.0.0.0/24
- **Router**: Dual-homed with NAT/forwarding enabled
- **All containers**: NET_RAW and NET_ADMIN capabilities

### Security Implications
1. **Traffic Interception**: Attacker can see victim's traffic
2. **Man-in-the-Middle**: Attacker can modify traffic
3. **Traffic Analysis**: Attacker can analyze communication patterns
4. **Service Disruption**: Attacker can drop or delay traffic

## Mitigation Strategies

1. **Disable ICMP Redirects**:
   ```bash
   sysctl -w net.ipv4.conf.all.accept_redirects=0
   sysctl -w net.ipv4.conf.all.send_redirects=0
   ```

2. **Static ARP Entries**: Prevent ARP poisoning
3. **Network Segmentation**: Isolate critical systems
4. **Monitoring**: Detect unusual ICMP traffic
5. **Secure Routing Protocols**: Use authenticated routing

## Troubleshooting

### Container Issues
```bash
# Check container status
docker ps -a

# Check logs
docker logs <container_name>

# Access container
docker exec -it <container_name> bash
```

### Network Issues
```bash
# Check network connectivity
docker exec victim ping 192.168.1.1  # Router
docker exec victim ping 10.0.0.100   # External server

# Check routing
docker exec victim ip route show
docker exec router ip route show

# Check iptables (in router)
docker exec router iptables -L -n -v
docker exec router iptables -t nat -L -n -v
```

### Attack Issues
```bash
# Check if scapy is installed
docker exec attacker python3 -c "import scapy; print('OK')"

# Check if scripts are present
docker exec attacker ls -la /root/

# Test manual ping
docker exec victim ping -c 1 10.0.0.100
```

## Cleanup

```bash
# Clean up everything
sudo ./cleanup_docker_environment.sh --force

# Or manual cleanup
docker stop victim router attacker external-server
docker rm victim router attacker external-server
docker network rm internal-net external-net
```

## Educational Use

This demonstration is for educational purposes only. It shows:
- How ICMP redirect attacks work
- Network routing manipulation
- Traffic interception techniques
- Docker networking concepts
- Security monitoring and detection

**Warning**: Only use in controlled environments for learning purposes. Unauthorized network attacks are illegal.

## Dependencies

- Docker
- Python 3
- Scapy (installed automatically in containers)
- iptables (installed automatically in containers)
- Standard Linux networking tools

## License

This project is for educational use only. Use responsibly and only in environments you own or have explicit permission to test.
