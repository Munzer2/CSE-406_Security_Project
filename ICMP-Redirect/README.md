# ICMP Redirect Attack Demonstration

## Overview

This project demonstrates an ICMP Redirect attack using a simplified 3-container Docker environment. The attack shows how a malicious actor can redirect network traffic through their machine by sending forged ICMP redirect messages.

## Architecture

### Network Topology
```
Internal Network (192.168.1.0/24)    Router    External Network (10.0.0.0/24)
       |                                |                      |
   Victim (192.168.1.10)               |              External Server (10.0.0.100)
   Attacker (192.168.1.20)             |
                            Router (192.168.1.1 <-> 10.0.0.1)
```

### Container Roles

1. **Victim (192.168.1.10)**: 
   - Target of the attack
   - Sends traffic to external destinations via router
   - Will be redirected to route traffic through attacker

2. **Attacker (192.168.1.20)**:
   - On same network as victim
   - Monitors victim's traffic
   - Sends ICMP redirect messages to victim
   - Intercepts and forwards victim's traffic

3. **Router (192.168.1.1 / 10.0.0.1)**:
   - Dual-homed router connecting internal and external networks
   - Normal gateway for victim and attacker
   - Target of impersonation in the attack

4. **External Server (10.0.0.100)**:
   - Simulates internet destination
   - Target of victim's communications
   - Shows the traffic flow changes

## Attack Flow

1. **Normal Operation**: 
   ```
   Victim -> Router -> External Server
   ```

2. **Attack Phase**:
   - Attacker monitors victim's traffic to external destinations
   - When traffic is detected, attacker sends ICMP redirect message
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
