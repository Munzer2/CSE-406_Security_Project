# ICMP Redirect Attack Demonstration

This project demonstrates an ICMP redirect attack for educational purposes in a Computer Security course. The implementation uses raw socket programming without relying on prebuilt packet crafting libraries.

## Overview

An ICMP redirect attack is a type of man-in-the-middle attack where an attacker sends forged ICMP redirect messages to a victim, causing the victim to route traffic through the attacker instead of the legitimate gateway. This allows the attacker to intercept, modify, or drop the victim's network traffic.

## Project Structure

```
ICMP-Redirect/
├── src/
│   ├── attacker.py                # Main attack script (runs on attacker)
│   ├── victim.py                  # Victim traffic generator and monitor
│   ├── target.py                  # Target host simulator
│   ├── verify_packets.py          # Packet crafting verification tests
│   └── util.py                    # Common packet crafting utilities
├── scripts/
│   ├── setup_environment.sh           # Docker environment setup script
│   ├── cleanup_docker_environment.sh  # Complete environment cleanup script
│   ├── check_environment.sh           # Environment status checker
│   ├── verify_setup.sh                # Complete setup verification
│   └── demo_attack.sh                 # Automated attack demonstration
└── README.md                          # Complete documentation
```

## Network Topology

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Router    │    │   Victim    │    │   Target    │
│ 10.0.0.1    │    │ 10.0.0.2    │    │ 10.0.0.4    │
│ (Gateway)   │    │ (Victim)    │    │ (Server)    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          │
                 ┌─────────────┐
                 │  Attacker   │
                 │ 10.0.0.3    │
                 │ (Malicious) │
                 └─────────────┘
```

## Technical Implementation

### Raw Packet Crafting

All packets are crafted from scratch using Python's `struct` module:

1. **IPv4 Header Construction**: 20-byte header with proper checksum calculation
2. **ICMP Packet Construction**: Type-specific ICMP packets with correct checksums
3. **ICMP Redirect Format**: Type 5 packets with gateway redirection information

### Attack Flow

1. **Traffic Monitoring**: Attacker sniffs network traffic to detect victim communications
2. **Redirect Generation**: When victim traffic to target is detected, attacker crafts ICMP redirect
3. **Source Spoofing**: Redirect appears to come from legitimate router (10.0.0.1)
4. **Route Poisoning**: Victim updates routing table to use attacker as gateway
5. **Traffic Interception**: Subsequent traffic flows through attacker

## Setup Instructions

### Prerequisites

- Linux system with Docker installed
- Root privileges (required for raw sockets)
- Python 3.6+ with basic networking libraries

### 1. Environment Setup

Make the setup script executable and run it:

```bash
chmod +x scripts/setup_environment.sh
sudo ./scripts/setup_environment.sh
```

This script will:
- Create Docker network with subnet 10.0.0.0/24
- Start four containers (router, victim, attacker, target)
- Install necessary dependencies (Python, Scapy, network tools)
- Ensure proper directory structure in containers
- Copy all Python files (attacker.py, victim.py, target.py, util.py, verify_packets.py) to all containers
- Set executable permissions on Python files
- Configure network settings (IP forwarding, ICMP redirects)
- Verify file copying was successful
- Test basic connectivity

### 2. Verify Environment

Check the status of your environment:

```bash
sudo ./scripts/check_environment.sh
```

Or run a complete setup verification:

```bash
sudo ./scripts/verify_setup.sh
```

The verification script will check:
- Project file structure and syntax
- Script permissions
- Docker availability and container status
- File presence in containers
- Overall setup completeness

This will show you:
- Docker daemon status
- Container status and health
- Network connectivity tests
- Routing table information
- Project file status

You can also manually check that all containers are running:

```bash
sudo docker ps
```

Test network connectivity:

```bash
# Test victim -> target connectivity
sudo docker exec victim ping -c3 10.0.0.4

# Check initial routing table
sudo docker exec victim ip route
```

### 3. File Copying Troubleshooting

The setup script automatically ensures the `/root/` directory exists in all containers and copies all Python files. If files are still missing in containers, you can:

**Check which files are missing:**
```bash
sudo ./scripts/check_environment.sh
```

**Manually verify files in containers:**
```bash
# Check files in a specific container
sudo docker exec victim ls -la /root/*.py

# Check if specific files exist
sudo docker exec victim test -f /root/victim.py && echo "victim.py exists"
sudo docker exec attacker test -f /root/attacker.py && echo "attacker.py exists"
```

**If files are still missing, manually copy them:**
```bash
# Ensure directory exists and copy files
sudo docker exec victim mkdir -p /root
sudo docker cp src/victim.py victim:/root/victim.py
sudo docker cp src/attacker.py attacker:/root/attacker.py
sudo docker cp src/target.py target:/root/target.py
sudo docker cp src/util.py victim:/root/util.py
sudo docker cp src/verify_packets.py attacker:/root/verify_packets.py

# Set executable permissions
sudo docker exec victim chmod +x /root/*.py
sudo docker exec attacker chmod +x /root/*.py
sudo docker exec target chmod +x /root/*.py
```

## Running the Attack

### Terminal 1: Start Target Host

```bash
sudo docker exec -it target python3 /root/target.py
```

This starts a server that responds to ping requests.

### Terminal 2: Start Victim Traffic Generator

```bash
sudo docker exec -it victim python3 /root/victim.py
```

This generates periodic ping traffic from victim to target.

### Terminal 3: Monitor Victim for Redirects

```bash
sudo docker exec -it victim python3 /root/victim.py --monitor
```

This monitors the victim for incoming ICMP redirect messages.

### Terminal 4: Launch Attack

```bash
sudo docker exec -it attacker python3 /root/attacker.py
```

This starts the ICMP redirect attack, monitoring for victim traffic and sending spoofed redirects.

### Terminal 5: Network Monitoring (Optional)

```bash
sudo docker exec -it attacker tcpdump -i eth0 -n icmp
```

This captures ICMP traffic for analysis.

## Attack Verification

### 1. Check Routing Table Changes

Before attack:
```bash
sudo docker exec victim ip route
```

After successful attack:
```bash
sudo docker exec victim ip route
# Should show 10.0.0.3 (attacker) as gateway for 10.0.0.4
```

### 2. Monitor ICMP Redirects

The victim monitor will show received redirect messages:
```
[!] ICMP REDIRECT RECEIVED!
    From: 10.0.0.1
    Type: Redirect for Host
    New Gateway: 10.0.0.3
    Original packet: 10.0.0.2 -> 10.0.0.4
[*] This could be a redirect attack!
```

### 3. Traffic Flow Analysis

Use tcpdump to verify traffic is being redirected through the attacker:
```bash
sudo docker exec attacker tcpdump -i eth0 -n host 10.0.0.2
```

## Manual Testing Options

### Single Ping Test

```bash
sudo docker exec victim python3 /root/victim.py --single
```

### Manual Redirect (Testing)

```bash
sudo docker exec attacker python3 /root/attacker.py --manual
```

### Routing Table Inspection

```bash
sudo docker exec victim python3 /root/victim.py --route
```

## Security Implications

### Attack Capabilities

1. **Traffic Interception**: All victim traffic to target flows through attacker
2. **Data Modification**: Attacker can modify packets in transit
3. **Service Disruption**: Attacker can drop packets, causing denial of service
4. **Information Gathering**: Attacker can analyze victim's communication patterns

### Defense Mechanisms

1. **Disable ICMP Redirects**: 
   ```bash
   echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
   ```

2. **Static Routing**: Use static routes instead of dynamic routing
3. **Network Segmentation**: Limit broadcast domains
4. **Monitoring**: Deploy network monitoring to detect unusual ICMP traffic
5. **Authentication**: Use authenticated routing protocols

## Cleanup

### Automated Cleanup

Use the provided cleanup script to completely remove the experiment environment:

```bash
sudo ./scripts/cleanup_docker_environment.sh
```

This script will:
- Stop and remove all experiment containers
- Remove Docker networks created for the experiment
- Clean up any volumes and temporary files
- Perform Docker system cleanup
- Verify complete removal
- Optionally remove Ubuntu 22.04 base image

### Force Cleanup (Non-interactive)

For automated or scripted cleanup:

```bash
sudo ./scripts/cleanup_docker_environment.sh --force
```

### Complete System Cleanup

For complete Docker system cleanup (removes ALL Docker resources):

```bash
sudo ./scripts/cleanup_docker_environment.sh --all
```

**Warning**: The `--all` flag will remove ALL Docker containers, networks, volumes, and images on your system, not just the experiment resources. Use with caution.

### Manual Cleanup

If you prefer manual cleanup:

```bash
# Stop all containers
sudo docker stop victim router target attacker

# Remove containers
sudo docker rm victim router target attacker

# Remove networks
sudo docker network rm icmp-redirect-net icmpnet

# Optional: Remove Ubuntu base image
sudo docker rmi ubuntu:22.04

# Clean up Docker system
sudo docker system prune -f
```

### Verification

After cleanup, verify everything was removed:

```bash
# Check for remaining containers
sudo docker ps -a | grep -E "(victim|router|target|attacker)"

# Check for remaining networks
sudo docker network ls | grep -E "(icmp|redirect)"

# Check Docker system usage
sudo docker system df
```

## Educational Notes

### Key Learning Points

1. **Raw Socket Programming**: Understanding low-level network programming
2. **Protocol Analysis**: Deep dive into IP and ICMP packet structures
3. **Network Security**: Understanding routing vulnerabilities
4. **Attack Mitigation**: Learning defensive strategies

### Ethical Considerations

- This demonstration is for educational purposes only
- Only use in controlled environments you own
- Never perform attacks on networks without explicit permission
- Understand legal implications of network security testing

### Common Issues and Troubleshooting

1. **Permission Denied**: Ensure running with root privileges
2. **Network Unreachable**: Check Docker network configuration
3. **Containers Not Starting**: Verify Docker daemon is running
4. **Attack Not Working**: Check ICMP redirect acceptance settings

## Further Exploration

### Advanced Scenarios

1. **ARP Spoofing Integration**: Combine with ARP poisoning
2. **SSL/TLS Interception**: Demonstrate HTTPS interception
3. **DNS Redirection**: Redirect DNS queries
4. **Multi-victim Attacks**: Scale attack to multiple victims

### Research Questions

1. How effective are modern OS protections against ICMP redirects?
2. Can this attack be detected using machine learning?
3. What is the performance impact of traffic redirection?
4. How do different network topologies affect attack success?

## References

- RFC 792: Internet Control Message Protocol
- RFC 1122: Requirements for Internet Hosts
- Stevens, W. Richard. "TCP/IP Illustrated, Volume 1"
- Donahue, Gary A. "Network Security Through Data Analysis"

## Quick Usage

To demonstrate the ICMP redirect attack from empty setup:

```bash
# 1. Setup Docker environment
sudo ./scripts/setup_environment.sh

# 2. Run automated attack demonstration  
sudo ./scripts/demo_attack.sh

# 3. Clean up all resources
sudo ./scripts/cleanup_docker_environment.sh
```

---

**Disclaimer**: This project is for educational purposes only. The authors are not responsible for any misuse of this information. Always ensure you have proper authorization before testing network security.
