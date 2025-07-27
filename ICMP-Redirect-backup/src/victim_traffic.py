#!/usr/bin/env python3
"""
Victim Traffic Generator
This script generates traffic from the victim to the target server to demonstrate
the ICMP Redirect attack. It continuously sends ping requests to the target.
"""

import socket
import struct
import time
import sys
import os

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
VICTIM_IP = "10.10.1.10"    # Victim's IP (us)
TARGET_IP = "10.10.2.10"    # Target's IP
INTERVAL = 2                # Ping interval in seconds

# ─── PACKET CRAFTING ─────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    """Compute Internet checksum for the data"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_echo_request(seq_num):
    """Create an ICMP Echo Request packet"""
    # ICMP header fields
    icmp_type = 8  # Echo Request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = os.getpid() & 0xFFFF  # Use process ID as identifier
    icmp_seq = seq_num
    
    # Create a basic payload
    payload = b'abcdefghijklmnopqrstuvwxyz'
    
    # Pack the ICMP header
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    
    # Calculate checksum
    icmp_checksum = checksum(icmp_header + payload)
    
    # Pack the header again with the correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    
    # Final packet
    icmp_packet = icmp_header + payload
    
    return icmp_packet

def ping_target(seq_num):
    """Send a ping to the target"""
    try:
        # Create a raw socket for ICMP
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            # Create ICMP packet
            icmp_packet = create_icmp_echo_request(seq_num)
            
            # Send the packet
            s.sendto(icmp_packet, (TARGET_IP, 0))
            
            print(f"🚀 Ping #{seq_num} sent to {TARGET_IP}")
            
            # Try to receive reply with timeout
            s.settimeout(2)
            try:
                data, addr = s.recvfrom(1024)
                print(f"📨 Received reply from {addr[0]}")
            except socket.timeout:
                print(f"⏱️  No reply received (timeout)")
            
    except Exception as e:
        print(f"❌ Failed to send ping: {e}")

def display_routing_info():
    """Display the victim's routing information"""
    print("\n📋 Current Routing Table:")
    os.system("ip route")
    
    print("\n📋 Current ARP Table:")
    os.system("arp -a")

# ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────────
def main():
    """Main function"""
    print("🚀 Victim Traffic Generator")
    print("======================================")
    print(f"Victim IP: {VICTIM_IP}")
    print(f"Target IP: {TARGET_IP}")
    print(f"Ping Interval: {INTERVAL} seconds")
    print("======================================")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root to create raw sockets.")
        sys.exit(1)
    
    # Display initial routing info
    display_routing_info()
    
    print("\n📡 Starting traffic generation...")
    print("Press Ctrl+C to stop")
    
    seq_num = 1
    try:
        while True:
            ping_target(seq_num)
            seq_num += 1
            
            # Show routing table every 5 pings to detect changes
            if seq_num % 5 == 0:
                display_routing_info()
            
            time.sleep(INTERVAL)
            
    except KeyboardInterrupt:
        print("\n🛑 Traffic generation stopped")
        # Show final routing table
        display_routing_info()
        print("👋 Exiting...")

if __name__ == "__main__":
    main()
