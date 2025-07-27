#!/usr/bin/env python3
"""
Target Host Server
This script implements a simple server on the target host that responds to pings
and logs all received traffic to demonstrate ICMP Redirect attack effectiveness.
"""

import socket
import struct
import time
import sys
import os

# ─── CONFIG ─────────────────────────────────────────────────────────────────────
TARGET_IP = "10.10.2.10"    # Target's IP (us)

# ─── PACKET CRAFTING ─────────────────────────────────────────────────────────────
def checksum(data: bytes) -> int:
    """Compute Internet checksum for the data"""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_echo_reply(orig_packet):
    """Create an ICMP Echo Reply packet from an Echo Request packet"""
    # Extract ICMP header from original packet
    icmp_header = orig_packet[20:28]  # IP header is 20 bytes
    
    # Extract payload from original packet
    payload = orig_packet[28:]
    
    # Extract ICMP type, code, checksum, ID, and sequence number
    icmp_type, icmp_code, old_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp_header)
    
    # Change type from 8 (Echo Request) to 0 (Echo Reply)
    icmp_type = 0
    
    # Create a new ICMP header with checksum set to 0
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
    
    # Calculate checksum for the new header + original payload
    icmp_checksum = checksum(icmp_header + payload)
    
    # Create the final header with correct checksum
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    
    # Combine header and payload
    icmp_reply = icmp_header + payload
    
    return icmp_reply

def process_packet(packet, addr):
    """Process a received packet and respond if it's an ICMP Echo Request"""
    # Extract IP header
    ip_header = packet[:20]
    
    # Extract protocol from IP header (offset 9)
    protocol = ip_header[9]
    
    # If ICMP packet (protocol 1)
    if protocol == 1:
        # Extract ICMP header
        icmp_header = packet[20:28]
        
        # Extract ICMP type (first byte)
        icmp_type = icmp_header[0]
        
        # If Echo Request (type 8)
        if icmp_type == 8:
            src_ip = socket.inet_ntoa(ip_header[12:16])
            print(f"📥 Echo Request from {src_ip}")
            
            # Create Echo Reply
            icmp_reply = create_icmp_echo_reply(packet)
            
            return icmp_reply, src_ip
    
    return None, None

# ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────────
def main():
    """Main function"""
    print("🎯 Target Host Server")
    print("======================================")
    print(f"Target IP: {TARGET_IP}")
    print("Responding to all ICMP Echo Requests")
    print("======================================")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This script must be run as root to create raw sockets.")
        sys.exit(1)
    
    try:
        # Create a raw socket to receive all IP packets
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as recv_socket:
            # Create a raw socket to send ICMP replies
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as send_socket:
                
                print("📡 Listening for incoming packets...")
                print("Press Ctrl+C to stop")
                
                while True:
                    # Receive packet
                    packet, addr = recv_socket.recvfrom(1024)
                    
                    # Process packet
                    reply, dst_ip = process_packet(packet, addr)
                    
                    # If reply needed, send it
                    if reply:
                        send_socket.sendto(reply, (dst_ip, 0))
                        print(f"📤 Echo Reply sent to {dst_ip}")
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        print("👋 Exiting...")
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
