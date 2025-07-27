#!/usr/bin/env python3
"""
Target Host Script
Simple target host that responds to pings
"""

import socket
import sys
import os
from util import PacketCrafter, NetworkConfig, parse_ip_header, parse_icmp_header

class TargetHost:
    def __init__(self):
        """Initialize target host"""
        self.target_ip = "10.10.2.10"
        self.running = True
        
        print(f"[*] Target Host initialized")
        print(f"    Target IP: {self.target_ip}")
        print(f"[*] Listening for incoming packets...")
        
    def listen_for_packets(self):
        """Listen for incoming packets and respond to pings"""
        try:
            # Create raw socket for listening
            listen_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            listen_socket.bind(("eth0", 0))
            
            print(f"[*] Listening for packets on eth0...")
            
            while self.running:
                try:
                    packet_data, addr = listen_socket.recvfrom(65536)
                    
                    # Parse Ethernet frame (skip 14 bytes for Ethernet header)
                    if len(packet_data) < 14:
                        continue
                        
                    eth_type = struct.unpack('!H', packet_data[12:14])[0]
                    
                    # Check if it's an IP packet (0x0800)
                    if eth_type == 0x0800:
                        ip_packet = packet_data[14:]  # Skip Ethernet header
                        self.handle_ip_packet(ip_packet)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Packet handling error: {e}")
                    
        except Exception as e:
            print(f"[!] Failed to listen for packets: {e}")
            
    def handle_ip_packet(self, ip_packet):
        """Handle incoming IP packets"""
        try:
            if len(ip_packet) < 20:
                return
                
            # Parse IP header
            ip_header = parse_ip_header(ip_packet)
            
            # Check if this packet is for us
            if ip_header['destination_ip'] == self.target_ip:
                print(f"[*] Received packet from {ip_header['source_ip']}")
                
                # Check if it's ICMP
                if ip_header['protocol'] == NetworkConfig.IPPROTO_ICMP:
                    icmp_data = ip_packet[ip_header['header_length']:]
                    self.handle_icmp_packet(ip_header['source_ip'], icmp_data)
                    
        except Exception as e:
            print(f"[!] IP packet processing error: {e}")
            
    def handle_icmp_packet(self, source_ip, icmp_data):
        """Handle ICMP packets (respond to pings)"""
        try:
            if len(icmp_data) < 8:
                return
                
            # Parse ICMP header
            icmp_header = parse_icmp_header(icmp_data)
            
            # Respond to ping requests
            if icmp_header['type'] == NetworkConfig.ICMP_ECHO_REQUEST:
                print(f"[*] Ping request from {source_ip}, sending reply...")
                
                # Create ICMP echo reply
                reply_icmp = PacketCrafter.create_icmp_packet(
                    packet_type=NetworkConfig.ICMP_ECHO_REPLY,
                    code=0,
                    identifier=icmp_header['identifier'],
                    sequence=icmp_header['sequence'],
                    payload=icmp_header['payload']
                )
                
                # Create IP header for reply
                reply_ip_header = PacketCrafter.create_ip_header(
                    src_ip=self.target_ip,
                    dst_ip=source_ip,
                    protocol=NetworkConfig.IPPROTO_ICMP,
                    payload_length=len(reply_icmp)
                )
                
                # Send reply
                reply_packet = reply_ip_header + reply_icmp
                PacketCrafter.send_raw_packet(reply_packet, source_ip)
                print(f"[*] Ping reply sent to {source_ip}")
                
        except Exception as e:
            print(f"[!] ICMP packet processing error: {e}")
            
    def stop(self):
        """Stop the target host"""
        self.running = False
        print(f"[*] Target host stopped")

def main():
    """Main function"""
    print("="*40)
    print("TARGET HOST")
    print("Responds to ping requests")
    print("="*40)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges")
        print("[!] Run with: sudo python3 target.py")
        sys.exit(1)
        
    target = TargetHost()
    
    import signal
    def signal_handler(sig, frame):
        print(f"\n[*] Received shutdown signal...")
        target.stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        target.listen_for_packets()
    except KeyboardInterrupt:
        print(f"\n[*] Target host interrupted")
    except Exception as e:
        print(f"[!] Target host error: {e}")
    finally:
        target.stop()

if __name__ == "__main__":
    import struct
    main()
