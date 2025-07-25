#!/usr/bin/env python3
"""
Target Host Simulator for ICMP Redirect Attack Demo
This script simulates a target host that responds to victim's traffic.
"""

import socket
import struct
import threading
import time
import sys
from util import PacketCrafter, NetworkConfig, parse_icmp_header

class TargetHostSimulator:
    """Simulate target host that responds to victim"""
    
    def __init__(self):
        self.packet_crafter = PacketCrafter()
        self.running = False
        
    def listen_for_pings(self):
        """Listen for incoming ICMP echo requests"""
        try:
            # Create raw socket for receiving ICMP
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.bind((NetworkConfig.TARGET_IP, 0))
            
            print(f"[*] Target host listening on {NetworkConfig.TARGET_IP}")
            print("[*] Waiting for ping requests...")
            
            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)
                    self.process_icmp_request(packet, addr[0])
                except socket.timeout:
                    continue
                    
        except Exception as e:
            print(f"[!] Error listening for pings: {e}")
        finally:
            sock.close()

    def process_icmp_request(self, packet, src_ip):
        """Process incoming ICMP request and send reply"""
        try:
            # Parse ICMP header using utility function
            icmp_info = parse_icmp_header(packet)
            
            if icmp_info['type'] == NetworkConfig.ICMP_ECHO_REQUEST:  # Echo Request
                payload = icmp_info['payload']
                
                print(f"[+] Received ping from {src_ip} (id={icmp_info['identifier']}, seq={icmp_info['sequence']})")
                
                # Send echo reply
                self.send_ping_reply(src_ip, icmp_info['identifier'], icmp_info['sequence'], payload)
                
        except Exception as e:
            print(f"[!] Error processing ICMP request: {e}")

    def send_ping_reply(self, dst_ip, identifier, sequence, original_payload):
        """Send ICMP echo reply"""
        try:
            # Create ICMP echo reply
            icmp_packet = self.packet_crafter.create_icmp_packet(
                NetworkConfig.ICMP_ECHO_REPLY, 0, identifier, sequence, original_payload
            )
            
            # Create IP header
            ip_header = self.packet_crafter.create_ip_header(
                NetworkConfig.TARGET_IP, dst_ip, NetworkConfig.IPPROTO_ICMP, len(icmp_packet), identification=54321
            )
            
            # Combine packet
            full_packet = ip_header + icmp_packet
            
            # Send reply
            self.packet_crafter.send_raw_packet(full_packet, dst_ip)
            
            print(f"[+] Sent ping reply to {dst_ip} (id={identifier}, seq={sequence})")
            
        except Exception as e:
            print(f"[!] Error sending ping reply: {e}")

    def start_server(self):
        """Start the target host server"""
        print("="*50)
        print("Target Host Simulator")
        print("="*50)
        print(f"Target IP: {NetworkConfig.TARGET_IP}")
        print("="*50)
        
        self.running = True
        
        # Start listening in separate thread
        listener_thread = threading.Thread(target=self.listen_for_pings)
        listener_thread.daemon = True
        listener_thread.start()
        
        try:
            print("[*] Server started. Press Ctrl+C to stop...")
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping server...")
            self.running = False

def main():
    """Main function"""
    target = TargetHostSimulator()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage:")
        print("  python3 target_host.py    # Start target host server")
    else:
        target.start_server()

if __name__ == "__main__":
    main()
