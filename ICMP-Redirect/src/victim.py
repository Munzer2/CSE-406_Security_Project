#!/usr/bin/env python3
"""
Victim Traffic Generator for ICMP Redirect Attack Demo
This script simulates a victim generating network traffic that can be redirected.
"""

import socket
import struct
import time
import threading
import sys
from util import PacketCrafter, NetworkConfig, parse_icmp_header, format_ip_address

class VictimTrafficGenerator:
    """Generate victim traffic for demonstration"""
    
    def __init__(self):
        self.packet_crafter = PacketCrafter()
        self.sequence = 1
        
    def send_ping_to_target(self):
        """Send ICMP ping to target host"""
        try:
            # Create ICMP echo request
            payload = b'Hello from victim!'
            icmp_packet = self.packet_crafter.create_icmp_packet(
                NetworkConfig.ICMP_ECHO_REQUEST, 0, 1234, self.sequence, payload
            )
            
            # Create IP header
            ip_header = self.packet_crafter.create_ip_header(
                NetworkConfig.VICTIM_IP, NetworkConfig.TARGET_IP, NetworkConfig.IPPROTO_ICMP, len(icmp_packet)
            )
            
            # Combine packet
            full_packet = ip_header + icmp_packet
            
            # Send packet
            self.packet_crafter.send_raw_packet(full_packet, NetworkConfig.TARGET_IP)
            
            print(f"[+] Sent ping to {NetworkConfig.TARGET_IP} (seq={self.sequence})")
            self.sequence += 1
            
        except Exception as e:
            print(f"[!] Error sending ping: {e}")

    def check_routing_table(self):
        """Check current routing table"""
        try:
            import subprocess
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            print("\n[*] Current routing table:")
            print(result.stdout)
        except Exception as e:
            print(f"[!] Error checking routing table: {e}")

    def monitor_redirects(self):
        """Monitor for ICMP redirects"""
        try:
            # Create raw socket for monitoring
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            print("[*] Monitoring for ICMP redirects...")
            
            while True:
                packet, addr = sock.recvfrom(65535)
                self.process_icmp_packet(packet, addr[0])
                
        except KeyboardInterrupt:
            print("\n[*] Stopped monitoring")
        except Exception as e:
            print(f"[!] Monitoring error: {e}")
        finally:
            sock.close()

    def process_icmp_packet(self, packet, src_ip):
        """Process received ICMP packet"""
        try:
            # Parse ICMP header using utility function
            icmp_info = parse_icmp_header(packet)
            
            if icmp_info['type'] == NetworkConfig.ICMP_REDIRECT:  # ICMP Redirect
                redirect_codes = {
                    NetworkConfig.ICMP_REDIRECT_NET: "Redirect for Network",
                    NetworkConfig.ICMP_REDIRECT_HOST: "Redirect for Host", 
                    NetworkConfig.ICMP_REDIRECT_TOS_NET: "Redirect for Type of Service and Network",
                    NetworkConfig.ICMP_REDIRECT_TOS_HOST: "Redirect for Type of Service and Host"
                }
                
                # Extract gateway address from redirect
                gateway_addr = struct.unpack('!4s', packet[4:8])[0]
                gateway_ip = format_ip_address(gateway_addr)
                
                print(f"\n[!] ICMP REDIRECT RECEIVED!")
                print(f"    From: {src_ip}")
                print(f"    Type: {redirect_codes.get(icmp_info['code'], 'Unknown')}")
                print(f"    New Gateway: {gateway_ip}")
                
                # Show original packet that triggered redirect
                if len(packet) > 8:
                    orig_packet = packet[8:]
                    if len(orig_packet) >= 20:
                        orig_src = format_ip_address(orig_packet[12:16])
                        orig_dst = format_ip_address(orig_packet[16:20])
                        print(f"    Original packet: {orig_src} -> {orig_dst}")
                
                print("[*] This could be a redirect attack!")
                
        except Exception as e:
            print(f"[!] Error processing ICMP packet: {e}")

    def generate_continuous_traffic(self, interval=3):
        """Generate continuous traffic to target"""
        print(f"[*] Generating traffic to {NetworkConfig.TARGET_IP} every {interval} seconds")
        print("[*] Press Ctrl+C to stop")
        
        try:
            while True:
                self.send_ping_to_target()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Stopped traffic generation")

def main():
    """Main function"""
    victim = VictimTrafficGenerator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--monitor":
            victim.monitor_redirects()
        elif sys.argv[1] == "--route":
            victim.check_routing_table()
        elif sys.argv[1] == "--single":
            victim.send_ping_to_target()
        elif sys.argv[1] == "--help":
            print("Usage:")
            print("  python3 victim_traffic.py              # Generate continuous traffic")
            print("  python3 victim_traffic.py --monitor    # Monitor for ICMP redirects")
            print("  python3 victim_traffic.py --route      # Show routing table")
            print("  python3 victim_traffic.py --single     # Send single ping")
        else:
            print("Unknown option. Use --help for usage.")
    else:
        # Default: generate continuous traffic
        victim.generate_continuous_traffic()

if __name__ == "__main__":
    main()
