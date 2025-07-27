#!/usr/bin/env python3
"""
Victim Traffic Generator  
Generates traffic to target host for ICMP redirect attack demonstration
Uses custom packet crafting (util.py) instead of Scapy
"""

import socket
import time
import sys
import os
from util import PacketCrafter, NetworkConfig

class VictimTrafficGenerator:
    def __init__(self):
        """Initialize victim traffic generator"""
        self.victim_ip = "10.10.1.10"     # This victim container
        self.target_ip = "10.10.2.10"     # Target to communicate with
        self.router_ip = "10.10.1.1"      # Default gateway
        
        self.packets_sent = 0
        
        print(f"[*] Victim Traffic Generator initialized")
        print(f"    Victim IP: {self.victim_ip}")
        print(f"    Target IP: {self.target_ip}")
        print(f"    Router IP: {self.router_ip}")
        
    def send_ping_to_target(self):
        """Send ICMP ping to target (generates traffic for attacker to sniff)"""
        try:
            print(f"[*] Sending ping to target {self.target_ip}...")
            
            # Create ICMP echo request
            icmp_packet = PacketCrafter.create_icmp_packet(
                packet_type=NetworkConfig.ICMP_ECHO_REQUEST,  # Echo Request
                code=0,
                identifier=os.getpid() & 0xFFFF,
                sequence=self.packets_sent,
                payload=b"Hello from victim - attack me!"
            )
            
            # Create IP header
            ip_header = PacketCrafter.create_ip_header(
                src_ip=self.victim_ip,
                dst_ip=self.target_ip,
                protocol=NetworkConfig.IPPROTO_ICMP,
                payload_length=len(icmp_packet)
            )
            
            # Combine packet
            ping_packet = ip_header + icmp_packet
            
            # Send packet
            PacketCrafter.send_raw_packet(ping_packet, self.target_ip)
            
            self.packets_sent += 1
            print(f"[*] Ping sent to {self.target_ip} (packet #{self.packets_sent})")
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to send ping: {e}")
            return False
            
    def send_continuous_traffic(self, interval=2):
        """Send continuous traffic to target"""
        print(f"[*] Starting continuous traffic to {self.target_ip}")
        print(f"[*] Interval: {interval} seconds")
        print(f"[*] Press Ctrl+C to stop")
        
        try:
            while True:
                self.send_ping_to_target()
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n[*] Traffic generation stopped")
            print(f"[*] Total packets sent: {self.packets_sent}")
            
    def check_routing_table(self):
        """Check current routing table"""
        print(f"\n[*] Current routing table:")
        os.system("ip route")
        
        print(f"\n[*] ARP table:")
        os.system("arp -a")
        
def main():
    """Main function"""
    print("="*50)
    print("VICTIM TRAFFIC GENERATOR")
    print("Generates traffic for ICMP redirect attack demo")
    print("="*50)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for raw sockets")
        print("[!] Run with: sudo python3 victim.py")
        sys.exit(1)
        
    victim = VictimTrafficGenerator()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--single":
            # Send single ping
            victim.send_ping_to_target()
        elif sys.argv[1] == "--routes":
            # Show routing table
            victim.check_routing_table()
        elif sys.argv[1] == "--help":
            print("Usage:")
            print("  python3 victim.py              - Send continuous traffic")
            print("  python3 victim.py --single     - Send single ping")
            print("  python3 victim.py --routes     - Show routing table")
            print("  python3 victim.py --help       - Show this help")
    else:
        # Default: continuous traffic
        victim.send_continuous_traffic()

if __name__ == "__main__":
    main()
