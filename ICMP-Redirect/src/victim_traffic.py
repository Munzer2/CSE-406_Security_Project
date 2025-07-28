#!/usr/bin/env python3
"""
Victim Traffic Generator - Macvlan Implementation
================================================
This script generates realistic victim traffic that can be observed and
redirected by the attacker in a macvlan environment.

Features:
- Uses common packet_craft.py library
- Generates various types of traffic to target servers
- Realistic timing and patterns
- Easy to observe in macvlan L2 environment
"""

import sys
import time
import threading
import signal
import subprocess
import atexit
from packet_craft import *

# ═══════════════════════════════════════════════════════════════════════════════════
# TRAFFIC CONFIGURATION  
# ═══════════════════════════════════════════════════════════════════════════════════

# Network addresses (matching macvlan setup)
VICTIM_IP = "10.9.0.5"      # Our IP (victim)
TARGET_IP = "10.9.0.200"    # Primary target server
TARGET2_IP = "10.9.0.201"   # Secondary target server  
ROUTER_IP = "10.9.0.11"     # Gateway router

# Traffic patterns
PING_INTERVAL = 3            # Seconds between pings
EXTERNAL_TARGETS = ["8.8.8.8", "1.1.1.1"]  # External IPs to trigger redirects

# ═══════════════════════════════════════════════════════════════════════════════════
# GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════════════

traffic_active = True
packets_sent = 0

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global traffic_active
    print(f"\n🛑 Traffic generation stopped by user")
    traffic_active = False
    sys.exit(0)

def cleanup():
    """Cleanup function called on exit"""
    global packets_sent
    print(f"\n📊 Traffic Summary:")
    print(f"   📤 Total packets sent: {packets_sent}")
    print(f"   🎯 Check attacker logs for intercepted traffic")

def send_ping(destination, identifier=None, sequence=None):
    """
    Send ICMP ping to destination
    
    Args:
        destination: Target IP address
        identifier: ICMP identifier (default random)
        sequence: ICMP sequence (default random)
        
    Returns:
        True if ping was sent successfully
    """
    global packets_sent
    
    try:
        # Create ping packet
        ping_packet = create_ping_packet(VICTIM_IP, destination, identifier, sequence)
        
        # Send the packet
        if send_packet(ping_packet, destination):
            packets_sent += 1
            print(f"📤 PING sent to {destination} (ID: {identifier or 'auto'}, Seq: {sequence or 'auto'})")
            return True
        else:
            print(f"❌ Failed to send ping to {destination}")
            return False
            
    except Exception as e:
        print(f"❌ Error sending ping: {e}")
        return False

def generate_internal_traffic():
    """Generate ping traffic to internal target servers"""
    
    targets = [TARGET_IP, TARGET2_IP]
    sequence = 1
    
    while traffic_active:
        for target in targets:
            if not traffic_active:
                break
                
            print(f"\n🎯 Generating ping to internal target: {target}")
            
            # Send ping
            send_ping(target, identifier=12345, sequence=sequence)
            sequence += 1
            
            time.sleep(PING_INTERVAL)

def generate_external_traffic():
    """Generate ping traffic to external targets (should trigger redirects)"""
    
    sequence = 1000
    
    while traffic_active:
        for target in EXTERNAL_TARGETS:
            if not traffic_active:
                break
                
            print(f"\n🌐 Generating ping to external target: {target}")
            
            # Send ping to external target
            send_ping(target, identifier=54321, sequence=sequence)
            sequence += 1
            
            time.sleep(PING_INTERVAL * 2)

def monitor_routing_changes():
    """Monitor our own routing table for changes"""
    
    print(f"📊 Starting routing monitor...")
    last_routes = ""
    
    while traffic_active:
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            current_routes = result.stdout.strip()
            
            if current_routes != last_routes:
                print(f"\n📋 Routing table changed:")
                for line in current_routes.split('\n'):
                    if line.strip():
                        print(f"   {line}")
                print("")
                last_routes = current_routes
                
            time.sleep(5)
            
        except Exception as e:
            if traffic_active:
                print(f"⚠️  Error monitoring routing: {e}")
            break

def main():
    """Main traffic generation function"""
    global traffic_active
    
    print("🚦 Victim Traffic Generator - Macvlan Version")
    print("==============================================")
    print(f"👤 Victim: {VICTIM_IP} (us)")
    print(f"🎯 Internal Targets: {TARGET_IP}, {TARGET2_IP}")
    print(f"🌐 External Targets: {', '.join(EXTERNAL_TARGETS)}")
    print(f"🌐 Router: {ROUTER_IP}")
    print("==============================================")
    
    # Register cleanup and signal handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"\n📊 Traffic Configuration:")
    print(f"   Ping interval: {PING_INTERVAL}s")
    print(f"   Traffic type: ICMP ping (sufficient for ICMP redirect)")
    
    print(f"\n💡 Instructions:")
    print(f"   1. This script generates victim ping traffic (sufficient for ICMP redirect)")
    print(f"   2. Start attacker: docker exec attacker python3 /root/icmp_redirect_attack.py")
    print(f"   3. Monitor routing changes: watch 'ip route'")
    print(f"   4. ICMP redirects work on ANY IP traffic, not just ICMP")
    print(f"   5. Stop with Ctrl+C")
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitor_routing_changes, daemon=True)
    monitor_thread.start()
    
    # Start traffic generation threads
    internal_thread = threading.Thread(target=generate_internal_traffic, daemon=True)
    external_thread = threading.Thread(target=generate_external_traffic, daemon=True)
    
    print(f"\n🎬 Starting traffic generation...")
    print(f"📡 Monitor traffic with: docker exec attacker tcpdump -i eth1 -n host {VICTIM_IP}")
    print("")
    
    try:
        internal_thread.start()
        time.sleep(2)  # Stagger start times
        external_thread.start()
        
        # Keep main thread alive
        while traffic_active:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Traffic generation stopped by user")
    except Exception as e:
        print(f"\n❌ Traffic generation failed: {e}")
    finally:
        traffic_active = False
        
    print(f"\n✅ Traffic generation completed")

if __name__ == "__main__":
    main()
