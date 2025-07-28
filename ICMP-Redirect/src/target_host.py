#!/usr/bin/env python3
"""
Target Host Server - Macvlan Implementation
==========================================
This script runs simple services on target hosts to make them
appear as legitimate destinations for victim traffic.

Features:
- HTTP server simulation
- DNS server simulation  
- ICMP responder
- Traffic logging
"""

import sys
import time
import threading
import signal
import atexit
import subprocess
import socketserver
import http.server
from packet_craft import *

# ═══════════════════════════════════════════════════════════════════════════════════
# SERVER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════════

# Network Configuration
MY_IP = "10.9.0.200"  # Default - will be auto-detected
HTTP_PORT = 80
DNS_PORT = 53

# Service flags
services_active = True
connections_received = 0

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    global services_active
    print(f"\n🛑 Target server stopped by user")
    services_active = False
    sys.exit(0)

def cleanup():
    """Cleanup function called on exit"""
    global connections_received
    print(f"\n📊 Server Summary:")
    print(f"   📥 Total connections received: {connections_received}")

def detect_my_ip():
    """Auto-detect container's IP address"""
    try:
        result = subprocess.run(['ip', 'route', 'get', '1'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'src' in line:
                # Extract IP from line like "1.0.0.0 via 10.9.0.1 dev eth1 src 10.9.0.200"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'src' and i + 1 < len(parts):
                        return parts[i + 1]
    except:
        pass
    
    # Fallback method
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        ip = result.stdout.strip().split()[0]
        if ip and not ip.startswith('127.'):
            return ip
    except:
        pass
        
    return MY_IP  # Default fallback

class CustomHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler that logs requests"""
    
    def do_GET(self):
        global connections_received
        connections_received += 1
        client_ip = self.client_address[0]
        print(f"📥 HTTP GET request from {client_ip}: {self.path}")
        
        # Send a simple response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = f"""
        <html>
        <head><title>Target Server {MY_IP}</title></head>
        <body>
        <h1>Target Server Active</h1>
        <p>This is target server {MY_IP}</p>
        <p>Request from: {client_ip}</p>
        <p>Path: {self.path}</p>
        <p>Time: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </body>
        </html>
        """
        self.wfile.write(response.encode())
    
    def do_POST(self):
        global connections_received
        connections_received += 1
        client_ip = self.client_address[0]
        print(f"📥 HTTP POST request from {client_ip}: {self.path}")
        self.do_GET()  # Same response for now
    
    def log_message(self, format, *args):
        # Suppress default logging to reduce noise
        pass

def run_http_server():
    """Run simple HTTP server"""
    try:
        with socketserver.TCPServer(("", HTTP_PORT), CustomHTTPHandler) as httpd:
            print(f"🌐 HTTP server started on {MY_IP}:{HTTP_PORT}")
            while services_active:
                httpd.timeout = 1
                httpd.handle_request()
    except Exception as e:
        print(f"⚠️  HTTP server error: {e}")

def run_dns_server():
    """Run simple DNS responder (UDP)"""
    global connections_received
    
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', DNS_PORT))
        sock.settimeout(1.0)
        
        print(f"📡 DNS server started on {MY_IP}:{DNS_PORT}")
        
        while services_active:
            try:
                data, addr = sock.recvfrom(1024)
                connections_received += 1
                print(f"📥 DNS query from {addr[0]}:{addr[1]} ({len(data)} bytes)")
                
                # Send a simple DNS response (not a real DNS packet, just acknowledgment)
                response = b"DNS response from target server"
                sock.sendto(response, addr)
                
            except socket.timeout:
                continue
            except Exception as e:
                if services_active:
                    print(f"⚠️  DNS server error: {e}")
                break
                
    except Exception as e:
        print(f"⚠️  Failed to start DNS server: {e}")

def run_ping_responder():
    """Respond to ICMP pings automatically (system handles this)"""
    print(f"🏓 ICMP ping responder active (automatic)")
    
    # Just monitor ping traffic for logging
    while services_active:
        try:
            # Use tcpdump to monitor incoming pings
            result = subprocess.run([
                'timeout', '5', 'tcpdump', '-c', '1', '-n', '-i', 'eth1', 'icmp and dst', MY_IP
            ], capture_output=True, text=True)
            
            if result.stdout and 'ICMP echo request' in result.stdout:
                # Extract source IP from tcpdump output
                for line in result.stdout.split('\n'):
                    if 'ICMP echo request' in line:
                        parts = line.split()
                        if len(parts) > 2:
                            src_ip = parts[2]
                            print(f"🏓 PING received from {src_ip}")
                            break
                            
        except Exception as e:
            if services_active:
                pass  # Ignore errors in monitoring
            
        time.sleep(1)

def monitor_traffic():
    """Monitor all incoming traffic"""
    print(f"📊 Traffic monitor started")
    
    while services_active:
        try:
            # Monitor overall traffic to this host
            result = subprocess.run([
                'timeout', '5', 'netstat', '-i'
            ], capture_output=True, text=True)
            
            # Just sleep and continue - detailed monitoring handled by other functions
            time.sleep(10)
            
        except Exception as e:
            if services_active:
                pass  # Ignore monitoring errors
                
        time.sleep(5)

def main():
    """Main server function"""
    global services_active, MY_IP
    
    # Auto-detect IP
    MY_IP = detect_my_ip()
    
    print("🎯 Target Host Server - Macvlan Version")
    print("========================================")
    print(f"🏠 Server IP: {MY_IP}")
    print(f"🌐 HTTP Port: {HTTP_PORT}")
    print(f"📡 DNS Port: {DNS_PORT}")
    print("========================================")
    
    # Register cleanup and signal handlers
    atexit.register(cleanup)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"\n🔧 Server Services:")
    print(f"   ✅ HTTP server (port {HTTP_PORT})")
    print(f"   ✅ DNS responder (port {DNS_PORT})")
    print(f"   ✅ ICMP ping responder")
    print(f"   ✅ Traffic monitor")
    
    print(f"\n💡 Testing Instructions:")
    print(f"   HTTP: curl http://{MY_IP}")
    print(f"   PING: ping {MY_IP}")
    print(f"   DNS:  dig @{MY_IP} example.com")
    
    # Start service threads
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    dns_thread = threading.Thread(target=run_dns_server, daemon=True)
    ping_thread = threading.Thread(target=run_ping_responder, daemon=True)
    monitor_thread = threading.Thread(target=monitor_traffic, daemon=True)
    
    print(f"\n🎬 Starting services...")
    
    try:
        http_thread.start()
        dns_thread.start()
        ping_thread.start()
        monitor_thread.start()
        
        print(f"✅ All services started on {MY_IP}")
        print(f"📊 Monitor logs below...")
        print(f"⏹️  Stop with Ctrl+C")
        print("")
        
        # Keep main thread alive
        while services_active:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Server failed: {e}")
    finally:
        services_active = False
        
    print(f"\n✅ Target server shutdown complete")

if __name__ == "__main__":
    main()
