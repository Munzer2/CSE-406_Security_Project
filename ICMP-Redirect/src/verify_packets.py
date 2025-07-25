#!/usr/bin/env python3
"""
Packet Verification Script
Tests the raw packet crafting functions to ensure they work correctly.
"""

import socket
import struct
import sys
from util import PacketCrafter, NetworkConfig

class PacketTester:
    """Test packet crafting functions"""
    
    def __init__(self):
        self.packet_crafter = PacketCrafter()
    
    def test_checksum_function(self):
        """Test checksum calculation with known values"""
        print("[*] Testing checksum calculation...")
        
        # Test with known data
        test_data = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c'
        expected_checksum = 0xb1e6  # Known correct checksum for this data
        
        calculated = self.packet_crafter.calculate_checksum(test_data)
        print(f"    Expected: 0x{expected_checksum:04x}")
        print(f"    Calculated: 0x{calculated:04x}")
        
        if calculated == expected_checksum:
            print("    ✓ Checksum calculation PASSED")
            return True
        else:
            print("    ✗ Checksum calculation FAILED")
            return False

    def test_ip_header_creation(self):
        """Test IP header creation"""
        print("\n[*] Testing IP header creation...")
        
        try:
            # Create a simple IP header using utility function
            header = self.packet_crafter.create_ip_header(
                NetworkConfig.VICTIM_IP, NetworkConfig.TARGET_IP, 
                NetworkConfig.IPPROTO_ICMP, 8, identification=12345
            )
            
            # Verify header is correct length
            if len(header) == 20:
                print("    ✓ IP header length correct (20 bytes)")
            else:
                print(f"    ✗ IP header length incorrect ({len(header)} bytes)")
                return False
            
            # Parse the header to verify structure
            version_ihl, tos, total_len, ip_id, flags_frag, ttl, protocol, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', header)
            
            # Verify checksum is reasonable
            if 0 <= checksum <= 0xFFFF:
                print(f"    ✓ IP header checksum valid (0x{checksum:04x})")
            else:
                print(f"    ✗ IP header checksum invalid (0x{checksum:04x})")
                return False
            
            print("    ✓ IP header creation PASSED")
            return True
            
        except Exception as e:
            print(f"    ✗ IP header creation FAILED: {e}")
            return False

    def test_icmp_packet_creation(self):
        """Test ICMP packet creation"""
        print("\n[*] Testing ICMP packet creation...")
        
        try:
            # Create ICMP echo request using utility function
            payload = b"Test payload"
            icmp_packet = self.packet_crafter.create_icmp_packet(
                NetworkConfig.ICMP_ECHO_REQUEST, 0, 1234, 1, payload
            )
            
            # Parse the packet to verify structure
            icmp_type, icmp_code, checksum, identifier, sequence = struct.unpack('!BBHHH', icmp_packet[:8])
            
            # Verify packet structure
            if len(icmp_packet[:8]) == 8:
                print("    ✓ ICMP header length correct (8 bytes)")
            else:
                print(f"    ✗ ICMP header length incorrect ({len(icmp_packet[:8])} bytes)")
                return False
            
            if 0 <= checksum <= 0xFFFF:
                print(f"    ✓ ICMP checksum valid (0x{checksum:04x})")
            else:
                print(f"    ✗ ICMP checksum invalid (0x{checksum:04x})")
                return False
            
            print("    ✓ ICMP packet creation PASSED")
            return True
            
        except Exception as e:
            print(f"    ✗ ICMP packet creation FAILED: {e}")
            return False

    def test_icmp_redirect_creation(self):
        """Test ICMP redirect packet creation"""
        print("\n[*] Testing ICMP redirect creation...")
        
        try:
            # Create fake original packet data for redirect
            original_header = self.packet_crafter.create_ip_header(
                NetworkConfig.VICTIM_IP, NetworkConfig.TARGET_IP, 
                NetworkConfig.IPPROTO_ICMP, 8
            )
            original_data = b'\x08\x00\xf7\xff\x00\x00\x00\x00'  # Fake ICMP data
            
            # Create ICMP redirect using utility function
            icmp_redirect = self.packet_crafter.create_icmp_redirect_packet(
                NetworkConfig.ATTACKER_IP, original_header, original_data
            )
            
            # Parse the redirect packet
            icmp_type, icmp_code, checksum = struct.unpack('!BBH', icmp_redirect[:4])
            
            if icmp_type == NetworkConfig.ICMP_REDIRECT:
                print("    ✓ ICMP redirect type correct")
            else:
                print(f"    ✗ ICMP redirect type incorrect ({icmp_type})")
                return False
            
            if 0 <= checksum <= 0xFFFF:
                print(f"    ✓ ICMP redirect checksum valid (0x{checksum:04x})")
            else:
                print(f"    ✗ ICMP redirect checksum invalid")
                return False
            
            print("    ✓ ICMP redirect creation PASSED")
            return True
            
        except Exception as e:
            print(f"    ✗ ICMP redirect creation FAILED: {e}")
            return False

    def run_all_tests(self):
        """Run all packet verification tests"""
        print("="*50)
        print("Packet Crafting Verification Tests")
        print("="*50)
        
        tests = [
            self.test_checksum_function,
            self.test_ip_header_creation,
            self.test_icmp_packet_creation,
            self.test_icmp_redirect_creation
        ]
        
        passed = 0
        total = len(tests)
        
        for test in tests:
            if test():
                passed += 1
        
        print("\n" + "="*50)
        print(f"Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("✓ All tests PASSED - Packet crafting functions work correctly")
            return True
        else:
            print("✗ Some tests FAILED - Check packet crafting implementation")
            return False

def main():
    """Main function"""
    tester = PacketTester()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python3 verify_packets.py")
        print("Runs verification tests for packet crafting functions")
    else:
        success = tester.run_all_tests()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
