#!/usr/bin/env python3
"""
Basic Network Packet Sniffer
This program captures and analyzes network traffic packets to understand
their structure, content, and how data flows through the network.

Requirements:
- Run with administrator/root privileges
- Install scapy: pip install scapy
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.dns import DNS
from scapy.packet import Raw
import socket
import struct
import textwrap
import argparse
import sys
import os
from datetime import datetime

class NetworkSniffer:
    def __init__(self, interface=None, filter_protocol=None, packet_count=0):
        self.interface = interface
        self.filter_protocol = filter_protocol
        self.packet_count = packet_count
        self.packets_captured = 0
        
    def start_sniffing(self):
        """Start capturing packets"""
        print(f"[*] Starting packet capture on interface: {self.interface or 'default'}")
        print(f"[*] Filter: {self.filter_protocol or 'All protocols'}")
        print(f"[*] Packet limit: {self.packet_count or 'Unlimited'}")
        print("-" * 60)
        
        try:
            
            sniff(
                iface=self.interface,
                filter=self.filter_protocol,
                prn=self.packet_callback,
                count=self.packet_count,
                store=0
            )
        except KeyboardInterrupt:
            print(f"\n[*] Stopping capture. Total packets captured: {self.packets_captured}")
        except Exception as e:
            print(f"[!] Error: {e}")
            print("[!] Try running with administrative privileges")

    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packets_captured += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        print(f"\n[PACKET #{self.packets_captured}] - {timestamp}")
        print("=" * 60)
        
        
        self.analyze_ethernet(packet)
        self.analyze_ip(packet)
        self.analyze_transport(packet)
        self.analyze_application(packet)
        
        print("-" * 60)

    def analyze_ethernet(self, packet):
        """Analyze Ethernet frame"""
        if packet.haslayer(Ether):
            eth = packet[Ether]
            print(f"[ETHERNET FRAME]")
            print(f"  Source MAC:      {eth.src}")
            print(f"  Destination MAC: {eth.dst}")
            print(f"  EtherType:       {hex(eth.type)} ({self.get_ethertype(eth.type)})")

    def analyze_ip(self, packet):
        """Analyze IP packet"""
        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"[IP PACKET]")
            print(f"  Version:         {ip.version}")
            print(f"  Header Length:   {ip.ihl * 4} bytes")
            print(f"  Type of Service: {ip.tos}")
            print(f"  Total Length:    {ip.len} bytes")
            print(f"  Identification:  {ip.id}")
            print(f"  Flags:           {ip.flags}")
            print(f"  Fragment Offset: {ip.frag}")
            print(f"  TTL:             {ip.ttl}")
            print(f"  Protocol:        {ip.proto} ({self.get_ip_protocol(ip.proto)})")
            print(f"  Source IP:       {ip.src}")
            print(f"  Destination IP:  {ip.dst}")
        elif packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            print(f"[IPv6 PACKET]")
            print(f"  Version:         {ipv6.version}")
            print(f"  Traffic Class:   {ipv6.tc}")
            print(f"  Flow Label:      {ipv6.fl}")
            print(f"  Payload Length:  {ipv6.plen}")
            print(f"  Next Header:     {ipv6.nh}")
            print(f"  Hop Limit:       {ipv6.hlim}")
            print(f"  Source IP:       {ipv6.src}")
            print(f"  Destination IP:  {ipv6.dst}")

    def analyze_transport(self, packet):
        """Analyze Transport layer (TCP/UDP)"""
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"[TCP SEGMENT]")
            print(f"  Source Port:     {tcp.sport}")
            print(f"  Destination Port: {tcp.dport}")
            print(f"  Sequence Number: {tcp.seq}")
            print(f"  Ack Number:      {tcp.ack}")
            print(f"  Header Length:   {tcp.dataofs * 4} bytes")
            print(f"  Flags:           {self.get_tcp_flags(tcp.flags)}")
            print(f"  Window Size:     {tcp.window}")
            print(f"  Checksum:        {hex(tcp.chksum)}")
            print(f"  Urgent Pointer:  {tcp.urgptr}")
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print(f"[UDP DATAGRAM]")
            print(f"  Source Port:     {udp.sport}")
            print(f"  Destination Port: {udp.dport}")
            print(f"  Length:          {udp.len} bytes")
            print(f"  Checksum:        {hex(udp.chksum)}")

    def analyze_application(self, packet):
        """Analyze Application layer protocols"""
        # HTTP
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if any(method in payload_str[:20] for method in ['GET ', 'POST ', 'PUT ', 'DELETE ']):
                    print(f"[HTTP REQUEST]")
                    lines = payload_str.split('\r\n')
                    print(f"  Request Line: {lines[0]}")
                    for line in lines[1:6]:  
                        if line and ':' in line:
                            print(f"  Header: {line}")
                elif payload_str.startswith('HTTP/'):
                    print(f"[HTTP RESPONSE]")
                    lines = payload_str.split('\r\n')
                    print(f"  Status Line: {lines[0]}")
                    for line in lines[1:6]:  
                        if line and ':' in line:
                            print(f"  Header: {line}")
            except:
                pass
        
        
        if packet.haslayer(DNS):
            dns = packet[DNS]
            print(f"[DNS QUERY/RESPONSE]")
            print(f"  Transaction ID:  {dns.id}")
            print(f"  Flags:           {hex(dns.flags)}")
            print(f"  Questions:       {dns.qdcount}")
            print(f"  Answers:         {dns.ancount}")
            if dns.qd:
                print(f"  Query Name:      {dns.qd.qname.decode()}")
                print(f"  Query Type:      {dns.qd.qtype}")
        
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if len(payload) > 0:
                print(f"[PAYLOAD PREVIEW] ({len(payload)} bytes)")
                
                hex_data = payload[:64].hex()
                ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload[:64])
                
                for i in range(0, len(hex_data), 32):
                    hex_line = ' '.join(hex_data[i:i+2] for i in range(i, min(i+32, len(hex_data)), 2))
                    ascii_line = ascii_data[i//2:(i+32)//2]
                    print(f"  {hex_line:<48} {ascii_line}")

    def get_ethertype(self, ethertype):
        """Get EtherType description"""
        ethertypes = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "VLAN",
        }
        return ethertypes.get(ethertype, "Unknown")

    def get_ip_protocol(self, protocol):
        """Get IP protocol description"""
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            89: "OSPF",
        }
        return protocols.get(protocol, "Unknown")

    def get_tcp_flags(self, flags):
        """Get TCP flags description"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        return f"{hex(flags)} ({', '.join(flag_names) if flag_names else 'None'})"


class RawSocketSniffer:
    """Alternative implementation using raw sockets (Linux/Unix only)"""
    
    def __init__(self):
        try:
            
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except socket.error as e:
            print(f"[!] Could not create raw socket: {e}")
            print("[!] Try running with root privileges on Linux")
            sys.exit(1)

    def start_sniffing(self, count=10):
        """Start capturing packets with raw socket"""
        print(f"[*] Starting raw socket capture ({count} packets)")
        print("-" * 60)
        
        for i in range(count):
            raw_data, addr = self.sock.recvfrom(65536)
            print(f"\n[PACKET #{i+1}]")
            self.parse_ethernet_frame(raw_data)

    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame"""
        dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
        
        print(f"Ethernet Frame:")
        print(f"  Destination: {self.format_mac_addr(dest_mac)}")
        print(f"  Source: {self.format_mac_addr(src_mac)}")
        print(f"  Protocol: {eth_proto}")
        
        
        if eth_proto == 8:
            self.parse_ipv4_packet(data[14:])

    def parse_ipv4_packet(self, data):
        """Parse IPv4 packet"""
        
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        print(f"IPv4 Packet:")
        print(f"  Version: {version}")
        print(f"  Header Length: {header_length}")
        print(f"  TTL: {ttl}")
        print(f"  Protocol: {proto}")
        print(f"  Source: {self.format_ipv4_addr(src)}")
        print(f"  Target: {self.format_ipv4_addr(target)}")
        
        
        if proto == 1:
            self.parse_icmp_packet(data[header_length:])
        elif proto == 6:
            self.parse_tcp_segment(data[header_length:])
        elif proto == 17:
            self.parse_udp_segment(data[header_length:])

    def parse_tcp_segment(self, data):
        """Parse TCP segment"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 511
        
        print(f"TCP Segment:")
        print(f"  Source Port: {src_port}")
        print(f"  Destination Port: {dest_port}")
        print(f"  Sequence: {sequence}")
        print(f"  Acknowledgment: {acknowledgment}")
        print(f"  Flags: {flags}")

    def parse_udp_segment(self, data):
        """Parse UDP segment"""
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        
        print(f"UDP Segment:")
        print(f"  Source Port: {src_port}")
        print(f"  Destination Port: {dest_port}")
        print(f"  Length: {length}")

    def parse_icmp_packet(self, data):
        """Parse ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        
        print(f"ICMP Packet:")
        print(f"  Type: {icmp_type}")
        print(f"  Code: {code}")
        print(f"  Checksum: {checksum}")

    @staticmethod
    def format_mac_addr(bytes_addr):
        """Format MAC address"""
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    @staticmethod
    def format_ipv4_addr(addr):
        """Format IPv4 address"""
        return '.'.join(map(str, addr))


def main():
    parser = argparse.ArgumentParser(description='Basic Network Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-f', '--filter', help='BPF filter (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--raw', action='store_true', help='Use raw sockets instead of scapy (Linux only)')
    
    args = parser.parse_args()
    
    print("Basic Network Packet Sniffer")
    print("=" * 40)
    
    if args.raw:
        
        sniffer = RawSocketSniffer()
        sniffer.start_sniffing(args.count or 10)
    else:
        
        sniffer = NetworkSniffer(args.interface, args.filter, args.count)
        sniffer.start_sniffing()


if __name__ == "__main__":
    
    if os.name == 'posix' and os.getuid() != 0:
        print("[!] Warning: This script may require root privileges on Unix systems")
        print("[!] Try running with: sudo python3 network_sniffer.py")
    
    main()
