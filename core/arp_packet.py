"""
ARP packet building and manipulation utilities.
"""

import struct
from typing import Optional, Tuple, Union

try:
    from scapy.all import Ether, ARP, Raw, sendp, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from config import settings


class ARPPacketBuilder:
    """
    Builder class for constructing ARP packets for various purposes.
    Supports both chat messages and spoofing operations.
    """
    
    # ARP hardware types
    HWTYPE_ETHERNET = 1
    
    # ARP protocol types
    PTYPE_IPV4 = 0x0800
    
    # ARP operation codes
    OP_REQUEST = 1
    OP_REPLY = 2
    
    # Hardware and protocol address lengths
    HWLEN = 6  # MAC address length
    PLEN = 4   # IPv4 address length
    
    def __init__(self, src_mac: str, src_ip: str):
        """
        Initialize the packet builder.
        
        Args:
            src_mac: Source MAC address.
            src_ip: Source IP address.
        """
        self.src_mac = src_mac
        self.src_ip = src_ip
    
    def build_arp_request(self, target_ip: str, 
                          target_mac: str = "00:00:00:00:00:00") -> 'Ether':
        """
        Build an ARP request packet.
        
        Args:
            target_ip: IP address to resolve.
            target_mac: Target MAC (usually zeros for requests).
        
        Returns:
            Scapy Ether/ARP packet.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet operations")
        
        return (
            Ether(src=self.src_mac, dst=settings.BROADCAST_MAC) /
            ARP(
                hwtype=self.HWTYPE_ETHERNET,
                ptype=self.PTYPE_IPV4,
                hwlen=self.HWLEN,
                plen=self.PLEN,
                op=self.OP_REQUEST,
                hwsrc=self.src_mac,
                psrc=self.src_ip,
                hwdst=target_mac,
                pdst=target_ip
            )
        )
    
    def build_arp_reply(self, target_ip: str, target_mac: str,
                        spoof_ip: Optional[str] = None) -> 'Ether':
        """
        Build an ARP reply packet.
        
        Args:
            target_ip: Target IP address.
            target_mac: Target MAC address.
            spoof_ip: IP to claim ownership of (for spoofing). 
                      Defaults to src_ip.
        
        Returns:
            Scapy Ether/ARP packet.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet operations")
        
        return (
            Ether(src=self.src_mac, dst=target_mac) /
            ARP(
                hwtype=self.HWTYPE_ETHERNET,
                ptype=self.PTYPE_IPV4,
                hwlen=self.HWLEN,
                plen=self.PLEN,
                op=self.OP_REPLY,
                hwsrc=self.src_mac,
                psrc=spoof_ip or self.src_ip,
                hwdst=target_mac,
                pdst=target_ip
            )
        )
    
    def build_gratuitous_arp(self, claim_ip: Optional[str] = None) -> 'Ether':
        """
        Build a gratuitous ARP packet.
        
        Args:
            claim_ip: IP address to claim. Defaults to src_ip.
        
        Returns:
            Scapy Ether/ARP packet.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet operations")
        
        ip = claim_ip or self.src_ip
        return (
            Ether(src=self.src_mac, dst=settings.BROADCAST_MAC) /
            ARP(
                hwtype=self.HWTYPE_ETHERNET,
                ptype=self.PTYPE_IPV4,
                hwlen=self.HWLEN,
                plen=self.PLEN,
                op=self.OP_REPLY,
                hwsrc=self.src_mac,
                psrc=ip,
                hwdst=settings.BROADCAST_MAC,
                pdst=ip
            )
        )
    
    def build_chat_packet(self, message_type: int, message_id: bytes,
                          payload: bytes, ether_type: int = None) -> 'Ether':
        """
        Build an ARP chat packet.
        
        The packet structure uses ARP format but carries chat data:
        - Uses configurable EtherType (default: experimental 0x88b5)
        - Payload stored in ARP protocol address fields
        
        Args:
            message_type: Type of message (see settings.PACKET_TYPE_*).
            message_id: Unique message/session ID (8 bytes).
            payload: Message payload bytes.
            ether_type: Ethernet type to use.
        
        Returns:
            Scapy packet for chat.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for packet operations")
        
        if ether_type is None:
            ether_type = settings.CHAT_ETHER_TYPES[settings.DEFAULT_CHAT_ETHER_TYPE]
        
        # Build custom ARP-like packet for chat
        # Header: PREFIX(7) + VERSION(1) + TYPE(1) + SEQ(1) + TOTAL(1) + ID(8)
        header = (
            settings.MESSAGE_PREFIX +
            bytes([settings.MESSAGE_VERSION, message_type, 0, 0]) +
            message_id
        )
        
        # Full data
        data = header + payload
        
        # Ensure data fits in ARP packet (protocol address field)
        if len(data) > 255:
            raise ValueError(f"Packet data too large: {len(data)} > 255")
        
        # Build Ethernet + ARP structure with our data
        return (
            Ether(src=self.src_mac, dst=settings.BROADCAST_MAC, type=0x0806) /
            ARP(
                hwtype=self.HWTYPE_ETHERNET,
                ptype=ether_type,
                hwlen=self.HWLEN,
                plen=len(data),
                op=self.OP_REQUEST,
                hwsrc=self.src_mac,
                psrc=data[:4] if len(data) >= 4 else data + b'\x00' * (4 - len(data)),
                hwdst="00:00:00:00:00:00",
                pdst="0.0.0.0"
            ) /
            Raw(load=data)
        )
    
    @staticmethod
    def parse_chat_packet(packet) -> Optional[Tuple[int, bytes, bytes]]:
        """
        Parse a received chat packet.
        
        Args:
            packet: Received Scapy packet.
        
        Returns:
            Tuple of (message_type, message_id, payload) or None if invalid.
        """
        try:
            if not packet.haslayer(Raw):
                return None
            
            data = bytes(packet[Raw].load)
            
            # Check prefix
            if not data.startswith(settings.MESSAGE_PREFIX):
                return None
            
            # Parse header
            prefix_len = len(settings.MESSAGE_PREFIX)
            if len(data) < prefix_len + 4 + settings.ID_SIZE:
                return None
            
            version = data[prefix_len]
            if version != settings.MESSAGE_VERSION:
                return None
            
            message_type = data[prefix_len + 1]
            # seq = data[prefix_len + 2]
            # total = data[prefix_len + 3]
            
            header_end = prefix_len + 4 + settings.ID_SIZE
            message_id = data[prefix_len + 4:header_end]
            payload = data[header_end:]
            
            return message_type, message_id, payload
            
        except Exception:
            return None


class RawARPPacket:
    """
    Low-level ARP packet manipulation without Scapy dependency.
    For environments where Scapy isn't available.
    """
    
    # Ethernet header: 14 bytes
    # ARP header: 28 bytes for Ethernet/IPv4
    
    @staticmethod
    def build_ethernet_header(src_mac: bytes, dst_mac: bytes, 
                              ether_type: int = 0x0806) -> bytes:
        """Build raw Ethernet header."""
        return dst_mac + src_mac + struct.pack('!H', ether_type)
    
    @staticmethod
    def build_arp_header(hw_type: int = 1, proto_type: int = 0x0800,
                         hw_len: int = 6, proto_len: int = 4,
                         operation: int = 1, sender_mac: bytes = b'\x00' * 6,
                         sender_ip: bytes = b'\x00' * 4,
                         target_mac: bytes = b'\x00' * 6,
                         target_ip: bytes = b'\x00' * 4) -> bytes:
        """Build raw ARP header."""
        return (
            struct.pack('!HHBBH', hw_type, proto_type, hw_len, proto_len, operation) +
            sender_mac + sender_ip + target_mac + target_ip
        )
    
    @staticmethod
    def parse_ethernet_header(data: bytes) -> Tuple[bytes, bytes, int]:
        """Parse Ethernet header, return (dst_mac, src_mac, ether_type)."""
        if len(data) < 14:
            raise ValueError("Data too short for Ethernet header")
        
        dst_mac = data[0:6]
        src_mac = data[6:12]
        ether_type = struct.unpack('!H', data[12:14])[0]
        
        return dst_mac, src_mac, ether_type
    
    @staticmethod
    def parse_arp_header(data: bytes) -> dict:
        """Parse ARP header starting at offset 14 (after Ethernet header)."""
        if len(data) < 42:  # 14 (Eth) + 28 (ARP)
            raise ValueError("Data too short for ARP packet")
        
        arp_data = data[14:]
        
        hw_type, proto_type, hw_len, proto_len, operation = struct.unpack(
            '!HHBBH', arp_data[0:8]
        )
        
        sender_mac = arp_data[8:14]
        sender_ip = arp_data[14:18]
        target_mac = arp_data[18:24]
        target_ip = arp_data[24:28]
        
        return {
            'hw_type': hw_type,
            'proto_type': proto_type,
            'hw_len': hw_len,
            'proto_len': proto_len,
            'operation': operation,
            'sender_mac': sender_mac,
            'sender_ip': sender_ip,
            'target_mac': target_mac,
            'target_ip': target_ip,
        }
