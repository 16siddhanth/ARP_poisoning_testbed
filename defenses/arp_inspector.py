"""
ARP Inspector - Dynamic ARP Inspection Daemon

This module implements a dynamic ARP inspection daemon that monitors
and validates ARP traffic in real-time.

Features:
- Rate limiting per MAC address
- ARP request/reply correlation
- Trusted port configuration
- Automatic blocking of suspicious sources
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from scapy.all import (
        Ether, ARP, sniff, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.network_utils import (
    get_mac_address, get_ip_address, get_gateway_info
)
from defenses.arp_detector import ARPDetector, ARPAlert, AlertSeverity


@dataclass
class ARPFlowEntry:
    """Tracks ARP request/reply flows"""
    request_time: datetime
    requester_mac: str
    requester_ip: str
    target_ip: str
    reply_received: bool = False
    reply_time: Optional[datetime] = None
    reply_mac: Optional[str] = None


@dataclass
class MACStatistics:
    """Statistics for a single MAC address"""
    mac: str
    first_seen: datetime
    last_seen: datetime
    arp_requests_sent: int = 0
    arp_replies_sent: int = 0
    arp_requests_received: int = 0
    unsolicited_replies: int = 0
    rate_limit_violations: int = 0
    is_blocked: bool = False
    blocked_at: Optional[datetime] = None
    ips_claimed: Set[str] = field(default_factory=set)


class ARPInspector:
    """
    Dynamic ARP Inspection Daemon
    
    Provides advanced ARP monitoring and protection:
    - Tracks ARP request/reply correlation
    - Implements rate limiting per source
    - Detects unsolicited ARP replies
    - Maintains trusted MAC list
    - Can block suspicious sources (via callback)
    """
    
    def __init__(
        self,
        interface: str,
        rate_limit: int = 10,  # ARP packets per second
        rate_window: float = 1.0,  # Window for rate calculation
        block_threshold: int = 3,  # Violations before blocking
        trusted_macs: Optional[List[str]] = None,
        block_callback: Optional[Callable[[str, str], None]] = None,
        verbose: bool = True
    ):
        """
        Initialize ARP Inspector
        
        Args:
            interface: Network interface to monitor
            rate_limit: Maximum ARP packets per source per window
            rate_window: Time window for rate limiting (seconds)
            block_threshold: Number of violations before blocking
            trusted_macs: List of trusted MAC addresses
            block_callback: Function to call when blocking (mac, reason)
            verbose: Enable verbose logging
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required")
            
        self.interface = interface
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.block_threshold = block_threshold
        self.block_callback = block_callback
        self.verbose = verbose
        
        # Get our addresses
        self.our_mac = get_mac_address(interface)
        self.our_ip = get_ip_address(interface)
        
        # Get gateway
        gw_info = get_gateway_info(interface)
        self.gateway_ip = gw_info['ip'] if gw_info else None
        self.gateway_mac = gw_info.get('mac') if gw_info else None
        
        # Trusted MACs (always includes gateway and ourselves)
        self.trusted_macs: Set[str] = set(trusted_macs or [])
        if self.our_mac:
            self.trusted_macs.add(self.our_mac.lower())
        if self.gateway_mac:
            self.trusted_macs.add(self.gateway_mac.lower())
            
        # State
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Tracking
        self._mac_stats: Dict[str, MACStatistics] = {}
        self._mac_stats_lock = threading.Lock()
        
        # ARP flow tracking
        self._pending_requests: Dict[str, ARPFlowEntry] = {}  # Key: target_ip
        self._pending_lock = threading.Lock()
        
        # Rate limiting
        self._rate_buckets: Dict[str, List[datetime]] = defaultdict(list)
        self._rate_lock = threading.Lock()
        
        # Blocked MACs
        self._blocked_macs: Set[str] = set()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'requests': 0,
            'replies': 0,
            'unsolicited_replies': 0,
            'rate_limit_violations': 0,
            'blocked_macs': 0,
            'trusted_bypasses': 0
        }
        
        # Integrate with detector for alerts
        self._detector: Optional[ARPDetector] = None
        
        conf.verb = 0
        
        self._log(f"ARP Inspector initialized")
        self._log(f"  Rate limit: {rate_limit} pkts/{rate_window}s")
        self._log(f"  Block threshold: {block_threshold} violations")
        self._log(f"  Trusted MACs: {len(self.trusted_macs)}")
        
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [ARPInspector] {message}")
            
    def add_trusted_mac(self, mac: str):
        """Add a MAC to the trusted list"""
        self.trusted_macs.add(mac.lower())
        self._log(f"Added trusted MAC: {mac}")
        
    def remove_trusted_mac(self, mac: str):
        """Remove a MAC from the trusted list"""
        self.trusted_macs.discard(mac.lower())
        self._log(f"Removed trusted MAC: {mac}")
        
    def _check_rate_limit(self, mac: str) -> bool:
        """
        Check if a MAC is within rate limit
        
        Returns True if within limit, False if exceeded
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.rate_window)
        
        with self._rate_lock:
            # Clean old entries
            self._rate_buckets[mac] = [
                t for t in self._rate_buckets[mac] if t > cutoff
            ]
            
            # Check limit
            if len(self._rate_buckets[mac]) >= self.rate_limit:
                return False
                
            # Add this packet
            self._rate_buckets[mac].append(now)
            return True
            
    def _get_or_create_mac_stats(self, mac: str) -> MACStatistics:
        """Get or create statistics for a MAC"""
        mac = mac.lower()
        
        with self._mac_stats_lock:
            if mac not in self._mac_stats:
                self._mac_stats[mac] = MACStatistics(
                    mac=mac,
                    first_seen=datetime.now(),
                    last_seen=datetime.now()
                )
            return self._mac_stats[mac]
            
    def _block_mac(self, mac: str, reason: str):
        """Block a MAC address"""
        mac = mac.lower()
        
        if mac in self.trusted_macs:
            self._log(f"Cannot block trusted MAC: {mac}")
            return
            
        if mac in self._blocked_macs:
            return
            
        self._blocked_macs.add(mac)
        self.stats['blocked_macs'] += 1
        
        with self._mac_stats_lock:
            if mac in self._mac_stats:
                self._mac_stats[mac].is_blocked = True
                self._mac_stats[mac].blocked_at = datetime.now()
                
        self._log(f"BLOCKED MAC: {mac} (reason: {reason})")
        
        if self.block_callback:
            try:
                self.block_callback(mac, reason)
            except Exception as e:
                self._log(f"Block callback error: {e}")
                
    def _is_blocked(self, mac: str) -> bool:
        """Check if a MAC is blocked"""
        return mac.lower() in self._blocked_macs
        
    def _process_packet(self, packet):
        """Process an ARP packet"""
        if not packet.haslayer(ARP):
            return
            
        self.stats['total_packets'] += 1
        
        arp = packet[ARP]
        source_mac = arp.hwsrc.lower()
        source_ip = arp.psrc
        target_ip = arp.pdst
        
        # Check if blocked
        if self._is_blocked(source_mac):
            return
            
        # Check if trusted
        is_trusted = source_mac in self.trusted_macs
        if is_trusted:
            self.stats['trusted_bypasses'] += 1
            
        # Rate limit check (skip for trusted)
        if not is_trusted and not self._check_rate_limit(source_mac):
            self.stats['rate_limit_violations'] += 1
            
            stats = self._get_or_create_mac_stats(source_mac)
            stats.rate_limit_violations += 1
            
            if stats.rate_limit_violations >= self.block_threshold:
                self._block_mac(source_mac, "rate_limit_exceeded")
            return
            
        # Update statistics
        stats = self._get_or_create_mac_stats(source_mac)
        stats.last_seen = datetime.now()
        stats.ips_claimed.add(source_ip)
        
        if arp.op == 1:  # ARP Request
            self.stats['requests'] += 1
            stats.arp_requests_sent += 1
            
            # Track this request for reply correlation
            with self._pending_lock:
                self._pending_requests[target_ip] = ARPFlowEntry(
                    request_time=datetime.now(),
                    requester_mac=source_mac,
                    requester_ip=source_ip,
                    target_ip=target_ip
                )
                
        elif arp.op == 2:  # ARP Reply
            self.stats['replies'] += 1
            stats.arp_replies_sent += 1
            
            # Check if this reply was solicited
            with self._pending_lock:
                if source_ip in self._pending_requests:
                    # Solicited reply
                    flow = self._pending_requests[source_ip]
                    flow.reply_received = True
                    flow.reply_time = datetime.now()
                    flow.reply_mac = source_mac
                    
                    # Clean up old entries
                    del self._pending_requests[source_ip]
                else:
                    # Unsolicited reply!
                    self.stats['unsolicited_replies'] += 1
                    stats.unsolicited_replies += 1
                    
                    if not is_trusted:
                        self._log(f"Unsolicited ARP reply: {source_ip} -> {source_mac}")
                        
                        # Check for excessive unsolicited replies
                        if stats.unsolicited_replies >= self.block_threshold:
                            self._block_mac(source_mac, "excessive_unsolicited_replies")
                            
    def _cleanup_pending(self):
        """Clean up old pending requests"""
        cutoff = datetime.now() - timedelta(seconds=10)
        
        with self._pending_lock:
            expired = [
                ip for ip, flow in self._pending_requests.items()
                if flow.request_time < cutoff
            ]
            for ip in expired:
                del self._pending_requests[ip]
                
    def _sniff_loop(self):
        """Sniffing loop"""
        self._log("Starting ARP inspection...")
        
        try:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception as e:
            self._log(f"Sniff error: {e}")
            
        self._log("ARP inspection stopped")
        
    def _maintenance_loop(self):
        """Maintenance loop for cleanup tasks"""
        while not self._stop_event.is_set():
            self._cleanup_pending()
            self._stop_event.wait(5)
            
    def start(self):
        """Start the ARP inspector"""
        if self._running:
            return
            
        self._log("Starting ARP inspector...")
        self._running = True
        self._stop_event.clear()
        
        # Start sniffing thread
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="ARPInspectorSniff"
        )
        self._sniff_thread.start()
        
        # Start maintenance thread
        self._maint_thread = threading.Thread(
            target=self._maintenance_loop,
            daemon=True,
            name="ARPInspectorMaint"
        )
        self._maint_thread.start()
        
        self._log("ARP inspector started")
        
    def stop(self):
        """Stop the ARP inspector"""
        if not self._running:
            return
            
        self._log("Stopping ARP inspector...")
        self._running = False
        self._stop_event.set()
        
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2)
            
        self._log("ARP inspector stopped")
        
    def get_statistics(self) -> Dict:
        """Get inspection statistics"""
        return dict(self.stats)
        
    def get_mac_statistics(self) -> Dict[str, Dict]:
        """Get per-MAC statistics"""
        with self._mac_stats_lock:
            return {
                mac: {
                    'first_seen': s.first_seen.isoformat(),
                    'last_seen': s.last_seen.isoformat(),
                    'requests_sent': s.arp_requests_sent,
                    'replies_sent': s.arp_replies_sent,
                    'unsolicited_replies': s.unsolicited_replies,
                    'rate_violations': s.rate_limit_violations,
                    'is_blocked': s.is_blocked,
                    'ips_claimed': list(s.ips_claimed)
                }
                for mac, s in self._mac_stats.items()
            }
            
    def get_blocked_macs(self) -> List[str]:
        """Get list of blocked MACs"""
        return list(self._blocked_macs)
        
    def unblock_mac(self, mac: str):
        """Unblock a MAC address"""
        mac = mac.lower()
        self._blocked_macs.discard(mac)
        
        with self._mac_stats_lock:
            if mac in self._mac_stats:
                self._mac_stats[mac].is_blocked = False
                
        self._log(f"Unblocked MAC: {mac}")
        
    def is_running(self) -> bool:
        """Check if inspector is running"""
        return self._running


def main():
    """Demo/test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ARP Inspector")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-d", "--duration", type=float, default=60, help="Duration")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit")
    
    args = parser.parse_args()
    
    def block_handler(mac: str, reason: str):
        print(f"\n🚫 BLOCKED: {mac} - {reason}")
        
    inspector = ARPInspector(
        interface=args.interface,
        rate_limit=args.rate_limit,
        block_callback=block_handler
    )
    
    print(f"[*] Inspecting ARP traffic for {args.duration} seconds...")
    inspector.start()
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        
    inspector.stop()
    
    # Print summary
    stats = inspector.get_statistics()
    print(f"\n[*] Statistics:")
    print(f"    Total packets: {stats['total_packets']}")
    print(f"    Requests/Replies: {stats['requests']}/{stats['replies']}")
    print(f"    Unsolicited replies: {stats['unsolicited_replies']}")
    print(f"    Rate violations: {stats['rate_limit_violations']}")
    print(f"    Blocked MACs: {stats['blocked_macs']}")


if __name__ == "__main__":
    main()
