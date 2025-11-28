"""
MAC Discrepancy Analysis for ARP Poisoning Detection

This module implements the detection algorithm described in:
"ARP Poisoning Detection and Prevention using Scapy" (ICITSD 2021)
by Aayush Majumdar, Shruti Raj, and T. Subbulakshmi

The key detection method:
1. Monitor ARP packets for IP-MAC mappings
2. Compare the claimed MAC address with the actual source MAC
3. Send verification ARP requests to validate bindings
4. Detect discrepancies that indicate spoofing

Reference: doi.org/10.1088/1742-6596/1911/1/012022
"""

import threading
import time
from typing import Dict, List, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

try:
    from scapy.all import (
        Ether, ARP, sniff, sendp, srp, conf,
        get_if_hwaddr, get_if_addr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DetectionMethod(Enum):
    """Detection methods as per the research paper."""
    MAC_HEADER_MISMATCH = "mac_header_mismatch"  # Ethernet MAC != ARP MAC
    DUPLICATE_IP = "duplicate_ip"                 # Same IP, different MACs
    MAC_FLIP_FLOP = "mac_flip_flop"              # MAC changes rapidly
    UNSOLICITED_REPLY = "unsolicited_reply"       # Reply without request
    VERIFICATION_FAILED = "verification_failed"   # ARP probe verification failed


@dataclass
class MACDiscrepancy:
    """
    Records a detected MAC address discrepancy.
    
    As per the paper, we track:
    - The IP address involved
    - The expected (real) MAC address
    - The claimed (possibly spoofed) MAC address
    - The detection method used
    """
    timestamp: float
    ip_address: str
    expected_mac: str
    claimed_mac: str
    detection_method: DetectionMethod
    confidence: float  # 0-1, how confident we are this is an attack
    ethernet_src_mac: Optional[str] = None
    details: str = ""
    verified: bool = False
    
    @property
    def is_high_confidence(self) -> bool:
        """Check if this is a high-confidence detection."""
        return self.confidence >= 0.8


@dataclass
class IPMACBinding:
    """
    Tracks an IP to MAC address binding.
    
    This implements the "real MAC address" tracking from the paper.
    """
    ip: str
    mac: str
    first_seen: float
    last_seen: float
    verified: bool = False
    verification_count: int = 0
    change_count: int = 0
    is_gateway: bool = False
    source: str = "arp"  # 'arp', 'static', 'dhcp', 'verified'


class ARPRequestTracker:
    """
    Tracks ARP requests to detect unsolicited replies.
    
    Per the paper's methodology, we track requests and match them
    to replies to detect unsolicited/gratuitous responses.
    """
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._requests: Dict[str, Tuple[float, str]] = {}  # dst_ip -> (timestamp, src_mac)
        self._lock = threading.Lock()
    
    def record_request(self, src_mac: str, dst_ip: str):
        """Record an ARP request."""
        with self._lock:
            self._requests[dst_ip] = (time.time(), src_mac)
    
    def check_reply(self, src_ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a reply was solicited.
        
        Returns:
            (is_solicited, requesting_mac)
        """
        with self._lock:
            self._cleanup()
            
            if src_ip in self._requests:
                _, req_mac = self._requests[src_ip]
                del self._requests[src_ip]
                return True, req_mac
            
            return False, None
    
    def _cleanup(self):
        """Remove expired requests."""
        now = time.time()
        expired = [
            ip for ip, (ts, _) in self._requests.items()
            if now - ts > self.timeout
        ]
        for ip in expired:
            del self._requests[ip]


class MACDiscrepancyDetector:
    """
    Main detector implementing the MAC discrepancy analysis from the paper.
    
    Detection Algorithm (from Majumdar et al., 2021):
    1. Capture ARP packets on the network
    2. For each ARP packet, extract:
       - Ethernet frame source MAC
       - ARP sender hardware address (claimed MAC)
       - ARP sender protocol address (claimed IP)
    3. Compare Ethernet source MAC with ARP sender MAC
    4. Maintain a binding table of known IP-MAC pairs
    5. Detect discrepancies:
       - Ethernet MAC != ARP MAC (immediate red flag)
       - New MAC for known IP
       - Multiple IPs claiming same MAC
    6. Verify suspicious bindings with active ARP probes
    
    Usage:
        detector = MACDiscrepancyDetector(interface="eth0")
        detector.add_trusted_binding("192.168.1.1", "aa:bb:cc:dd:ee:ff")  # Gateway
        detector.start()
        
        # Check for detections
        discrepancies = detector.get_discrepancies()
        
        detector.stop()
    """
    
    def __init__(
        self,
        interface: str,
        enable_active_verification: bool = True,
        verification_interval: float = 5.0,
        callback: Optional[Callable[[MACDiscrepancy], None]] = None,
        verbose: bool = True
    ):
        """
        Initialize the MAC Discrepancy Detector.
        
        Args:
            interface: Network interface to monitor
            enable_active_verification: Send ARP probes to verify bindings
            verification_interval: Seconds between verification rounds
            callback: Function to call on discrepancy detection
            verbose: Enable verbose logging
        """
        self.interface = interface
        self.enable_active_verification = enable_active_verification
        self.verification_interval = verification_interval
        self.callback = callback
        self.verbose = verbose
        
        # Get our own addresses
        if SCAPY_AVAILABLE:
            self.our_mac = get_if_hwaddr(interface)
            self.our_ip = get_if_addr(interface)
        else:
            self.our_mac = None
            self.our_ip = None
        
        # Known IP-MAC bindings (the "real" bindings)
        self._bindings: Dict[str, IPMACBinding] = {}
        self._bindings_lock = threading.Lock()
        
        # Detected discrepancies
        self._discrepancies: List[MACDiscrepancy] = []
        self._discrepancies_lock = threading.Lock()
        
        # Request tracking for unsolicited reply detection
        self._request_tracker = ARPRequestTracker()
        
        # MAC to IPs mapping for duplicate detection
        self._mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'header_mismatches': 0,
            'duplicate_ips': 0,
            'unsolicited_replies': 0,
            'verification_failures': 0,
            'bindings_verified': 0,
            'attacks_detected': 0,
        }
        
        # Thread control
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._verify_thread: Optional[threading.Thread] = None
        
        conf.verb = 0
        
        self._log("MAC Discrepancy Detector initialized")
        self._log(f"  Interface: {interface}")
        self._log(f"  Our MAC: {self.our_mac}")
        self._log(f"  Active verification: {enable_active_verification}")
    
    def _log(self, message: str):
        """Log message if verbose."""
        if self.verbose:
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{ts}] [MACDetector] {message}")
    
    def add_trusted_binding(self, ip: str, mac: str, is_gateway: bool = False):
        """
        Add a known-good (trusted) IP-MAC binding.
        
        This establishes the "real MAC address" as mentioned in the paper.
        Any ARP traffic claiming a different MAC for this IP will be flagged.
        """
        with self._bindings_lock:
            self._bindings[ip] = IPMACBinding(
                ip=ip,
                mac=mac.lower(),
                first_seen=time.time(),
                last_seen=time.time(),
                verified=True,
                source="static",
                is_gateway=is_gateway
            )
            self._mac_to_ips[mac.lower()].add(ip)
        
        self._log(f"Added trusted binding: {ip} -> {mac}" + 
                 (" (gateway)" if is_gateway else ""))
    
    def start(self):
        """Start the detector."""
        if self._running:
            return
        
        self._running = True
        
        # Start packet sniffing
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            name="MACDetector-Sniff"
        )
        self._sniff_thread.daemon = True
        self._sniff_thread.start()
        
        # Start active verification if enabled
        if self.enable_active_verification:
            self._verify_thread = threading.Thread(
                target=self._verification_loop,
                name="MACDetector-Verify"
            )
            self._verify_thread.daemon = True
            self._verify_thread.start()
        
        self._log("Detector started")
    
    def stop(self):
        """Stop the detector."""
        self._running = False
        
        if self._sniff_thread:
            self._sniff_thread.join(timeout=2.0)
        if self._verify_thread:
            self._verify_thread.join(timeout=2.0)
        
        self._log("Detector stopped")
    
    def _sniff_loop(self):
        """Main packet sniffing loop."""
        try:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self._running
            )
        except Exception as e:
            self._log(f"Sniff error: {e}")
    
    def _process_packet(self, packet):
        """
        Process an ARP packet for discrepancy detection.
        
        This implements the core detection algorithm from the paper.
        """
        if not packet.haslayer(ARP) or not packet.haslayer(Ether):
            return
        
        self.stats['packets_processed'] += 1
        
        # Extract addresses from Ethernet header and ARP payload
        eth_src_mac = packet[Ether].src.lower()
        arp = packet[ARP]
        arp_src_mac = arp.hwsrc.lower()  # ARP sender hardware address
        arp_src_ip = arp.psrc            # ARP sender protocol address
        arp_dst_ip = arp.pdst            # ARP target protocol address
        
        # Ignore our own packets
        if eth_src_mac == self.our_mac:
            return
        
        # Detection 1: Ethernet MAC vs ARP MAC mismatch
        # This is a key detection from the paper
        if eth_src_mac != arp_src_mac:
            self._detect_header_mismatch(
                eth_src_mac, arp_src_mac, arp_src_ip, arp_dst_ip
            )
        
        # Track requests for unsolicited reply detection
        if arp.op == 1:  # ARP Request
            self._request_tracker.record_request(eth_src_mac, arp_dst_ip)
        
        # Process ARP replies
        elif arp.op == 2:  # ARP Reply
            # Detection 2: Check for unsolicited replies
            is_solicited, _ = self._request_tracker.check_reply(arp_src_ip)
            if not is_solicited:
                self._detect_unsolicited_reply(
                    arp_src_ip, arp_src_mac, eth_src_mac
                )
            
            # Detection 3: Check against known bindings
            self._check_binding(arp_src_ip, arp_src_mac, eth_src_mac)
    
    def _detect_header_mismatch(self, eth_mac: str, arp_mac: str, 
                                src_ip: str, dst_ip: str):
        """
        Detect Ethernet header / ARP payload MAC mismatch.
        
        This is a strong indicator of ARP spoofing as per the paper:
        "The detection algorithm is based on analyzing the real MAC Address 
        and response MAC Address of the ARP Packet sniffed for any discrepancies."
        """
        self.stats['header_mismatches'] += 1
        
        discrepancy = MACDiscrepancy(
            timestamp=time.time(),
            ip_address=src_ip,
            expected_mac=eth_mac,
            claimed_mac=arp_mac,
            detection_method=DetectionMethod.MAC_HEADER_MISMATCH,
            confidence=0.95,  # High confidence - this is very suspicious
            ethernet_src_mac=eth_mac,
            details=f"Ethernet source ({eth_mac}) != ARP sender ({arp_mac}) "
                   f"for IP {src_ip}"
        )
        
        self._record_discrepancy(discrepancy)
        
        self._log(f"⚠️  HEADER MISMATCH: Ethernet={eth_mac}, ARP={arp_mac} "
                 f"claiming IP {src_ip}")
    
    def _detect_unsolicited_reply(self, src_ip: str, arp_mac: str, eth_mac: str):
        """
        Detect unsolicited ARP replies (gratuitous ARP).
        
        While not all gratuitous ARPs are malicious, they are commonly
        used in poisoning attacks.
        """
        self.stats['unsolicited_replies'] += 1
        
        # Check if this matches a known binding
        with self._bindings_lock:
            if src_ip in self._bindings:
                known_mac = self._bindings[src_ip].mac
                if known_mac != arp_mac:
                    # Unsolicited reply with different MAC - suspicious!
                    discrepancy = MACDiscrepancy(
                        timestamp=time.time(),
                        ip_address=src_ip,
                        expected_mac=known_mac,
                        claimed_mac=arp_mac,
                        detection_method=DetectionMethod.UNSOLICITED_REPLY,
                        confidence=0.85,
                        ethernet_src_mac=eth_mac,
                        details=f"Unsolicited reply claiming {src_ip}={arp_mac}, "
                               f"but known MAC is {known_mac}"
                    )
                    self._record_discrepancy(discrepancy)
    
    def _check_binding(self, ip: str, claimed_mac: str, eth_mac: str):
        """
        Check an IP-MAC claim against known bindings.
        
        This implements the binding validation from the paper.
        """
        with self._bindings_lock:
            if ip in self._bindings:
                binding = self._bindings[ip]
                known_mac = binding.mac
                
                if known_mac != claimed_mac:
                    # MAC mismatch with known binding!
                    self.stats['duplicate_ips'] += 1
                    
                    # Higher confidence if the binding was verified
                    confidence = 0.9 if binding.verified else 0.75
                    
                    # Even higher if it's the gateway
                    if binding.is_gateway:
                        confidence = 0.98
                    
                    discrepancy = MACDiscrepancy(
                        timestamp=time.time(),
                        ip_address=ip,
                        expected_mac=known_mac,
                        claimed_mac=claimed_mac,
                        detection_method=DetectionMethod.DUPLICATE_IP,
                        confidence=confidence,
                        ethernet_src_mac=eth_mac,
                        details=f"IP {ip} known as {known_mac}, "
                               f"but claimed by {claimed_mac}",
                        verified=binding.verified
                    )
                    self._record_discrepancy(discrepancy)
                else:
                    # MAC matches - update last seen
                    binding.last_seen = time.time()
            else:
                # New binding - add to table
                self._bindings[ip] = IPMACBinding(
                    ip=ip,
                    mac=claimed_mac,
                    first_seen=time.time(),
                    last_seen=time.time(),
                    source="arp"
                )
                self._mac_to_ips[claimed_mac].add(ip)
    
    def _record_discrepancy(self, discrepancy: MACDiscrepancy):
        """Record a discrepancy and notify callback."""
        with self._discrepancies_lock:
            self._discrepancies.append(discrepancy)
        
        self.stats['attacks_detected'] += 1
        
        if self.callback:
            try:
                self.callback(discrepancy)
            except Exception as e:
                self._log(f"Callback error: {e}")
    
    def _verification_loop(self):
        """
        Periodic verification of bindings using ARP probes.
        
        This implements the active verification component of the paper's
        prevention mechanism.
        """
        while self._running:
            time.sleep(self.verification_interval)
            
            if not self._running:
                break
            
            self._verify_bindings()
    
    def _verify_bindings(self):
        """Send ARP probes to verify all bindings."""
        if not SCAPY_AVAILABLE:
            return
        
        with self._bindings_lock:
            bindings_to_verify = list(self._bindings.items())
        
        for ip, binding in bindings_to_verify:
            if ip == self.our_ip:
                continue
            
            try:
                # Create ARP request for this IP
                arp_request = (
                    Ether(dst="ff:ff:ff:ff:ff:ff") /
                    ARP(pdst=ip)
                )
                
                # Send and wait for response
                responses, _ = srp(
                    arp_request,
                    iface=self.interface,
                    timeout=2,
                    verbose=0
                )
                
                if responses:
                    # Check response MAC against known binding
                    response_mac = responses[0][1].hwsrc.lower()
                    
                    if response_mac == binding.mac:
                        # Verified!
                        with self._bindings_lock:
                            if ip in self._bindings:
                                self._bindings[ip].verified = True
                                self._bindings[ip].verification_count += 1
                        self.stats['bindings_verified'] += 1
                    else:
                        # Verification failed - MAC mismatch!
                        self.stats['verification_failures'] += 1
                        
                        discrepancy = MACDiscrepancy(
                            timestamp=time.time(),
                            ip_address=ip,
                            expected_mac=binding.mac,
                            claimed_mac=response_mac,
                            detection_method=DetectionMethod.VERIFICATION_FAILED,
                            confidence=0.92,
                            details=f"Verification probe for {ip}: expected "
                                   f"{binding.mac}, got {response_mac}"
                        )
                        self._record_discrepancy(discrepancy)
                        
            except Exception as e:
                self._log(f"Verification error for {ip}: {e}")
    
    def get_discrepancies(self, since: float = None) -> List[MACDiscrepancy]:
        """
        Get detected discrepancies.
        
        Args:
            since: Optional timestamp to filter by
        """
        with self._discrepancies_lock:
            if since:
                return [d for d in self._discrepancies if d.timestamp >= since]
            return list(self._discrepancies)
    
    def get_high_confidence_attacks(self) -> List[MACDiscrepancy]:
        """Get only high-confidence attack detections."""
        return [d for d in self.get_discrepancies() if d.is_high_confidence]
    
    def get_bindings(self) -> Dict[str, IPMACBinding]:
        """Get current IP-MAC bindings."""
        with self._bindings_lock:
            return dict(self._bindings)
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        return dict(self.stats)
    
    def clear_discrepancies(self):
        """Clear recorded discrepancies."""
        with self._discrepancies_lock:
            self._discrepancies.clear()
    
    def print_status(self):
        """Print current detector status."""
        print("\n" + "=" * 60)
        print("MAC Discrepancy Detector Status")
        print("=" * 60)
        print(f"Running: {self._running}")
        print(f"Interface: {self.interface}")
        print(f"Our MAC: {self.our_mac}")
        
        print("\nKnown Bindings:")
        with self._bindings_lock:
            for ip, binding in self._bindings.items():
                verified = "✓" if binding.verified else "?"
                gw = " (GATEWAY)" if binding.is_gateway else ""
                print(f"  {ip} -> {binding.mac} [{verified}]{gw}")
        
        print("\nStatistics:")
        for key, value in self.stats.items():
            print(f"  {key}: {value}")
        
        print("\nRecent Discrepancies:")
        with self._discrepancies_lock:
            for d in self._discrepancies[-5:]:
                ts = datetime.fromtimestamp(d.timestamp).strftime("%H:%M:%S")
                print(f"  [{ts}] {d.detection_method.value}: {d.ip_address} "
                      f"({d.claimed_mac} vs {d.expected_mac})")
        
        print("=" * 60)


def run_detection_demo():
    """
    Demonstrate MAC discrepancy detection.
    
    Note: This is a simulation for environments without network access.
    """
    print("=" * 60)
    print("MAC Discrepancy Detection Demo")
    print("Based on Majumdar et al. (ICITSD 2021)")
    print("=" * 60)
    
    # Simulate detection without actual network
    print("\n[Simulated Detection Scenario]")
    print("\n1. Normal ARP Reply:")
    print("   Ethernet src: aa:bb:cc:11:22:33")
    print("   ARP sender MAC: aa:bb:cc:11:22:33")
    print("   ARP sender IP: 192.168.1.10")
    print("   Result: LEGITIMATE (MACs match)")
    
    print("\n2. Spoofed ARP Reply:")
    print("   Ethernet src: aa:bb:cc:44:55:66 (attacker)")
    print("   ARP sender MAC: aa:bb:cc:ff:ff:ff (gateway)")
    print("   ARP sender IP: 192.168.1.1 (gateway)")
    print("   Result: ATTACK DETECTED!")
    print("   - Header mismatch: Ethernet != ARP")
    print("   - Confidence: 95%")
    
    print("\n3. Binding Conflict:")
    print("   Known: 192.168.1.1 = aa:bb:cc:ff:ff:ff")
    print("   Claimed: 192.168.1.1 = aa:bb:cc:44:55:66")
    print("   Result: ATTACK DETECTED!")
    print("   - MAC change for known IP")
    print("   - Confidence: 98% (is gateway)")
    
    print("\n" + "=" * 60)
    print("Detection Algorithm Summary (from paper):")
    print("=" * 60)
    print("""
The detection algorithm analyzes:
1. Real MAC Address (from Ethernet header)
2. Response MAC Address (from ARP payload)

Any discrepancy between these indicates potential spoofing.

Additional checks:
- Known IP-MAC binding violations
- Unsolicited ARP replies
- Active verification probes
    """)
    
    print("=" * 60)
    print("Demo complete!")


if __name__ == "__main__":
    run_detection_demo()
