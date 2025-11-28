"""
ARP Poisoning Detector with TCP SYN Validation

This module implements ARP spoofing detection using TCP SYN validation,
inspired by rnehra01/arp-validator.

The core concept: When we receive an ARP reply mapping IP->MAC,
we validate it by sending a TCP SYN to the IP. If the response
comes from a different MAC than claimed, it's likely spoofed.

Author: Security Research Team
"""

import threading
import time
import socket
import random
from typing import Optional, Dict, List, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum

try:
    from scapy.all import (
        Ether, ARP, IP, TCP, ICMP,
        sniff, sendp, send, sr1, conf,
        get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.network_utils import (
    get_mac_address, get_ip_address, get_arp_table,
    get_gateway_info, validate_interface
)
from config.settings import ARPConfig


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ARPAlert:
    """Represents an ARP poisoning alert"""
    timestamp: datetime
    severity: AlertSeverity
    alert_type: str
    source_ip: str
    source_mac: str
    claimed_ip: Optional[str] = None
    expected_mac: Optional[str] = None
    actual_mac: Optional[str] = None
    description: str = ""
    validated: bool = False
    
    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'alert_type': self.alert_type,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'claimed_ip': self.claimed_ip,
            'expected_mac': self.expected_mac,
            'actual_mac': self.actual_mac,
            'description': self.description,
            'validated': self.validated
        }


@dataclass
class ARPEntry:
    """Tracked ARP entry with validation info"""
    ip: str
    mac: str
    first_seen: datetime
    last_seen: datetime
    validated: bool = False
    validation_method: Optional[str] = None
    change_count: int = 0
    is_gateway: bool = False
    is_static: bool = False


class ARPDetector:
    """
    ARP Poisoning Detector
    
    Monitors ARP traffic and detects potential poisoning attacks using:
    1. ARP table change monitoring
    2. Duplicate IP detection
    3. Gratuitous ARP detection
    4. TCP SYN validation (inspired by arp-validator)
    5. MAC address anomaly detection
    
    Based on patterns from rnehra01/arp-validator
    """
    
    def __init__(
        self,
        interface: str,
        validate_with_tcp: bool = True,
        validation_timeout: float = 2.0,
        alert_callback: Optional[Callable[[ARPAlert], None]] = None,
        verbose: bool = True
    ):
        """
        Initialize ARP Detector
        
        Args:
            interface: Network interface to monitor
            validate_with_tcp: Enable TCP SYN validation
            validation_timeout: Timeout for TCP validation
            alert_callback: Function to call when alert is generated
            verbose: Enable verbose logging
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for ARP detection")
            
        self.interface = interface
        self.validate_with_tcp = validate_with_tcp
        self.validation_timeout = validation_timeout
        self.alert_callback = alert_callback
        self.verbose = verbose
        
        # Validate interface
        if not validate_interface(interface):
            raise ValueError(f"Invalid interface: {interface}")
            
        # Get our own addresses
        self.our_mac = get_mac_address(interface)
        self.our_ip = get_ip_address(interface)
        
        # Get gateway info
        gw_info = get_gateway_info(interface)
        self.gateway_ip = gw_info['ip'] if gw_info else None
        self.gateway_mac = gw_info.get('mac') if gw_info else None
        
        # State
        self._running = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._validation_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # ARP table tracking
        self._arp_table: Dict[str, ARPEntry] = {}
        self._arp_table_lock = threading.Lock()
        
        # Validation queue
        self._validation_queue: List[Tuple[str, str]] = []
        self._validation_lock = threading.Lock()
        
        # Alert history
        self.alerts: List[ARPAlert] = []
        
        # Statistics
        self.stats = {
            'arp_packets_seen': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'gratuitous_arps': 0,
            'validations_performed': 0,
            'validations_passed': 0,
            'validations_failed': 0,
            'alerts_generated': 0,
            'mac_changes_detected': 0
        }
        
        # Known MAC vendor prefixes for anomaly detection
        self._known_vendors = set()
        
        # Configure Scapy
        conf.verb = 0
        
        # Initialize with current ARP table
        self._initialize_arp_table()
        
        self._log(f"ARP Detector initialized on {interface}")
        self._log(f"  Our IP: {self.our_ip} ({self.our_mac})")
        self._log(f"  Gateway: {self.gateway_ip} ({self.gateway_mac})")
        
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [ARPDetector] {message}")
            
    def _initialize_arp_table(self):
        """Initialize ARP table from system"""
        current_table = get_arp_table()
        
        with self._arp_table_lock:
            for ip, info in current_table.items():
                self._arp_table[ip] = ARPEntry(
                    ip=ip,
                    mac=info['mac'],
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    validated=False,
                    is_gateway=(ip == self.gateway_ip),
                    is_static=info.get('type', '').lower() == 'static'
                )
                
        self._log(f"Initialized with {len(self._arp_table)} ARP entries")
        
    def _generate_alert(
        self,
        severity: AlertSeverity,
        alert_type: str,
        source_ip: str,
        source_mac: str,
        description: str,
        **kwargs
    ):
        """Generate and process an alert"""
        alert = ARPAlert(
            timestamp=datetime.now(),
            severity=severity,
            alert_type=alert_type,
            source_ip=source_ip,
            source_mac=source_mac,
            description=description,
            **kwargs
        )
        
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        self._log(f"ALERT [{severity.value.upper()}]: {description}")
        
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                self._log(f"Alert callback error: {e}")
                
    def _is_gratuitous_arp(self, packet) -> bool:
        """Check if packet is a gratuitous ARP"""
        if not packet.haslayer(ARP):
            return False
            
        arp = packet[ARP]
        
        # Gratuitous ARP: source and destination IP are the same
        if arp.psrc == arp.pdst:
            return True
            
        # Also check for broadcast destination with reply
        if arp.op == 2 and packet[Ether].dst == "ff:ff:ff:ff:ff:ff":
            return True
            
        return False
        
    def _process_arp_packet(self, packet):
        """Process an ARP packet"""
        if not packet.haslayer(ARP):
            return
            
        self.stats['arp_packets_seen'] += 1
        
        arp = packet[ARP]
        source_ip = arp.psrc
        source_mac = arp.hwsrc
        
        # Track request vs reply
        if arp.op == 1:  # ARP request
            self.stats['arp_requests'] += 1
        elif arp.op == 2:  # ARP reply
            self.stats['arp_replies'] += 1
            
        # Check for gratuitous ARP
        if self._is_gratuitous_arp(packet):
            self.stats['gratuitous_arps'] += 1
            self._handle_gratuitous_arp(source_ip, source_mac)
            
        # Ignore our own packets
        if source_mac == self.our_mac:
            return
            
        # Check for IP conflicts with our address
        if source_ip == self.our_ip and source_mac != self.our_mac:
            self._generate_alert(
                AlertSeverity.CRITICAL,
                "ip_conflict",
                source_ip,
                source_mac,
                f"IP conflict! {source_ip} claimed by {source_mac}",
                expected_mac=self.our_mac,
                actual_mac=source_mac
            )
            return
            
        # Check for gateway spoofing
        if source_ip == self.gateway_ip and self.gateway_mac:
            if source_mac != self.gateway_mac:
                self._generate_alert(
                    AlertSeverity.CRITICAL,
                    "gateway_spoof",
                    source_ip,
                    source_mac,
                    f"Gateway MAC changed! {self.gateway_ip}: "
                    f"{self.gateway_mac} -> {source_mac}",
                    expected_mac=self.gateway_mac,
                    actual_mac=source_mac,
                    claimed_ip=self.gateway_ip
                )
                
                # Queue for validation
                if self.validate_with_tcp:
                    self._queue_validation(source_ip, source_mac)
                return
                
        # Check for MAC changes in known entries
        with self._arp_table_lock:
            if source_ip in self._arp_table:
                entry = self._arp_table[source_ip]
                
                if entry.mac != source_mac:
                    # MAC address changed!
                    self.stats['mac_changes_detected'] += 1
                    
                    severity = AlertSeverity.HIGH
                    if entry.is_gateway:
                        severity = AlertSeverity.CRITICAL
                    elif entry.validated:
                        severity = AlertSeverity.HIGH
                    else:
                        severity = AlertSeverity.MEDIUM
                        
                    self._generate_alert(
                        severity,
                        "mac_change",
                        source_ip,
                        source_mac,
                        f"MAC change detected: {source_ip}: "
                        f"{entry.mac} -> {source_mac}",
                        expected_mac=entry.mac,
                        actual_mac=source_mac
                    )
                    
                    # Update entry
                    entry.mac = source_mac
                    entry.change_count += 1
                    entry.last_seen = datetime.now()
                    entry.validated = False
                    
                    # Queue for validation
                    if self.validate_with_tcp:
                        self._queue_validation(source_ip, source_mac)
                else:
                    # Same MAC, update last seen
                    entry.last_seen = datetime.now()
            else:
                # New entry
                self._arp_table[source_ip] = ARPEntry(
                    ip=source_ip,
                    mac=source_mac,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    is_gateway=(source_ip == self.gateway_ip)
                )
                
    def _handle_gratuitous_arp(self, ip: str, mac: str):
        """Handle gratuitous ARP - often used in attacks"""
        with self._arp_table_lock:
            if ip in self._arp_table:
                entry = self._arp_table[ip]
                
                if entry.mac != mac:
                    # Gratuitous ARP with different MAC - suspicious!
                    self._generate_alert(
                        AlertSeverity.HIGH,
                        "gratuitous_arp_spoof",
                        ip,
                        mac,
                        f"Gratuitous ARP with MAC change: {ip}: "
                        f"{entry.mac} -> {mac}",
                        expected_mac=entry.mac,
                        actual_mac=mac
                    )
                    
                    if self.validate_with_tcp:
                        self._queue_validation(ip, mac)
            else:
                # New IP announced via gratuitous ARP
                self._generate_alert(
                    AlertSeverity.LOW,
                    "gratuitous_arp_new",
                    ip,
                    mac,
                    f"New IP announced via gratuitous ARP: {ip} ({mac})"
                )
                
    def _queue_validation(self, ip: str, mac: str):
        """Queue an IP/MAC pair for TCP validation"""
        with self._validation_lock:
            if (ip, mac) not in self._validation_queue:
                self._validation_queue.append((ip, mac))
                
    def _validate_with_tcp_syn(self, ip: str, claimed_mac: str) -> bool:
        """
        Validate IP/MAC mapping using TCP SYN
        
        Send a TCP SYN packet and check if the response comes
        from the claimed MAC address.
        
        Returns True if validation passes (MAC matches)
        """
        self.stats['validations_performed'] += 1
        
        try:
            # Pick a random high port
            src_port = random.randint(40000, 60000)
            dst_port = 80  # Try HTTP port first
            
            # Build TCP SYN packet
            syn_packet = IP(dst=ip) / TCP(
                sport=src_port,
                dport=dst_port,
                flags='S',
                seq=random.randint(0, 2**32 - 1)
            )
            
            # Send and wait for response
            response = sr1(
                syn_packet,
                timeout=self.validation_timeout,
                verbose=0,
                iface=self.interface
            )
            
            if response:
                # Check the MAC address in the Ethernet header
                if response.haslayer(Ether):
                    response_mac = response[Ether].src
                    
                    if response_mac.lower() == claimed_mac.lower():
                        self.stats['validations_passed'] += 1
                        self._log(f"TCP validation PASSED for {ip}")
                        
                        # Mark as validated
                        with self._arp_table_lock:
                            if ip in self._arp_table:
                                self._arp_table[ip].validated = True
                                self._arp_table[ip].validation_method = 'tcp_syn'
                        return True
                    else:
                        self.stats['validations_failed'] += 1
                        self._generate_alert(
                            AlertSeverity.CRITICAL,
                            "tcp_validation_failed",
                            ip,
                            response_mac,
                            f"TCP validation FAILED! Response from {response_mac}, "
                            f"expected {claimed_mac}",
                            expected_mac=claimed_mac,
                            actual_mac=response_mac,
                            validated=True
                        )
                        return False
                        
            # No response - try ICMP
            return self._validate_with_icmp(ip, claimed_mac)
            
        except Exception as e:
            self._log(f"TCP validation error: {e}")
            return False
            
    def _validate_with_icmp(self, ip: str, claimed_mac: str) -> bool:
        """Fallback validation using ICMP ping"""
        try:
            icmp_packet = IP(dst=ip) / ICMP()
            response = sr1(
                icmp_packet,
                timeout=self.validation_timeout,
                verbose=0,
                iface=self.interface
            )
            
            if response and response.haslayer(Ether):
                response_mac = response[Ether].src
                
                if response_mac.lower() == claimed_mac.lower():
                    self.stats['validations_passed'] += 1
                    self._log(f"ICMP validation PASSED for {ip}")
                    
                    with self._arp_table_lock:
                        if ip in self._arp_table:
                            self._arp_table[ip].validated = True
                            self._arp_table[ip].validation_method = 'icmp'
                    return True
                else:
                    self.stats['validations_failed'] += 1
                    return False
                    
        except Exception as e:
            self._log(f"ICMP validation error: {e}")
            
        return False
        
    def _validation_loop(self):
        """Validation loop running in thread"""
        self._log("Starting validation loop...")
        
        while not self._stop_event.is_set():
            # Get next validation target
            target = None
            with self._validation_lock:
                if self._validation_queue:
                    target = self._validation_queue.pop(0)
                    
            if target:
                ip, mac = target
                self._validate_with_tcp_syn(ip, mac)
            else:
                self._stop_event.wait(0.5)
                
        self._log("Validation loop stopped")
        
    def _sniff_loop(self):
        """ARP sniffing loop"""
        self._log("Starting ARP monitor...")
        
        try:
            sniff(
                iface=self.interface,
                filter="arp",
                prn=self._process_arp_packet,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception as e:
            self._log(f"Sniff error: {e}")
            
        self._log("ARP monitor stopped")
        
    def start(self):
        """Start the ARP detector"""
        if self._running:
            return
            
        self._log("Starting ARP detector...")
        self._running = True
        self._stop_event.clear()
        
        # Start sniffing thread
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="ARPSniffThread"
        )
        self._sniff_thread.start()
        
        # Start validation thread
        if self.validate_with_tcp:
            self._validation_thread = threading.Thread(
                target=self._validation_loop,
                daemon=True,
                name="ARPValidationThread"
            )
            self._validation_thread.start()
            
        self._log("ARP detector started")
        
    def stop(self):
        """Stop the ARP detector"""
        if not self._running:
            return
            
        self._log("Stopping ARP detector...")
        self._running = False
        self._stop_event.set()
        
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=2)
            
        if self._validation_thread and self._validation_thread.is_alive():
            self._validation_thread.join(timeout=2)
            
        self._log("ARP detector stopped")
        
    def get_arp_table(self) -> Dict[str, Dict]:
        """Get current tracked ARP table"""
        with self._arp_table_lock:
            return {
                ip: {
                    'mac': entry.mac,
                    'first_seen': entry.first_seen.isoformat(),
                    'last_seen': entry.last_seen.isoformat(),
                    'validated': entry.validated,
                    'validation_method': entry.validation_method,
                    'change_count': entry.change_count,
                    'is_gateway': entry.is_gateway,
                    'is_static': entry.is_static
                }
                for ip, entry in self._arp_table.items()
            }
            
    def get_alerts(self, severity: Optional[AlertSeverity] = None) -> List[Dict]:
        """Get alerts, optionally filtered by severity"""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return [a.to_dict() for a in alerts]
        
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return dict(self.stats)
        
    def is_running(self) -> bool:
        """Check if detector is running"""
        return self._running
        
    def clear_alerts(self):
        """Clear alert history"""
        self.alerts.clear()


def main():
    """Demo/test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ARP Detector")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-d", "--duration", type=float, default=60, help="Duration")
    parser.add_argument("--no-validate", action="store_true", help="Disable TCP validation")
    
    args = parser.parse_args()
    
    def alert_handler(alert: ARPAlert):
        print(f"\n🚨 ALERT: {alert.description}")
        
    detector = ARPDetector(
        interface=args.interface,
        validate_with_tcp=not args.no_validate,
        alert_callback=alert_handler
    )
    
    print(f"[*] Monitoring ARP traffic for {args.duration} seconds...")
    detector.start()
    
    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        
    detector.stop()
    
    # Print summary
    stats = detector.get_statistics()
    print(f"\n[*] Statistics:")
    print(f"    ARP packets seen: {stats['arp_packets_seen']}")
    print(f"    Requests/Replies: {stats['arp_requests']}/{stats['arp_replies']}")
    print(f"    Gratuitous ARPs: {stats['gratuitous_arps']}")
    print(f"    Alerts: {stats['alerts_generated']}")
    print(f"    Validations: {stats['validations_performed']} "
          f"(passed: {stats['validations_passed']}, failed: {stats['validations_failed']})")


if __name__ == "__main__":
    main()
