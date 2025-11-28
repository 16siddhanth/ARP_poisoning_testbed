"""
Simulated Dynamic ARP Inspection (DAI) Module.

This module simulates switch-level ARP inspection as would be found in
enterprise network switches. It implements DHCP snooping binding database
and DAI validation at the switch/bridge level.

Reference: Cisco Dynamic ARP Inspection (DAI) and similar enterprise features.
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any, Set
from enum import Enum
from collections import defaultdict


logger = logging.getLogger(__name__)


class DAIAction(Enum):
    """Actions that DAI can take on packets."""
    PERMIT = "permit"
    DENY = "deny"
    LOG = "log"
    LOG_AND_DENY = "log_and_deny"


class DAIViolationType(Enum):
    """Types of DAI violations."""
    INVALID_MAC = "invalid_mac"           # Source MAC mismatch
    INVALID_IP = "invalid_ip"             # Source IP mismatch
    UNKNOWN_BINDING = "unknown_binding"   # No DHCP binding exists
    RATE_LIMIT_EXCEEDED = "rate_limit"    # Too many ARP packets
    DUPLICATE_IP = "duplicate_ip"         # IP address conflict
    GRATUITOUS_ARP = "gratuitous_arp"     # Unsolicited gratuitous ARP


@dataclass
class DHCPBinding:
    """
    DHCP Snooping binding entry.
    
    In real switches, this comes from DHCP snooping. Here we simulate it
    or allow manual configuration.
    """
    mac_address: str
    ip_address: str
    vlan: int = 1
    interface: str = ""
    lease_time: int = 86400  # seconds
    binding_type: str = "dynamic"  # dynamic, static
    timestamp: float = field(default_factory=time.time)
    
    def is_valid(self) -> bool:
        """Check if binding is still valid (not expired)."""
        if self.binding_type == "static":
            return True
        return (time.time() - self.timestamp) < self.lease_time


@dataclass
class DAIViolation:
    """Record of a DAI violation."""
    timestamp: float
    violation_type: DAIViolationType
    interface: str
    src_mac: str
    src_ip: str
    dst_ip: str
    action_taken: DAIAction
    details: str = ""


@dataclass
class PortConfig:
    """Per-port DAI configuration."""
    interface: str
    trusted: bool = False          # Trusted ports bypass DAI
    rate_limit: int = 15           # ARP packets per second
    burst: int = 6                 # Burst allowance
    enabled: bool = True
    log_violations: bool = True


class DHCPSnoopingDatabase:
    """
    Simulated DHCP Snooping Binding Database.
    
    In production, this is populated by snooping DHCP traffic.
    For testing, we provide methods to manually add bindings.
    """
    
    def __init__(self):
        self._bindings: Dict[str, DHCPBinding] = {}  # keyed by MAC
        self._ip_index: Dict[str, str] = {}  # IP -> MAC for fast lookup
        self._lock = threading.RLock()
    
    def add_binding(self, binding: DHCPBinding):
        """Add or update a DHCP binding."""
        with self._lock:
            self._bindings[binding.mac_address.lower()] = binding
            self._ip_index[binding.ip_address] = binding.mac_address.lower()
    
    def remove_binding(self, mac_address: str):
        """Remove a binding by MAC address."""
        with self._lock:
            mac = mac_address.lower()
            if mac in self._bindings:
                binding = self._bindings[mac]
                del self._bindings[mac]
                if binding.ip_address in self._ip_index:
                    del self._ip_index[binding.ip_address]
    
    def get_binding_by_mac(self, mac_address: str) -> Optional[DHCPBinding]:
        """Get binding for a MAC address."""
        with self._lock:
            return self._bindings.get(mac_address.lower())
    
    def get_binding_by_ip(self, ip_address: str) -> Optional[DHCPBinding]:
        """Get binding for an IP address."""
        with self._lock:
            mac = self._ip_index.get(ip_address)
            if mac:
                return self._bindings.get(mac)
            return None
    
    def validate_binding(self, mac_address: str, ip_address: str) -> bool:
        """
        Validate that a MAC-IP pair matches our binding database.
        
        This is the core of DAI validation.
        """
        with self._lock:
            binding = self._bindings.get(mac_address.lower())
            if not binding:
                return False
            if not binding.is_valid():
                return False
            return binding.ip_address == ip_address
    
    def get_all_bindings(self) -> List[DHCPBinding]:
        """Get all current bindings."""
        with self._lock:
            return [b for b in self._bindings.values() if b.is_valid()]
    
    def clear(self):
        """Clear all bindings."""
        with self._lock:
            self._bindings.clear()
            self._ip_index.clear()
    
    def import_static_entries(self, entries: List[Dict[str, str]]):
        """
        Import static binding entries.
        
        Args:
            entries: List of dicts with 'mac', 'ip', and optionally 'interface', 'vlan'
        """
        for entry in entries:
            binding = DHCPBinding(
                mac_address=entry['mac'],
                ip_address=entry['ip'],
                interface=entry.get('interface', ''),
                vlan=entry.get('vlan', 1),
                binding_type="static"
            )
            self.add_binding(binding)


class RateLimiter:
    """Per-port rate limiter for ARP packets."""
    
    def __init__(self, rate: int = 15, burst: int = 6):
        self.rate = rate  # packets per second
        self.burst = burst
        self._tokens = burst
        self._last_update = time.time()
        self._lock = threading.Lock()
    
    def allow(self) -> bool:
        """Check if packet should be allowed based on rate limit."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            self._last_update = now
            
            # Add tokens based on elapsed time
            self._tokens = min(
                self.burst,
                self._tokens + elapsed * self.rate
            )
            
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False
    
    def reset(self):
        """Reset the rate limiter."""
        with self._lock:
            self._tokens = self.burst
            self._last_update = time.time()


class DynamicARPInspector:
    """
    Simulated Dynamic ARP Inspection (DAI) Switch Feature.
    
    This class simulates enterprise switch DAI functionality for testing
    ARP attack scenarios without requiring actual network hardware.
    
    Features:
    - DHCP Snooping binding validation
    - Per-port trust configuration
    - Rate limiting
    - Violation logging and statistics
    - Multiple validation modes
    """
    
    def __init__(self, vlan_id: int = 1):
        self.vlan_id = vlan_id
        self.enabled = True
        
        # DHCP Snooping binding database
        self.binding_db = DHCPSnoopingDatabase()
        
        # Port configurations
        self.port_configs: Dict[str, PortConfig] = {}
        self.rate_limiters: Dict[str, RateLimiter] = {}
        
        # Validation options
        self.validate_src_mac = True   # Validate Ethernet src MAC matches ARP src MAC
        self.validate_dst_mac = True   # Validate for unicast ARP
        self.validate_ip = True        # Validate IP against binding database
        self.drop_gratuitous = False   # Drop gratuitous ARP by default
        
        # Violation tracking
        self.violations: List[DAIViolation] = []
        self.violation_callbacks: List[Callable[[DAIViolation], None]] = []
        
        # Statistics
        self.stats = {
            'packets_inspected': 0,
            'packets_permitted': 0,
            'packets_denied': 0,
            'violations_logged': 0,
            'rate_limit_drops': 0,
        }
        self._stats_lock = threading.Lock()
        
        # ARP cache for additional tracking
        self._observed_bindings: Dict[str, Set[str]] = defaultdict(set)  # MAC -> IPs seen
    
    def configure_port(self, interface: str, trusted: bool = False,
                      rate_limit: int = 15, burst: int = 6):
        """
        Configure DAI settings for a port.
        
        Args:
            interface: Port/interface name
            trusted: If True, port bypasses DAI (e.g., uplink to router)
            rate_limit: Max ARP packets per second
            burst: Burst tolerance
        """
        self.port_configs[interface] = PortConfig(
            interface=interface,
            trusted=trusted,
            rate_limit=rate_limit,
            burst=burst
        )
        self.rate_limiters[interface] = RateLimiter(rate_limit, burst)
    
    def add_trusted_binding(self, mac: str, ip: str, interface: str = ""):
        """
        Add a static trusted binding to the database.
        
        This simulates entries from DHCP snooping or static configuration.
        """
        binding = DHCPBinding(
            mac_address=mac,
            ip_address=ip,
            interface=interface,
            binding_type="static"
        )
        self.binding_db.add_binding(binding)
    
    def register_violation_callback(self, callback: Callable[[DAIViolation], None]):
        """Register a callback to be called on violations."""
        self.violation_callbacks.append(callback)
    
    def inspect_arp_packet(self, interface: str, eth_src_mac: str, eth_dst_mac: str,
                           arp_src_mac: str, arp_src_ip: str,
                           arp_dst_mac: str, arp_dst_ip: str,
                           is_reply: bool = False) -> DAIAction:
        """
        Inspect an ARP packet and determine action.
        
        This is the main inspection function called for each ARP packet.
        
        Args:
            interface: Ingress interface/port
            eth_src_mac: Ethernet frame source MAC
            eth_dst_mac: Ethernet frame destination MAC
            arp_src_mac: ARP payload source MAC (sender hardware address)
            arp_src_ip: ARP payload source IP (sender protocol address)
            arp_dst_mac: ARP payload destination MAC (target hardware address)
            arp_dst_ip: ARP payload destination IP (target protocol address)
            is_reply: True if this is an ARP reply
        
        Returns:
            Action to take (PERMIT, DENY, LOG, LOG_AND_DENY)
        """
        with self._stats_lock:
            self.stats['packets_inspected'] += 1
        
        if not self.enabled:
            return DAIAction.PERMIT
        
        # Check if port is trusted
        port_config = self.port_configs.get(interface)
        if port_config and port_config.trusted:
            with self._stats_lock:
                self.stats['packets_permitted'] += 1
            return DAIAction.PERMIT
        
        # Check rate limit
        rate_limiter = self.rate_limiters.get(interface)
        if rate_limiter and not rate_limiter.allow():
            violation = self._record_violation(
                DAIViolationType.RATE_LIMIT_EXCEEDED,
                interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                "Rate limit exceeded"
            )
            with self._stats_lock:
                self.stats['rate_limit_drops'] += 1
                self.stats['packets_denied'] += 1
            return DAIAction.DENY
        
        # Check for gratuitous ARP
        if arp_src_ip == arp_dst_ip:
            if self.drop_gratuitous:
                violation = self._record_violation(
                    DAIViolationType.GRATUITOUS_ARP,
                    interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                    "Gratuitous ARP detected"
                )
                with self._stats_lock:
                    self.stats['packets_denied'] += 1
                return DAIAction.LOG_AND_DENY
        
        # Validate source MAC consistency (Ethernet vs ARP)
        if self.validate_src_mac:
            if eth_src_mac.lower() != arp_src_mac.lower():
                violation = self._record_violation(
                    DAIViolationType.INVALID_MAC,
                    interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                    f"MAC mismatch: Ethernet src={eth_src_mac}, ARP src={arp_src_mac}"
                )
                with self._stats_lock:
                    self.stats['packets_denied'] += 1
                return DAIAction.LOG_AND_DENY
        
        # Validate against DHCP snooping database
        if self.validate_ip:
            if not self.binding_db.validate_binding(arp_src_mac, arp_src_ip):
                # Check if we have any binding for this MAC
                existing_binding = self.binding_db.get_binding_by_mac(arp_src_mac)
                
                if existing_binding:
                    # MAC exists but with different IP
                    violation = self._record_violation(
                        DAIViolationType.INVALID_IP,
                        interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                        f"IP mismatch: MAC {arp_src_mac} should have IP {existing_binding.ip_address}, "
                        f"not {arp_src_ip}"
                    )
                else:
                    # No binding exists at all
                    violation = self._record_violation(
                        DAIViolationType.UNKNOWN_BINDING,
                        interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                        f"No DHCP binding found for MAC {arp_src_mac}"
                    )
                
                with self._stats_lock:
                    self.stats['packets_denied'] += 1
                return DAIAction.LOG_AND_DENY
        
        # Track observed bindings for analysis
        self._observed_bindings[arp_src_mac.lower()].add(arp_src_ip)
        
        # Check for potential IP conflicts (same IP, different MAC)
        ip_binding = self.binding_db.get_binding_by_ip(arp_src_ip)
        if ip_binding and ip_binding.mac_address.lower() != arp_src_mac.lower():
            violation = self._record_violation(
                DAIViolationType.DUPLICATE_IP,
                interface, arp_src_mac, arp_src_ip, arp_dst_ip,
                f"Duplicate IP: {arp_src_ip} claimed by {arp_src_mac}, "
                f"but bound to {ip_binding.mac_address}"
            )
            with self._stats_lock:
                self.stats['packets_denied'] += 1
            return DAIAction.LOG_AND_DENY
        
        # All checks passed
        with self._stats_lock:
            self.stats['packets_permitted'] += 1
        return DAIAction.PERMIT
    
    def _record_violation(self, violation_type: DAIViolationType,
                         interface: str, src_mac: str, src_ip: str,
                         dst_ip: str, details: str) -> DAIViolation:
        """Record a violation and notify callbacks."""
        violation = DAIViolation(
            timestamp=time.time(),
            violation_type=violation_type,
            interface=interface,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            action_taken=DAIAction.LOG_AND_DENY,
            details=details
        )
        
        self.violations.append(violation)
        with self._stats_lock:
            self.stats['violations_logged'] += 1
        
        # Notify callbacks
        for callback in self.violation_callbacks:
            try:
                callback(violation)
            except Exception as e:
                logger.error(f"Violation callback error: {e}")
        
        logger.warning(f"DAI Violation [{violation_type.value}]: {details}")
        
        return violation
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get DAI statistics."""
        with self._stats_lock:
            return dict(self.stats)
    
    def get_violations(self, since: float = None) -> List[DAIViolation]:
        """
        Get recorded violations.
        
        Args:
            since: Optional timestamp to filter violations after
        """
        if since:
            return [v for v in self.violations if v.timestamp >= since]
        return list(self.violations)
    
    def get_violation_summary(self) -> Dict[str, int]:
        """Get summary of violations by type."""
        summary: Dict[str, int] = {}
        for violation in self.violations:
            key = violation.violation_type.value
            summary[key] = summary.get(key, 0) + 1
        return summary
    
    def clear_violations(self):
        """Clear violation history."""
        self.violations.clear()
    
    def reset_statistics(self):
        """Reset all statistics."""
        with self._stats_lock:
            for key in self.stats:
                self.stats[key] = 0
    
    def print_status(self):
        """Print current DAI status."""
        print("\n" + "=" * 60)
        print("Dynamic ARP Inspection (DAI) Status")
        print("=" * 60)
        print(f"VLAN: {self.vlan_id}")
        print(f"Enabled: {self.enabled}")
        print(f"Validate Source MAC: {self.validate_src_mac}")
        print(f"Validate IP (DHCP Binding): {self.validate_ip}")
        print(f"Drop Gratuitous ARP: {self.drop_gratuitous}")
        
        print("\nPort Configuration:")
        for port, config in self.port_configs.items():
            trust_status = "TRUSTED" if config.trusted else "UNTRUSTED"
            print(f"  {port}: {trust_status}, rate={config.rate_limit}/sec")
        
        print("\nDHCP Binding Database:")
        for binding in self.binding_db.get_all_bindings():
            print(f"  {binding.mac_address} -> {binding.ip_address} "
                  f"[{binding.binding_type}]")
        
        print("\nStatistics:")
        for key, value in self.get_statistics().items():
            print(f"  {key}: {value}")
        
        print("\nRecent Violations:")
        for violation in self.violations[-5:]:
            print(f"  [{violation.violation_type.value}] {violation.details}")
        
        print("=" * 60)


class SimulatedSwitch:
    """
    Simulated network switch with DAI capability.
    
    This provides a higher-level abstraction for testing ARP scenarios
    in a simulated switch environment.
    """
    
    def __init__(self, name: str = "SW1"):
        self.name = name
        self.ports: Dict[str, Dict] = {}
        self.dai = DynamicARPInspector()
        self.forwarding_table: Dict[str, str] = {}  # MAC -> port
        self._lock = threading.Lock()
    
    def add_port(self, port_name: str, trusted: bool = False,
                 connected_device: Dict = None):
        """Add a port to the switch."""
        with self._lock:
            self.ports[port_name] = {
                'name': port_name,
                'trusted': trusted,
                'connected_device': connected_device,
                'enabled': True
            }
            self.dai.configure_port(port_name, trusted=trusted)
    
    def add_dhcp_binding(self, mac: str, ip: str, port: str = ""):
        """Add a DHCP binding (simulates DHCP snooping)."""
        self.dai.add_trusted_binding(mac, ip, port)
    
    def receive_arp(self, ingress_port: str, eth_src: str, eth_dst: str,
                   arp_src_mac: str, arp_src_ip: str,
                   arp_dst_mac: str, arp_dst_ip: str,
                   is_reply: bool = False) -> bool:
        """
        Process an incoming ARP packet.
        
        Returns:
            True if packet was forwarded, False if dropped.
        """
        action = self.dai.inspect_arp_packet(
            ingress_port, eth_src, eth_dst,
            arp_src_mac, arp_src_ip, arp_dst_mac, arp_dst_ip,
            is_reply
        )
        
        return action in (DAIAction.PERMIT, DAIAction.LOG)
    
    def print_status(self):
        """Print switch status including DAI."""
        print(f"\n{'='*60}")
        print(f"Switch: {self.name}")
        print(f"{'='*60}")
        print("\nPorts:")
        for port_name, port_info in self.ports.items():
            status = "UP" if port_info['enabled'] else "DOWN"
            trust = "TRUSTED" if port_info['trusted'] else "UNTRUSTED"
            print(f"  {port_name}: {status}, {trust}")
        
        self.dai.print_status()


def run_dai_demo():
    """Demonstrate DAI functionality."""
    print("=" * 60)
    print("Simulated Dynamic ARP Inspection (DAI) Demo")
    print("=" * 60)
    
    # Create simulated switch
    switch = SimulatedSwitch("TestSwitch")
    
    # Configure ports
    print("\n[1] Configuring Switch Ports")
    switch.add_port("Gi0/1", trusted=False)  # User port
    switch.add_port("Gi0/2", trusted=False)  # User port (attacker)
    switch.add_port("Gi0/24", trusted=True)  # Uplink to router
    print("    Gi0/1: Untrusted (Victim)")
    print("    Gi0/2: Untrusted (Attacker)")
    print("    Gi0/24: Trusted (Router uplink)")
    
    # Add DHCP bindings
    print("\n[2] Adding DHCP Snooping Bindings")
    switch.add_dhcp_binding("aa:bb:cc:11:22:33", "192.168.1.10", "Gi0/1")  # Victim
    switch.add_dhcp_binding("aa:bb:cc:44:55:66", "192.168.1.20", "Gi0/2")  # Attacker
    switch.add_dhcp_binding("aa:bb:cc:ff:ff:ff", "192.168.1.1", "Gi0/24")  # Gateway
    print("    Victim: 192.168.1.10 -> aa:bb:cc:11:22:33")
    print("    Attacker: 192.168.1.20 -> aa:bb:cc:44:55:66")
    print("    Gateway: 192.168.1.1 -> aa:bb:cc:ff:ff:ff")
    
    # Test legitimate ARP
    print("\n[3] Testing Legitimate ARP from Victim")
    result = switch.receive_arp(
        "Gi0/1",
        "aa:bb:cc:11:22:33", "ff:ff:ff:ff:ff:ff",
        "aa:bb:cc:11:22:33", "192.168.1.10",
        "00:00:00:00:00:00", "192.168.1.1",
        is_reply=False
    )
    print(f"    ARP Request: {'PERMITTED' if result else 'DENIED'}")
    
    # Test ARP spoofing attack
    print("\n[4] Testing ARP Spoofing Attack")
    print("    Attacker trying to impersonate gateway (192.168.1.1)")
    
    result = switch.receive_arp(
        "Gi0/2",
        "aa:bb:cc:44:55:66", "aa:bb:cc:11:22:33",
        "aa:bb:cc:44:55:66", "192.168.1.1",  # Claiming to be gateway!
        "aa:bb:cc:11:22:33", "192.168.1.10",
        is_reply=True
    )
    print(f"    Spoofed ARP Reply: {'PERMITTED' if result else 'DENIED (BLOCKED!)'}")
    
    # Test MAC mismatch attack
    print("\n[5] Testing MAC Mismatch Attack")
    result = switch.receive_arp(
        "Gi0/2",
        "aa:bb:cc:44:55:66", "ff:ff:ff:ff:ff:ff",
        "aa:bb:cc:ff:ff:ff", "192.168.1.1",  # ARP MAC != Ethernet MAC
        "00:00:00:00:00:00", "192.168.1.10",
        is_reply=False
    )
    print(f"    MAC Mismatch ARP: {'PERMITTED' if result else 'DENIED (BLOCKED!)'}")
    
    # Print final status
    print("\n[6] Final Switch Status")
    switch.print_status()
    
    # Show violations
    print("\n[7] Violation Summary")
    summary = switch.dai.get_violation_summary()
    for violation_type, count in summary.items():
        print(f"    {violation_type}: {count}")
    
    print("\n" + "=" * 60)
    print("DAI Demo Complete - Attacks Successfully Blocked!")
    print("=" * 60)


if __name__ == "__main__":
    run_dai_demo()
