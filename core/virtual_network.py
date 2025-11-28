"""
Virtual network module for single-machine ARP testbed testing.

This module provides virtual interface management and simulated ARP operations
for environments where physical network testing is not possible.
"""

import platform
import subprocess
import threading
import queue
import time
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum


class VirtualInterfaceType(Enum):
    """Types of virtual interfaces supported."""
    LOOPBACK = "loopback"
    VETH_PAIR = "veth"  # Linux virtual ethernet pair
    TAP = "tap"         # TAP device
    BRIDGE = "bridge"   # Software bridge
    SIMULATED = "simulated"  # Fully software-simulated


@dataclass
class VirtualInterface:
    """Represents a virtual network interface."""
    name: str
    type: VirtualInterfaceType
    mac: str
    ip: str
    netmask: str = "255.255.255.0"
    gateway: str = ""
    peer: Optional[str] = None  # For veth pairs
    active: bool = True
    
    def __repr__(self):
        return f"VirtualInterface(name={self.name}, ip={self.ip}, mac={self.mac})"


@dataclass
class VirtualARPEntry:
    """Entry in the virtual ARP table."""
    ip: str
    mac: str
    interface: str
    static: bool = False
    timestamp: float = field(default_factory=time.time)


@dataclass
class VirtualPacket:
    """Simulated network packet for virtual testing."""
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    payload: bytes
    packet_type: str = "ARP"
    timestamp: float = field(default_factory=time.time)


class VirtualNetwork:
    """
    Simulated virtual network for single-machine ARP testing.
    
    This allows testing ARP attacks and defenses without requiring
    actual network hardware or multiple machines.
    """
    
    def __init__(self):
        self.interfaces: Dict[str, VirtualInterface] = {}
        self.arp_tables: Dict[str, Dict[str, VirtualARPEntry]] = {}
        self.packet_queues: Dict[str, queue.Queue] = {}
        self.packet_handlers: Dict[str, List[Callable]] = {}
        self._lock = threading.RLock()
        self._running = False
        self._network_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'arp_requests': 0,
            'arp_replies': 0,
            'packets_dropped': 0,
        }
        
        # Create default loopback simulation
        self._setup_default_interfaces()
    
    def _setup_default_interfaces(self):
        """Set up default simulated interfaces for testing."""
        # Simulated subnet: 10.0.0.0/24
        # Gateway at 10.0.0.1
        self.add_interface(VirtualInterface(
            name="veth0",
            type=VirtualInterfaceType.SIMULATED,
            mac="aa:bb:cc:dd:00:01",
            ip="10.0.0.2",
            gateway="10.0.0.1",
            peer="veth1"
        ))
        
        self.add_interface(VirtualInterface(
            name="veth1",
            type=VirtualInterfaceType.SIMULATED,
            mac="aa:bb:cc:dd:00:02",
            ip="10.0.0.3",
            gateway="10.0.0.1",
            peer="veth0"
        ))
        
        # Simulated gateway
        self.add_interface(VirtualInterface(
            name="vgw0",
            type=VirtualInterfaceType.SIMULATED,
            mac="aa:bb:cc:dd:00:ff",
            ip="10.0.0.1"
        ))
    
    def add_interface(self, interface: VirtualInterface) -> bool:
        """Add a virtual interface to the network."""
        with self._lock:
            if interface.name in self.interfaces:
                return False
            
            self.interfaces[interface.name] = interface
            self.arp_tables[interface.name] = {}
            self.packet_queues[interface.name] = queue.Queue()
            self.packet_handlers[interface.name] = []
            
            # Pre-populate ARP table with gateway
            if interface.gateway:
                gw_iface = self._find_interface_by_ip(interface.gateway)
                if gw_iface:
                    self.arp_tables[interface.name][interface.gateway] = VirtualARPEntry(
                        ip=interface.gateway,
                        mac=gw_iface.mac,
                        interface=interface.name,
                        static=True
                    )
            
            return True
    
    def remove_interface(self, name: str) -> bool:
        """Remove a virtual interface."""
        with self._lock:
            if name not in self.interfaces:
                return False
            
            del self.interfaces[name]
            del self.arp_tables[name]
            del self.packet_queues[name]
            del self.packet_handlers[name]
            return True
    
    def _find_interface_by_ip(self, ip: str) -> Optional[VirtualInterface]:
        """Find interface by IP address."""
        for iface in self.interfaces.values():
            if iface.ip == ip:
                return iface
        return None
    
    def _find_interface_by_mac(self, mac: str) -> Optional[VirtualInterface]:
        """Find interface by MAC address."""
        for iface in self.interfaces.values():
            if iface.mac.lower() == mac.lower():
                return iface
        return None
    
    def get_arp_table(self, interface: str) -> Dict[str, VirtualARPEntry]:
        """Get ARP table for an interface."""
        with self._lock:
            return dict(self.arp_tables.get(interface, {}))
    
    def add_arp_entry(self, interface: str, ip: str, mac: str, 
                      static: bool = False) -> bool:
        """Add or update an ARP entry."""
        with self._lock:
            if interface not in self.arp_tables:
                return False
            
            self.arp_tables[interface][ip] = VirtualARPEntry(
                ip=ip,
                mac=mac,
                interface=interface,
                static=static
            )
            return True
    
    def delete_arp_entry(self, interface: str, ip: str) -> bool:
        """Delete an ARP entry."""
        with self._lock:
            if interface not in self.arp_tables:
                return False
            if ip in self.arp_tables[interface]:
                del self.arp_tables[interface][ip]
                return True
            return False
    
    def send_arp_request(self, src_interface: str, target_ip: str) -> Optional[str]:
        """
        Send a simulated ARP request and get the response.
        
        Returns:
            MAC address of the target, or None if not reachable.
        """
        with self._lock:
            if src_interface not in self.interfaces:
                return None
            
            src = self.interfaces[src_interface]
            self.stats['arp_requests'] += 1
            
            # Check if already in ARP table
            if target_ip in self.arp_tables[src_interface]:
                return self.arp_tables[src_interface][target_ip].mac
            
            # Find target interface
            target = self._find_interface_by_ip(target_ip)
            if target and target.active:
                # Simulate ARP response
                self.stats['arp_replies'] += 1
                self.add_arp_entry(src_interface, target_ip, target.mac)
                return target.mac
            
            return None
    
    def send_arp_reply(self, src_interface: str, dst_ip: str, 
                       spoofed_ip: str = None, spoofed_mac: str = None):
        """
        Send a simulated ARP reply (potentially spoofed).
        
        Args:
            src_interface: Interface sending the reply
            dst_ip: Destination IP (who will receive the reply)
            spoofed_ip: IP to claim (for poisoning)
            spoofed_mac: MAC to associate with spoofed_ip
        """
        with self._lock:
            if src_interface not in self.interfaces:
                return False
            
            src = self.interfaces[src_interface]
            dst = self._find_interface_by_ip(dst_ip)
            
            if not dst:
                return False
            
            # The IP we're claiming to be
            claimed_ip = spoofed_ip or src.ip
            claimed_mac = spoofed_mac or src.mac
            
            self.stats['arp_replies'] += 1
            
            # Update victim's ARP table (this is the poisoning!)
            self.add_arp_entry(dst.name, claimed_ip, claimed_mac)
            
            # Create packet for handlers
            packet = VirtualPacket(
                src_mac=claimed_mac,
                dst_mac=dst.mac,
                src_ip=claimed_ip,
                dst_ip=dst_ip,
                payload=b'ARP_REPLY',
                packet_type="ARP_REPLY"
            )
            
            self._deliver_packet(dst.name, packet)
            return True
    
    def send_gratuitous_arp(self, src_interface: str, 
                            spoofed_ip: str = None, spoofed_mac: str = None):
        """
        Send gratuitous ARP (announce IP-MAC binding to all).
        
        This is commonly used in ARP poisoning attacks.
        """
        with self._lock:
            if src_interface not in self.interfaces:
                return False
            
            src = self.interfaces[src_interface]
            claimed_ip = spoofed_ip or src.ip
            claimed_mac = spoofed_mac or src.mac
            
            # Send to all interfaces in the network
            for iface_name, iface in self.interfaces.items():
                if iface_name != src_interface and iface.active:
                    self.add_arp_entry(iface_name, claimed_ip, claimed_mac)
            
            self.stats['arp_requests'] += 1
            return True
    
    def _deliver_packet(self, dst_interface: str, packet: VirtualPacket):
        """Deliver a packet to interface handlers."""
        if dst_interface in self.packet_queues:
            self.packet_queues[dst_interface].put(packet)
            self.stats['packets_received'] += 1
            
            # Call registered handlers
            for handler in self.packet_handlers.get(dst_interface, []):
                try:
                    handler(packet)
                except Exception:
                    pass
    
    def register_packet_handler(self, interface: str, 
                                handler: Callable[[VirtualPacket], None]):
        """Register a packet handler for an interface."""
        with self._lock:
            if interface not in self.packet_handlers:
                self.packet_handlers[interface] = []
            self.packet_handlers[interface].append(handler)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network statistics."""
        with self._lock:
            return dict(self.stats)
    
    def reset_statistics(self):
        """Reset network statistics."""
        with self._lock:
            for key in self.stats:
                self.stats[key] = 0


class VirtualARPSpoofer:
    """
    Simulated ARP spoofer for virtual network testing.
    
    Demonstrates ARP poisoning attacks in a safe, virtual environment.
    """
    
    def __init__(self, network: VirtualNetwork, attacker_interface: str):
        self.network = network
        self.attacker_interface = attacker_interface
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.poisoning_stats = {
            'packets_sent': 0,
            'victims_poisoned': 0,
        }
    
    def start_poisoning(self, victim_ip: str, gateway_ip: str,
                        interval: float = 1.0):
        """
        Start ARP poisoning attack against a victim.
        
        Args:
            victim_ip: IP of the victim to poison
            gateway_ip: IP of the gateway to impersonate
            interval: Time between poison packets
        """
        if self._running:
            return False
        
        self._running = True
        self._thread = threading.Thread(
            target=self._poison_loop,
            args=(victim_ip, gateway_ip, interval)
        )
        self._thread.daemon = True
        self._thread.start()
        return True
    
    def _poison_loop(self, victim_ip: str, gateway_ip: str, interval: float):
        """Continuous poisoning loop."""
        attacker = self.network.interfaces.get(self.attacker_interface)
        if not attacker:
            return
        
        while self._running:
            # Tell victim that gateway is at attacker's MAC
            self.network.send_arp_reply(
                self.attacker_interface,
                victim_ip,
                spoofed_ip=gateway_ip,
                spoofed_mac=attacker.mac
            )
            
            # Tell gateway that victim is at attacker's MAC
            self.network.send_arp_reply(
                self.attacker_interface,
                gateway_ip,
                spoofed_ip=victim_ip,
                spoofed_mac=attacker.mac
            )
            
            self.poisoning_stats['packets_sent'] += 2
            self.poisoning_stats['victims_poisoned'] = 1
            
            time.sleep(interval)
    
    def stop_poisoning(self):
        """Stop the poisoning attack."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)


class VirtualARPDetector:
    """
    Simulated ARP attack detector for virtual network.
    
    Implements detection based on MAC address discrepancy analysis
    as described in the research paper.
    """
    
    def __init__(self, network: VirtualNetwork, interface: str):
        self.network = network
        self.interface = interface
        self.known_bindings: Dict[str, str] = {}  # IP -> MAC
        self.alerts: List[Dict] = []
        self._running = False
    
    def add_trusted_binding(self, ip: str, mac: str):
        """Add a known-good IP-MAC binding."""
        self.known_bindings[ip] = mac.lower()
    
    def check_arp_table(self) -> List[Dict]:
        """
        Check ARP table for inconsistencies.
        
        Returns list of detected anomalies.
        """
        anomalies = []
        arp_table = self.network.get_arp_table(self.interface)
        
        for ip, entry in arp_table.items():
            if ip in self.known_bindings:
                expected_mac = self.known_bindings[ip]
                actual_mac = entry.mac.lower()
                
                if expected_mac != actual_mac:
                    anomaly = {
                        'type': 'MAC_MISMATCH',
                        'ip': ip,
                        'expected_mac': expected_mac,
                        'actual_mac': actual_mac,
                        'severity': 'HIGH',
                        'timestamp': time.time(),
                        'description': f"MAC address for {ip} changed from "
                                      f"{expected_mac} to {actual_mac}"
                    }
                    anomalies.append(anomaly)
                    self.alerts.append(anomaly)
        
        # Check for duplicate MACs
        mac_to_ips: Dict[str, List[str]] = {}
        for ip, entry in arp_table.items():
            mac = entry.mac.lower()
            if mac not in mac_to_ips:
                mac_to_ips[mac] = []
            mac_to_ips[mac].append(ip)
        
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                anomaly = {
                    'type': 'DUPLICATE_MAC',
                    'mac': mac,
                    'ips': ips,
                    'severity': 'CRITICAL',
                    'timestamp': time.time(),
                    'description': f"Multiple IPs ({', '.join(ips)}) have same MAC {mac}"
                }
                anomalies.append(anomaly)
                self.alerts.append(anomaly)
        
        return anomalies
    
    def get_alerts(self) -> List[Dict]:
        """Get all recorded alerts."""
        return list(self.alerts)
    
    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts.clear()


class SystemInterfaceManager:
    """
    Manages real virtual interfaces on the system.
    
    Supports creating veth pairs on Linux and bridge interfaces.
    Requires root/admin privileges.
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.created_interfaces: List[str] = []
    
    def is_supported(self) -> bool:
        """Check if system supports virtual interface creation."""
        return self.system == 'linux'
    
    def create_veth_pair(self, name1: str, name2: str,
                         ip1: str = None, ip2: str = None) -> bool:
        """
        Create a veth pair (Linux only).
        
        Args:
            name1: Name of first interface
            name2: Name of second interface
            ip1: IP address for first interface
            ip2: IP address for second interface
        
        Returns:
            True if successful, False otherwise.
        """
        if self.system != 'linux':
            return False
        
        try:
            # Create veth pair
            subprocess.run([
                'ip', 'link', 'add', name1, 'type', 'veth', 'peer', 'name', name2
            ], check=True, capture_output=True)
            
            # Bring interfaces up
            subprocess.run(['ip', 'link', 'set', name1, 'up'], 
                          check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', name2, 'up'], 
                          check=True, capture_output=True)
            
            # Assign IPs if provided
            if ip1:
                subprocess.run(['ip', 'addr', 'add', f'{ip1}/24', 'dev', name1],
                              check=True, capture_output=True)
            if ip2:
                subprocess.run(['ip', 'addr', 'add', f'{ip2}/24', 'dev', name2],
                              check=True, capture_output=True)
            
            self.created_interfaces.extend([name1, name2])
            return True
            
        except subprocess.CalledProcessError:
            return False
    
    def create_bridge(self, name: str, interfaces: List[str] = None) -> bool:
        """
        Create a software bridge (Linux only).
        
        Args:
            name: Bridge name
            interfaces: Interfaces to add to bridge
        
        Returns:
            True if successful.
        """
        if self.system != 'linux':
            return False
        
        try:
            subprocess.run(['ip', 'link', 'add', name, 'type', 'bridge'],
                          check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', name, 'up'],
                          check=True, capture_output=True)
            
            if interfaces:
                for iface in interfaces:
                    subprocess.run([
                        'ip', 'link', 'set', iface, 'master', name
                    ], check=True, capture_output=True)
            
            self.created_interfaces.append(name)
            return True
            
        except subprocess.CalledProcessError:
            return False
    
    def delete_interface(self, name: str) -> bool:
        """Delete a virtual interface."""
        if self.system != 'linux':
            return False
        
        try:
            subprocess.run(['ip', 'link', 'del', name],
                          check=True, capture_output=True)
            if name in self.created_interfaces:
                self.created_interfaces.remove(name)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def cleanup(self):
        """Remove all created interfaces."""
        for iface in list(self.created_interfaces):
            self.delete_interface(iface)


# Demo function for virtual network testing
def run_virtual_network_demo():
    """
    Demonstrate virtual network ARP testing.
    
    This allows testing on a single machine without network hardware.
    """
    print("=" * 60)
    print("Virtual Network ARP Testbed Demo")
    print("=" * 60)
    
    # Create virtual network
    network = VirtualNetwork()
    
    print("\n[1] Virtual Network Initialized")
    print("    Interfaces:")
    for name, iface in network.interfaces.items():
        print(f"      - {name}: IP={iface.ip}, MAC={iface.mac}")
    
    # Set up detector on victim interface
    print("\n[2] Setting up ARP Detector on veth0 (victim)")
    detector = VirtualARPDetector(network, "veth0")
    
    # Add trusted bindings (victim knows gateway's real MAC)
    gateway_iface = network.interfaces["vgw0"]
    detector.add_trusted_binding(gateway_iface.ip, gateway_iface.mac)
    print(f"    Trusted binding: {gateway_iface.ip} -> {gateway_iface.mac}")
    
    # Check initial state
    print("\n[3] Initial ARP Table Check")
    anomalies = detector.check_arp_table()
    print(f"    Anomalies detected: {len(anomalies)}")
    
    # Start ARP poisoning attack
    print("\n[4] Starting ARP Poisoning Attack from veth1 (attacker)")
    spoofer = VirtualARPSpoofer(network, "veth1")
    
    # Send poisoned ARP
    attacker = network.interfaces["veth1"]
    network.send_arp_reply(
        "veth1",
        "10.0.0.2",  # victim
        spoofed_ip="10.0.0.1",  # gateway
        spoofed_mac=attacker.mac  # attacker's MAC
    )
    
    print("    Poisoned ARP sent: Claiming to be gateway (10.0.0.1)")
    
    # Check for attack detection
    print("\n[5] Running Attack Detection")
    anomalies = detector.check_arp_table()
    print(f"    Anomalies detected: {len(anomalies)}")
    
    for anomaly in anomalies:
        print(f"\n    ALERT: {anomaly['type']}")
        print(f"      Severity: {anomaly['severity']}")
        print(f"      Details: {anomaly['description']}")
    
    # Show statistics
    print("\n[6] Network Statistics")
    stats = network.get_statistics()
    for key, value in stats.items():
        print(f"    {key}: {value}")
    
    print("\n" + "=" * 60)
    print("Demo Complete - Attack successfully detected!")
    print("=" * 60)


if __name__ == "__main__":
    run_virtual_network_demo()
