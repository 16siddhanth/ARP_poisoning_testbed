"""
Static ARP Table Manager

This module manages static ARP entries as a defense against ARP poisoning.
Static entries cannot be overwritten by ARP replies.

Cross-platform support:
- Linux: ip neigh / arp command
- macOS: arp command
- Windows: netsh / arp command
"""

import subprocess
import platform
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from core.network_utils import get_arp_table, get_gateway_info, validate_interface
from config.settings import get_platform


@dataclass
class StaticARPEntry:
    """Represents a static ARP entry"""
    ip: str
    mac: str
    interface: Optional[str] = None
    added_at: Optional[datetime] = None
    is_persistent: bool = False


class StaticARPManager:
    """
    Manages static ARP entries for defense against poisoning
    
    Static ARP entries are not updated by incoming ARP replies,
    providing protection against spoofing attacks.
    """
    
    def __init__(self, interface: Optional[str] = None, verbose: bool = True):
        """
        Initialize Static ARP Manager
        
        Args:
            interface: Default network interface (optional)
            verbose: Enable verbose logging
        """
        self.interface = interface
        self.verbose = verbose
        self.platform = get_platform()
        
        # Track entries we've added
        self._managed_entries: Dict[str, StaticARPEntry] = {}
        
        self._log(f"Static ARP Manager initialized ({self.platform})")
        
    def _log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [StaticARP] {message}")
            
    def _run_command(self, cmd: List[str], check: bool = True) -> Tuple[bool, str]:
        """Run a system command"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
        except Exception as e:
            return False, str(e)
            
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        return True
        
    def _validate_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        # Accept formats: aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
        mac = mac.lower().replace('-', ':')
        if not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
            return False
        return True
        
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format"""
        return mac.lower().replace('-', ':')
        
    def add_static_entry(
        self,
        ip: str,
        mac: str,
        interface: Optional[str] = None,
        persistent: bool = False
    ) -> bool:
        """
        Add a static ARP entry
        
        Args:
            ip: IP address
            mac: MAC address
            interface: Network interface (uses default if None)
            persistent: Survive reboots (not supported on all platforms)
            
        Returns:
            True if successful
        """
        # Validate inputs
        if not self._validate_ip(ip):
            self._log(f"Invalid IP address: {ip}")
            return False
            
        if not self._validate_mac(mac):
            self._log(f"Invalid MAC address: {mac}")
            return False
            
        mac = self._normalize_mac(mac)
        iface = interface or self.interface
        
        self._log(f"Adding static ARP entry: {ip} -> {mac}")
        
        success = False
        
        if self.platform == 'linux':
            success = self._add_static_linux(ip, mac, iface)
        elif self.platform == 'darwin':  # macOS
            success = self._add_static_macos(ip, mac, iface)
        elif self.platform == 'windows':
            success = self._add_static_windows(ip, mac, iface)
        else:
            self._log(f"Unsupported platform: {self.platform}")
            return False
            
        if success:
            self._managed_entries[ip] = StaticARPEntry(
                ip=ip,
                mac=mac,
                interface=iface,
                added_at=datetime.now(),
                is_persistent=persistent
            )
            self._log(f"Successfully added static entry for {ip}")
        else:
            self._log(f"Failed to add static entry for {ip}")
            
        return success
        
    def _add_static_linux(self, ip: str, mac: str, interface: Optional[str]) -> bool:
        """Add static ARP entry on Linux"""
        # Try ip neigh first (modern)
        if interface:
            cmd = ['sudo', 'ip', 'neigh', 'replace', ip, 'lladdr', mac, 
                   'nud', 'permanent', 'dev', interface]
        else:
            cmd = ['sudo', 'ip', 'neigh', 'replace', ip, 'lladdr', mac, 
                   'nud', 'permanent']
            
        success, output = self._run_command(cmd, check=False)
        
        if not success:
            # Fall back to arp command
            if interface:
                cmd = ['sudo', 'arp', '-s', ip, mac, '-i', interface]
            else:
                cmd = ['sudo', 'arp', '-s', ip, mac]
            success, output = self._run_command(cmd, check=False)
            
        return success
        
    def _add_static_macos(self, ip: str, mac: str, interface: Optional[str]) -> bool:
        """Add static ARP entry on macOS"""
        # First delete any existing entry
        self._run_command(['sudo', 'arp', '-d', ip], check=False)
        
        # Add static entry
        if interface:
            cmd = ['sudo', 'arp', '-s', ip, mac, '-i', interface]
        else:
            cmd = ['sudo', 'arp', '-s', ip, mac]
            
        success, output = self._run_command(cmd, check=False)
        return success
        
    def _add_static_windows(self, ip: str, mac: str, interface: Optional[str]) -> bool:
        """Add static ARP entry on Windows"""
        # Convert MAC format for Windows (use dashes)
        win_mac = mac.replace(':', '-')
        
        # Try netsh first
        if interface:
            cmd = ['netsh', 'interface', 'ip', 'add', 'neighbors',
                   interface, ip, win_mac]
        else:
            # Need interface for Windows, try to get default
            cmd = ['arp', '-s', ip, win_mac]
            
        success, output = self._run_command(cmd, check=False)
        return success
        
    def remove_static_entry(self, ip: str) -> bool:
        """
        Remove a static ARP entry
        
        Args:
            ip: IP address to remove
            
        Returns:
            True if successful
        """
        self._log(f"Removing static ARP entry: {ip}")
        
        success = False
        
        if self.platform == 'linux':
            success = self._remove_static_linux(ip)
        elif self.platform == 'darwin':
            success = self._remove_static_macos(ip)
        elif self.platform == 'windows':
            success = self._remove_static_windows(ip)
            
        if success:
            if ip in self._managed_entries:
                del self._managed_entries[ip]
            self._log(f"Successfully removed static entry for {ip}")
        else:
            self._log(f"Failed to remove static entry for {ip}")
            
        return success
        
    def _remove_static_linux(self, ip: str) -> bool:
        """Remove static ARP entry on Linux"""
        cmd = ['sudo', 'ip', 'neigh', 'del', ip, 'dev', self.interface or 'eth0']
        success, _ = self._run_command(cmd, check=False)
        
        if not success:
            cmd = ['sudo', 'arp', '-d', ip]
            success, _ = self._run_command(cmd, check=False)
            
        return success
        
    def _remove_static_macos(self, ip: str) -> bool:
        """Remove static ARP entry on macOS"""
        cmd = ['sudo', 'arp', '-d', ip]
        success, _ = self._run_command(cmd, check=False)
        return success
        
    def _remove_static_windows(self, ip: str) -> bool:
        """Remove static ARP entry on Windows"""
        cmd = ['arp', '-d', ip]
        success, _ = self._run_command(cmd, check=False)
        return success
        
    def protect_gateway(self, interface: Optional[str] = None) -> bool:
        """
        Add static entry for the gateway
        
        This is the most critical protection as gateway spoofing
        is the most common MITM attack.
        
        Args:
            interface: Network interface
            
        Returns:
            True if successful
        """
        iface = interface or self.interface
        
        gw_info = get_gateway_info(iface)
        if not gw_info:
            self._log("Could not detect gateway")
            return False
            
        gateway_ip = gw_info['ip']
        gateway_mac = gw_info.get('mac')
        
        if not gateway_mac:
            self._log(f"Could not determine gateway MAC for {gateway_ip}")
            return False
            
        self._log(f"Protecting gateway: {gateway_ip} ({gateway_mac})")
        return self.add_static_entry(gateway_ip, gateway_mac, iface)
        
    def protect_hosts(
        self,
        hosts: Dict[str, str],
        interface: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Add static entries for multiple hosts
        
        Args:
            hosts: Dict mapping IP -> MAC
            interface: Network interface
            
        Returns:
            Dict mapping IP -> success status
        """
        results = {}
        for ip, mac in hosts.items():
            results[ip] = self.add_static_entry(ip, mac, interface)
        return results
        
    def clear_all(self) -> int:
        """
        Remove all managed static entries
        
        Returns:
            Number of entries removed
        """
        self._log("Clearing all managed static entries")
        count = 0
        
        for ip in list(self._managed_entries.keys()):
            if self.remove_static_entry(ip):
                count += 1
                
        return count
        
    def get_managed_entries(self) -> Dict[str, Dict]:
        """Get all entries managed by this instance"""
        return {
            ip: {
                'mac': entry.mac,
                'interface': entry.interface,
                'added_at': entry.added_at.isoformat() if entry.added_at else None,
                'is_persistent': entry.is_persistent
            }
            for ip, entry in self._managed_entries.items()
        }
        
    def verify_entries(self) -> Dict[str, bool]:
        """
        Verify that managed entries are still in the ARP table
        
        Returns:
            Dict mapping IP -> verified status
        """
        current_table = get_arp_table()
        results = {}
        
        for ip, entry in self._managed_entries.items():
            if ip in current_table:
                current_mac = current_table[ip]['mac'].lower()
                expected_mac = entry.mac.lower()
                results[ip] = (current_mac == expected_mac)
                
                if not results[ip]:
                    self._log(f"WARNING: Entry for {ip} changed! "
                             f"Expected {expected_mac}, got {current_mac}")
            else:
                results[ip] = False
                self._log(f"WARNING: Entry for {ip} is missing from ARP table")
                
        return results
        
    def refresh_entries(self) -> int:
        """
        Re-add all managed entries (in case they were cleared)
        
        Returns:
            Number of entries refreshed
        """
        self._log("Refreshing all managed entries")
        count = 0
        
        for ip, entry in list(self._managed_entries.items()):
            if self.add_static_entry(ip, entry.mac, entry.interface):
                count += 1
                
        return count
        
    def __enter__(self):
        """Context manager entry"""
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clear entries"""
        self.clear_all()
        return False


def main():
    """Demo/test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Static ARP Manager")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("--protect-gateway", action="store_true",
                       help="Add static entry for gateway")
    parser.add_argument("--add", nargs=2, metavar=("IP", "MAC"),
                       help="Add static entry")
    parser.add_argument("--remove", metavar="IP",
                       help="Remove static entry")
    parser.add_argument("--list", action="store_true",
                       help="List current ARP table")
    
    args = parser.parse_args()
    
    manager = StaticARPManager(interface=args.interface)
    
    if args.list:
        table = get_arp_table()
        print("\nCurrent ARP Table:")
        for ip, info in table.items():
            print(f"  {ip} -> {info['mac']} ({info.get('type', 'dynamic')})")
            
    if args.protect_gateway:
        if manager.protect_gateway():
            print("Gateway protected with static entry")
        else:
            print("Failed to protect gateway")
            
    if args.add:
        ip, mac = args.add
        if manager.add_static_entry(ip, mac):
            print(f"Added static entry: {ip} -> {mac}")
        else:
            print(f"Failed to add static entry")
            
    if args.remove:
        if manager.remove_static_entry(args.remove):
            print(f"Removed static entry for {args.remove}")
        else:
            print(f"Failed to remove static entry")


if __name__ == "__main__":
    main()
