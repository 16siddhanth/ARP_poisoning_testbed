"""
Network utilities for interface management and ARP operations.
"""

import platform
import socket
import struct
import subprocess
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import (
        get_if_list,
        get_if_hwaddr,
        get_if_addr,
        conf,
        ARP,
        Ether,
        srp,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


class InterfaceInfo:
    """Information about a network interface."""
    
    def __init__(self, name: str, description: str = "", mac: str = "",
                 ip: str = "", netmask: str = "", gateway: str = ""):
        self.name = name
        self.description = description
        self.mac = mac
        self.ip = ip
        self.netmask = netmask
        self.gateway = gateway
    
    def __repr__(self):
        return (f"InterfaceInfo(name={self.name!r}, mac={self.mac!r}, "
                f"ip={self.ip!r}, gateway={self.gateway!r})")
    
    def is_valid(self) -> bool:
        """Check if interface has required attributes for ARP operations."""
        return bool(self.mac and self.ip)


def get_interfaces() -> List[InterfaceInfo]:
    """
    Get list of all network interfaces with their information.
    
    Returns:
        List of InterfaceInfo objects for each interface.
    """
    interfaces = []
    
    if NETIFACES_AVAILABLE:
        for iface_name in netifaces.interfaces():
            info = InterfaceInfo(name=iface_name)
            
            # Get addresses
            addrs = netifaces.ifaddresses(iface_name)
            
            # MAC address
            if netifaces.AF_LINK in addrs:
                link_info = addrs[netifaces.AF_LINK][0]
                info.mac = link_info.get('addr', '')
            
            # IPv4 address and netmask
            if netifaces.AF_INET in addrs:
                inet_info = addrs[netifaces.AF_INET][0]
                info.ip = inet_info.get('addr', '')
                info.netmask = inet_info.get('netmask', '')
            
            # Gateway
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                gw_info = gws['default'][netifaces.AF_INET]
                if gw_info[1] == iface_name:
                    info.gateway = gw_info[0]
            
            interfaces.append(info)
    
    elif SCAPY_AVAILABLE:
        for iface_name in get_if_list():
            info = InterfaceInfo(name=iface_name)
            try:
                info.mac = get_if_hwaddr(iface_name)
                info.ip = get_if_addr(iface_name)
            except Exception:
                pass
            interfaces.append(info)
    
    else:
        # Fallback: basic interface listing
        system = platform.system().lower()
        if system in ('linux', 'darwin'):
            try:
                result = subprocess.run(['ip', 'link', 'show'], 
                                       capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ': ' in line and '@' not in line[:20]:
                        parts = line.split(': ')
                        if len(parts) >= 2:
                            name = parts[1].split('@')[0]
                            interfaces.append(InterfaceInfo(name=name))
            except Exception:
                pass
    
    return interfaces


def get_interface_info(interface: str) -> Optional[InterfaceInfo]:
    """
    Get detailed information about a specific interface.
    
    Args:
        interface: Interface name (e.g., 'eth0', 'en0').
    
    Returns:
        InterfaceInfo object or None if interface not found.
    """
    for iface in get_interfaces():
        if iface.name == interface:
            return iface
    return None


def get_mac_address(interface: str) -> Optional[str]:
    """
    Get the MAC address of an interface.
    
    Args:
        interface: Interface name.
    
    Returns:
        MAC address string (e.g., 'aa:bb:cc:dd:ee:ff') or None.
    """
    info = get_interface_info(interface)
    return info.mac if info else None


def get_ip_address(interface: str) -> Optional[str]:
    """
    Get the IPv4 address of an interface.
    
    Args:
        interface: Interface name.
    
    Returns:
        IP address string or None.
    """
    info = get_interface_info(interface)
    return info.ip if info else None


def get_gateway(interface: str = None) -> Optional[str]:
    """
    Get the default gateway IP address.
    
    Args:
        interface: Optional interface name to get gateway for.
    
    Returns:
        Gateway IP address string or None.
    """
    if NETIFACES_AVAILABLE:
        gws = netifaces.gateways()
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            gw_info = gws['default'][netifaces.AF_INET]
            if interface is None or gw_info[1] == interface:
                return gw_info[0]
    
    # Fallback: parse route table
    system = platform.system().lower()
    try:
        if system == 'linux':
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                   capture_output=True, text=True)
            parts = result.stdout.split()
            if 'via' in parts:
                idx = parts.index('via')
                return parts[idx + 1]
        elif system == 'darwin':
            result = subprocess.run(['route', '-n', 'get', 'default'],
                                   capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'gateway:' in line:
                    return line.split(':')[1].strip()
    except Exception:
        pass
    
    return None


def resolve_mac(ip_address: str, interface: str = None, 
                timeout: float = 2.0) -> Optional[str]:
    """
    Resolve an IP address to its MAC address using ARP.
    
    Args:
        ip_address: Target IP address.
        interface: Network interface to use.
        timeout: ARP request timeout in seconds.
    
    Returns:
        MAC address string or None if resolution failed.
    """
    if not SCAPY_AVAILABLE:
        # Fallback: check ARP cache
        return _check_arp_cache(ip_address)
    
    try:
        # Create ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        
        # Send and receive
        if interface:
            answered, _ = srp(arp_request, iface=interface, timeout=timeout, 
                             verbose=False)
        else:
            answered, _ = srp(arp_request, timeout=timeout, verbose=False)
        
        if answered:
            return answered[0][1].hwsrc
    except Exception:
        pass
    
    return None


def _check_arp_cache(ip_address: str) -> Optional[str]:
    """Check the system ARP cache for a MAC address."""
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            result = subprocess.run(['ip', 'neigh', 'show', ip_address],
                                   capture_output=True, text=True)
            parts = result.stdout.split()
            if 'lladdr' in parts:
                idx = parts.index('lladdr')
                return parts[idx + 1]
        elif system in ('darwin', 'windows'):
            result = subprocess.run(['arp', '-n', ip_address],
                                   capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ip_address in line:
                    parts = line.split()
                    for part in parts:
                        if ':' in part and len(part) >= 11:
                            return part
    except Exception:
        pass
    
    return None


def ip_to_bytes(ip: str) -> bytes:
    """Convert IP address string to bytes."""
    return socket.inet_aton(ip)


def bytes_to_ip(data: bytes) -> str:
    """Convert bytes to IP address string."""
    return socket.inet_ntoa(data)


def mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to bytes."""
    return bytes.fromhex(mac.replace(':', '').replace('-', ''))


def bytes_to_mac(data: bytes) -> str:
    """Convert bytes to MAC address string."""
    return ':'.join(f'{b:02x}' for b in data)


def get_network_address(ip: str, netmask: str) -> str:
    """Calculate network address from IP and netmask."""
    ip_bytes = struct.unpack('!I', socket.inet_aton(ip))[0]
    mask_bytes = struct.unpack('!I', socket.inet_aton(netmask))[0]
    network = ip_bytes & mask_bytes
    return socket.inet_ntoa(struct.pack('!I', network))


def is_same_network(ip1: str, ip2: str, netmask: str) -> bool:
    """Check if two IPs are on the same network."""
    return get_network_address(ip1, netmask) == get_network_address(ip2, netmask)


def validate_interface(interface: str) -> bool:
    """
    Validate that a network interface exists and is usable.
    
    Args:
        interface: Interface name to validate.
    
    Returns:
        True if interface is valid, False otherwise.
    """
    if not interface:
        return False
    
    interfaces = get_interfaces()
    for iface in interfaces:
        if iface.name == interface:
            return True
    return False


def get_gateway_info(interface: str = None) -> Optional[Dict[str, str]]:
    """
    Get gateway information including IP and MAC address.
    
    Args:
        interface: Optional interface name to get gateway for.
    
    Returns:
        Dictionary with 'ip' and optionally 'mac' keys, or None if not found.
    """
    gateway_ip = get_gateway(interface)
    if not gateway_ip:
        return None
    
    result = {'ip': gateway_ip}
    
    # Try to get gateway MAC from ARP cache or via ARP request
    gateway_mac = resolve_mac(gateway_ip, interface)
    if gateway_mac:
        result['mac'] = gateway_mac
    
    return result


def get_arp_table() -> Dict[str, Dict[str, str]]:
    """
    Get the current system ARP table.
    
    Returns:
        Dictionary mapping IP addresses to their info (mac, type, interface).
        Example: {'192.168.1.1': {'mac': 'aa:bb:cc:dd:ee:ff', 'type': 'dynamic'}}
    """
    arp_entries = {}
    system = platform.system().lower()
    
    try:
        if system == 'linux':
            result = subprocess.run(['ip', 'neigh', 'show'],
                                   capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 4 and 'lladdr' in parts:
                    ip = parts[0]
                    idx = parts.index('lladdr')
                    mac = parts[idx + 1]
                    entry_type = 'dynamic'
                    if 'PERMANENT' in parts:
                        entry_type = 'static'
                    arp_entries[ip] = {
                        'mac': mac,
                        'type': entry_type,
                        'interface': parts[2] if 'dev' in parts else ''
                    }
        elif system == 'darwin':
            result = subprocess.run(['arp', '-an'],
                                   capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                if not line or 'incomplete' in line:
                    continue
                # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
                parts = line.split()
                if len(parts) >= 4 and 'at' in parts:
                    # Extract IP from parentheses
                    ip_part = parts[1]
                    if ip_part.startswith('(') and ip_part.endswith(')'):
                        ip = ip_part[1:-1]
                    else:
                        continue
                    idx = parts.index('at')
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1]
                        entry_type = 'static' if 'permanent' in line.lower() else 'dynamic'
                        interface = ''
                        if 'on' in parts:
                            on_idx = parts.index('on')
                            if on_idx + 1 < len(parts):
                                interface = parts[on_idx + 1]
                        arp_entries[ip] = {
                            'mac': mac,
                            'type': entry_type,
                            'interface': interface
                        }
        elif system == 'windows':
            result = subprocess.run(['arp', '-a'],
                                   capture_output=True, text=True)
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    # Format: 192.168.1.1    aa-bb-cc-dd-ee-ff    dynamic
                    ip = parts[0]
                    # Validate IP format
                    if not all(c in '0123456789.' for c in ip):
                        continue
                    mac = parts[1].replace('-', ':')
                    entry_type = parts[2] if len(parts) > 2 else 'dynamic'
                    arp_entries[ip] = {
                        'mac': mac,
                        'type': entry_type,
                        'interface': ''
                    }
    except Exception:
        pass
    
    return arp_entries


def print_interfaces():
    """Print available network interfaces in a formatted way."""
    interfaces = get_interfaces()
    
    print("\nAvailable Network Interfaces:")
    print("-" * 70)
    
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface.name}")
        if iface.description:
            print(f"   Description: {iface.description}")
        if iface.mac:
            print(f"   MAC: {iface.mac}")
        if iface.ip:
            print(f"   IP: {iface.ip}/{iface.netmask}" if iface.netmask else f"   IP: {iface.ip}")
        if iface.gateway:
            print(f"   Gateway: {iface.gateway}")
        print()


if __name__ == "__main__":
    print_interfaces()
