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
    # Direct match first
    for iface in get_interfaces():
        if iface.name == interface:
            return iface

    # Windows Npcap device fallback
    if interface.startswith(r"\\Device\\NPF_"):
        # Return first valid non-loopback interface
        for iface in get_interfaces():
            if iface.ip and iface.ip != "127.0.0.1" and iface.ip != "0.0.0.0":
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
    # First, try to ping to populate ARP cache
    system = platform.system().lower()
    try:
        if system == 'windows':
            subprocess.run(['ping', '-n', '1', '-w', '1000', ip_address],
                          capture_output=True, timeout=3)
        else:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip_address],
                          capture_output=True, timeout=3)
    except:
        pass
    
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
    except Exception as e:
        print(f"[DEBUG] ARP resolution error: {e}")
    
    # Fallback to ARP cache
    mac = _check_arp_cache(ip_address)
    if mac:
        return mac
    
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
        elif system == 'darwin':
            # macOS: use 'arp -n' or 'arp -a'
            result = subprocess.run(['arp', '-n', ip_address],
                                   capture_output=True, text=True)
            # If -n fails, try -a
            if result.returncode != 0 or not result.stdout.strip():
                result = subprocess.run(['arp', '-a'],
                                       capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ip_address in line:
                    parts = line.split()
                    for part in parts:
                        # MAC address format: xx:xx:xx:xx:xx:xx
                        if ':' in part and len(part) >= 11 and part.count(':') >= 4:
                            return part
        elif system == 'windows':
            result = subprocess.run(['arp', '-a', ip_address],
                                   capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ip_address in line:
                    parts = line.split()
                    for part in parts:
                        if '-' in part and len(part) >= 11:
                            # Convert Windows format (xx-xx-xx-xx-xx-xx) to standard
                            return part.replace('-', ':')
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
