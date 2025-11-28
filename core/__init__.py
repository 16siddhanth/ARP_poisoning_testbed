"""
Core module for ARP-based networking.

Includes:
- Network utilities for interface and ARP table management
- ARP packet building with Scapy
- ARP-based chat messaging
- Message encryption
- Virtual network simulation for single-machine testing
"""

from .network_utils import (
    get_interfaces,
    get_interface_info,
    get_mac_address,
    get_ip_address,
    get_gateway,
    resolve_mac,
)
from .arp_packet import ARPPacketBuilder
from .arp_chat import ARPChat
from .encryption import MessageEncryption
from .virtual_network import (
    VirtualNetwork,
    VirtualInterface,
    VirtualARPSpoofer,
    VirtualARPDetector,
    SystemInterfaceManager,
)
