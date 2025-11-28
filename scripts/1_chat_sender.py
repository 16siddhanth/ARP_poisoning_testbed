#!/usr/bin/env python3
"""
STEP 1A: ARP Chat Sender

Run this on Laptop A to send messages to Laptop B.

Usage:
    sudo python scripts/1_chat_sender.py -i <interface> -t <target_ip>
    
Example:
    sudo python scripts/1_chat_sender.py -i en0 -t 192.168.1.20
"""

import sys
import argparse
import time
from datetime import datetime

sys.path.insert(0, '.')

try:
    from scapy.all import Ether, ARP, Raw, sendp, get_if_hwaddr, conf
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from core.network_utils import get_interface_info, get_mac_address


class SimpleChatSender:
    """Simple ARP-based message sender for demo."""
    
    ETHER_TYPE = 0x88b5  # Experimental EtherType for ARP Chat
    
    def __init__(self, interface: str, target_ip: str):
        self.interface = interface
        self.target_ip = target_ip
        
        # Get our MAC
        info = get_interface_info(interface)
        if not info:
            raise ValueError(f"Cannot get info for interface {interface}")
        self.our_mac = info.mac
        self.our_ip = info.ip
        
        # Get target MAC
        self.target_mac = get_mac_address(target_ip, interface)
        if not self.target_mac:
            print(f"Warning: Could not resolve MAC for {target_ip}, using broadcast")
            self.target_mac = "ff:ff:ff:ff:ff:ff"
            
        print(f"\n{'='*60}")
        print(f"  ARP CHAT SENDER")
        print(f"{'='*60}")
        print(f"  Interface: {interface}")
        print(f"  Our IP:    {self.our_ip}")
        print(f"  Our MAC:   {self.our_mac}")
        print(f"  Target IP: {target_ip}")
        print(f"  Target MAC:{self.target_mac}")
        print(f"{'='*60}\n")
        
    def send_message(self, message: str):
        """Send a message via ARP packet."""
        # Create packet with message embedded
        packet = (
            Ether(dst=self.target_mac, src=self.our_mac, type=self.ETHER_TYPE) /
            Raw(load=f"ARPCHAT|{self.our_ip}|{message}".encode())
        )
        
        sendp(packet, iface=self.interface, verbose=False)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] SENT: {message}")
        

def main():
    parser = argparse.ArgumentParser(description="ARP Chat Sender")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    args = parser.parse_args()
    
    sender = SimpleChatSender(args.interface, args.target)
    
    print("Type messages and press Enter to send. Ctrl+C to exit.\n")
    
    try:
        while True:
            message = input("You: ")
            if message.strip():
                sender.send_message(message)
    except KeyboardInterrupt:
        print("\n\nExiting chat sender...")


if __name__ == "__main__":
    main()
