#!/usr/bin/env python3
"""
STEP 1A: ARP Chat Sender

Run this on Laptop A to send messages to Laptop B.

Usage:
    sudo python scripts/1_chat_sender.py -i <interface> -t <target_ip>
    sudo python scripts/1_chat_sender.py -i <interface> -t <target_ip> --encrypt
    
Example:
    sudo python scripts/1_chat_sender.py -i en0 -t 192.168.1.20
    sudo python scripts/1_chat_sender.py -i en0 -t 192.168.1.20 --encrypt
"""

import sys
import argparse
import time
from datetime import datetime

sys.path.insert(0, '.')

try:
    from scapy.all import Ether, ARP, Raw, sendp, get_if_hwaddr, getmacbyip, conf
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from core.network_utils import get_interface_info

# Try to import encryption
try:
    from core.encryption import MessageEncryption, CRYPTO_AVAILABLE
except ImportError:
    CRYPTO_AVAILABLE = False

# Shared key for demo (in production, use key exchange)
SHARED_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='


class SimpleChatSender:
    """Simple ARP-based message sender for demo."""
    
    ETHER_TYPE = 0x88b5  # Experimental EtherType for ARP Chat
    
    def __init__(self, interface: str, target_ip: str, use_encryption: bool = False):
        self.interface = interface
        self.target_ip = target_ip
        self.use_encryption = use_encryption and CRYPTO_AVAILABLE
        
        # Initialize encryption if enabled
        if self.use_encryption:
            self.encryptor = MessageEncryption(SHARED_KEY)
        else:
            self.encryptor = None
        
        # Get our MAC
        info = get_interface_info(interface)
        if not info:
            raise ValueError(f"Cannot get info for interface {interface}")
        self.our_mac = info.mac
        self.our_ip = info.ip
        
        # Get target MAC from ARP cache (to pick up poisoned entries!)
        print(f"Resolving MAC address for {target_ip}...")
        # Use ARP cache lookup instead of fresh ARP request
        self.target_mac = self._get_mac_from_cache(target_ip)
        if not self.target_mac:
            # Fallback to scapy if cache lookup fails
            self.target_mac = getmacbyip(target_ip)
        if not self.target_mac:
            print(f"Warning: Could not resolve MAC for {target_ip}, using broadcast")
            self.target_mac = "ff:ff:ff:ff:ff:ff"
    
    def _get_mac_from_cache(self, ip_address: str) -> str:
        """Get MAC from ARP cache (picks up poisoned entries)."""
        import subprocess
        try:
            result = subprocess.run(['arp', '-a', ip_address], 
                                   capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ip_address in line:
                    # Windows format: IP  MAC  Type
                    parts = line.split()
                    for part in parts:
                        if '-' in part and len(part) == 17:
                            return part.replace('-', ':').lower()
        except:
            pass
        return None
            
        print(f"\n{'='*60}")
        print(f"  ARP CHAT SENDER")
        print(f"{'='*60}")
        print(f"  Interface: {interface}")
        print(f"  Our IP:    {self.our_ip}")
        print(f"  Our MAC:   {self.our_mac}")
        print(f"  Target IP: {target_ip}")
        print(f"  Target MAC:{self.target_mac}")
        print(f"  Encryption: {'🔒 ENABLED' if self.use_encryption else '🔓 DISABLED'}")
        print(f"{'='*60}\n")
        
    def send_message(self, message: str):
        """Send a message via ARP packet."""
        if self.use_encryption and self.encryptor:
            # Encrypt the message
            encrypted = self.encryptor.encrypt(message)
            payload = f"ARPCHAT_ENC|{self.our_ip}|{encrypted.decode()}"
            enc_indicator = " 🔒"
        else:
            payload = f"ARPCHAT|{self.our_ip}|{message}"
            enc_indicator = ""
        
        # Create packet with message embedded
        packet = (
            Ether(dst=self.target_mac, src=self.our_mac, type=self.ETHER_TYPE) /
            Raw(load=payload.encode())
        )
        
        sendp(packet, iface=self.interface, verbose=False)
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] SENT{enc_indicator}: {message}")
        
    def toggle_encryption(self):
        """Toggle encryption on/off."""
        if not CRYPTO_AVAILABLE:
            print("[!] Encryption not available. Install: pip install cryptography")
            return
        
        self.use_encryption = not self.use_encryption
        if self.use_encryption and not self.encryptor:
            self.encryptor = MessageEncryption(SHARED_KEY)
        status = "🔒 ENABLED" if self.use_encryption else "🔓 DISABLED"
        print(f"[*] Encryption: {status}")
        

def main():
    parser = argparse.ArgumentParser(description="ARP Chat Sender")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Enable encryption")
    args = parser.parse_args()
    
    if args.encrypt and not CRYPTO_AVAILABLE:
        print("WARNING: cryptography not installed. Encryption disabled.")
        print("Install with: pip install cryptography")
    
    sender = SimpleChatSender(args.interface, args.target, args.encrypt)
    
    print("Type messages and press Enter to send.")
    print("Commands: /encrypt (toggle encryption), /quit (exit)\n")
    
    try:
        while True:
            message = input("You: ")
            if message.strip().lower() == '/encrypt':
                sender.toggle_encryption()
            elif message.strip().lower() == '/quit':
                break
            elif message.strip():
                sender.send_message(message)
    except KeyboardInterrupt:
        print("\n\nExiting chat sender...")


if __name__ == "__main__":
    main()