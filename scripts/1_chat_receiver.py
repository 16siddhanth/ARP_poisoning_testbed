#!/usr/bin/env python3
"""
STEP 1B: ARP Chat Receiver

Run this on Laptop B to receive messages from Laptop A.

Usage:
    sudo python scripts/1_chat_receiver.py -i <interface>
    
Example:
    sudo python scripts/1_chat_receiver.py -i en0
"""

import sys
import argparse
from datetime import datetime

sys.path.insert(0, '.')

try:
    from scapy.all import Ether, Raw, sniff, get_if_hwaddr
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


class SimpleChatReceiver:
    """Simple ARP-based message receiver for demo."""
    
    ETHER_TYPE = 0x88b5  # Experimental EtherType for ARP Chat
    
    def __init__(self, interface: str):
        self.interface = interface
        
        # Initialize decryption
        if CRYPTO_AVAILABLE:
            self.decryptor = MessageEncryption(SHARED_KEY)
        else:
            self.decryptor = None
        
        info = get_interface_info(interface)
        if not info:
            raise ValueError(f"Cannot get info for interface {interface}")
        self.our_mac = info.mac
        self.our_ip = info.ip
        
        print(f"\n{'='*60}")
        print(f"  ARP CHAT RECEIVER")
        print(f"{'='*60}")
        print(f"  Interface: {interface}")
        print(f"  Our IP:    {self.our_ip}")
        print(f"  Our MAC:   {self.our_mac}")
        print(f"  Decryption: {'🔒 AVAILABLE' if CRYPTO_AVAILABLE else '🔓 NOT AVAILABLE'}")
        print(f"  Listening for ARP Chat messages...")
        print(f"{'='*60}\n")
        
    def packet_handler(self, packet):
        """Handle incoming packets."""
        if packet.haslayer(Ether) and packet[Ether].type == self.ETHER_TYPE:
            if packet.haslayer(Raw):
                try:
                    data = packet[Raw].load.decode()
                    
                    # Handle encrypted messages
                    if data.startswith("ARPCHAT_ENC|"):
                        parts = data.split("|", 2)
                        if len(parts) >= 3:
                            sender_ip = parts[1]
                            encrypted_msg = parts[2]
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            
                            if self.decryptor:
                                try:
                                    message = self.decryptor.decrypt(encrypted_msg.encode())
                                    print(f"[{timestamp}] 🔒 FROM {sender_ip}: {message}")
                                except Exception as e:
                                    print(f"[{timestamp}] ⚠️ FROM {sender_ip}: [DECRYPTION FAILED]")
                            else:
                                print(f"[{timestamp}] ⚠️ FROM {sender_ip}: [ENCRYPTED - NO KEY]")
                    
                    # Handle plaintext messages
                    elif data.startswith("ARPCHAT|"):
                        parts = data.split("|", 2)
                        if len(parts) >= 3:
                            sender_ip = parts[1]
                            message = parts[2]
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"[{timestamp}] FROM {sender_ip}: {message}")
                except:
                    pass
                    
    def start(self):
        """Start listening for messages."""
        print("Waiting for messages... (Ctrl+C to exit)\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=f"ether proto {hex(self.ETHER_TYPE)}",
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nExiting chat receiver...")


def main():
    parser = argparse.ArgumentParser(description="ARP Chat Receiver")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    args = parser.parse_args()
    
    if not CRYPTO_AVAILABLE:
        print("WARNING: cryptography not installed. Encrypted messages cannot be decrypted.")
        print("Install with: pip install cryptography\n")
    
    receiver = SimpleChatReceiver(args.interface)
    receiver.start()


if __name__ == "__main__":
    main()
