#!/usr/bin/env python3
"""
STEP 3: ARP Defense

Run this on Laptop A or B to detect attacks and protect against ARP poisoning.

Usage:
    sudo python scripts/3_defender.py -i <interface> --protect <ip_to_protect> --mac <real_mac>
    
Example:
    sudo python scripts/3_defender.py -i en0 --protect 192.168.1.20 --mac aa:bb:cc:dd:ee:ff

This script:
1. Adds static ARP entry for the protected IP (cannot be overwritten)
2. Monitors for ARP spoofing attempts
3. Alerts when attacks are detected
"""

import sys
import argparse
import time
import subprocess
import platform
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, '.')

try:
    from scapy.all import Ether, ARP, sniff, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from core.network_utils import get_interface_info


class ARPDefender:
    """ARP Defense System for demo."""
    
    def __init__(self, interface: str, protected_ip: str = None, protected_mac: str = None):
        self.interface = interface
        self.protected_ip = protected_ip
        self.protected_mac = protected_mac
        self.running = False
        self.platform = platform.system().lower()
        
        # Detection state
        self.arp_table = {}  # ip -> mac mappings we've seen
        self.mac_history = defaultdict(list)  # ip -> list of (mac, timestamp)
        self.alerts = []
        self.packets_seen = 0
        
        info = get_interface_info(interface)
        if not info:
            raise ValueError(f"Cannot get info for interface {interface}")
        self.our_mac = info.mac
        self.our_ip = info.ip
        
        print(f"\n{'='*60}")
        print(f"  ARP DEFENSE SYSTEM")
        print(f"{'='*60}")
        print(f"  Interface: {interface}")
        print(f"  Our IP:    {self.our_ip}")
        print(f"  Our MAC:   {self.our_mac}")
        if protected_ip and protected_mac:
            print(f"  ")
            print(f"  Protected IP:  {protected_ip}")
            print(f"  Protected MAC: {protected_mac}")
        print(f"{'='*60}\n")
        
    def add_static_arp(self, ip: str, mac: str):
        """Add a static ARP entry (cannot be overwritten by attacks)."""
        print(f"[*] Adding static ARP entry: {ip} -> {mac}")
        
        try:
            if self.platform == "darwin":  # macOS
                cmd = ["sudo", "arp", "-s", ip, mac]
                subprocess.run(cmd, check=True, capture_output=True)
            elif self.platform == "linux":
                cmd = ["sudo", "arp", "-s", ip, mac]
                subprocess.run(cmd, check=True, capture_output=True)
            elif self.platform == "windows":
                # Windows: use netsh with interface index or arp -s
                # First try to get interface name from index
                mac_formatted = mac.replace(":", "-")
                
                # Try using arp -s first (simpler)
                try:
                    cmd = ["arp", "-s", ip, mac_formatted]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"[✓] Static ARP entry added successfully")
                        self.arp_table[ip] = mac
                        return True
                except:
                    pass
                
                # Try netsh with common interface names
                for iface_name in ["Wi-Fi", "Ethernet", "Local Area Connection", "Wireless Network Connection"]:
                    try:
                        cmd = ["netsh", "interface", "ip", "add", "neighbors", iface_name, ip, mac_formatted]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            print(f"[✓] Static ARP entry added via {iface_name}")
                            self.arp_table[ip] = mac
                            return True
                    except:
                        continue
                
                print(f"[!] Could not add static ARP entry automatically.")
                print(f"[!] Run this command manually as Administrator:")
                print(f"    netsh interface ip add neighbors \"Wi-Fi\" {ip} {mac_formatted}")
                print(f"    OR: arp -s {ip} {mac_formatted}")
                self.arp_table[ip] = mac  # Still track it for detection
                return False
            else:
                print(f"[!] Unsupported platform: {self.platform}")
                return False
                
            print(f"[✓] Static ARP entry added successfully")
            self.arp_table[ip] = mac
            return True
        except subprocess.CalledProcessError as e:
            print(f"[✗] Failed to add static entry: {e}")
            print(f"[!] Try running as Administrator")
            return False
        except Exception as e:
            print(f"[✗] Error: {e}")
            return False
            
    def remove_static_arp(self, ip: str):
        """Remove a static ARP entry."""
        print(f"[*] Removing static ARP entry for {ip}")
        
        try:
            if self.platform == "darwin":
                cmd = ["sudo", "arp", "-d", ip]
            elif self.platform == "linux":
                cmd = ["sudo", "arp", "-d", ip]
            elif self.platform == "windows":
                cmd = ["netsh", "interface", "ip", "delete", "neighbors",
                       self.interface, ip]
            else:
                return False
                
            subprocess.run(cmd, check=True, capture_output=True)
            print(f"[✓] Static ARP entry removed")
            return True
        except:
            return False
            
    def detect_spoofing(self, packet):
        """Analyze ARP packet for spoofing."""
        if not packet.haslayer(ARP):
            return
            
        self.packets_seen += 1
        arp = packet[ARP]
        
        # We care about ARP replies (op=2) 
        if arp.op != 2:
            return
            
        claimed_ip = arp.psrc
        claimed_mac = arp.hwsrc
        real_src_mac = packet[Ether].src if packet.haslayer(Ether) else claimed_mac
        
        timestamp = datetime.now()
        
        # Check 1: MAC discrepancy (Ethernet header vs ARP payload)
        if real_src_mac.lower() != claimed_mac.lower():
            self.alert(
                "MAC_DISCREPANCY",
                f"MAC mismatch! Ethernet: {real_src_mac}, ARP claims: {claimed_mac}",
                claimed_ip, claimed_mac
            )
            return
            
        # Check 2: Protected IP being spoofed
        if self.protected_ip and claimed_ip == self.protected_ip:
            if self.protected_mac and claimed_mac.lower() != self.protected_mac.lower():
                self.alert(
                    "PROTECTED_IP_SPOOF",
                    f"Someone claiming to be {self.protected_ip} with wrong MAC!",
                    claimed_ip, claimed_mac
                )
                return
                
        # Check 3: IP-MAC mapping changed (possible attack)
        if claimed_ip in self.arp_table:
            old_mac = self.arp_table[claimed_ip]
            if old_mac.lower() != claimed_mac.lower():
                self.alert(
                    "MAC_CHANGED",
                    f"MAC for {claimed_ip} changed: {old_mac} -> {claimed_mac}",
                    claimed_ip, claimed_mac
                )
                return
                
        # Update our tracking
        self.arp_table[claimed_ip] = claimed_mac
        self.mac_history[claimed_ip].append((claimed_mac, timestamp))
        
    def alert(self, alert_type: str, message: str, ip: str, mac: str):
        """Generate an alert."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert = {
            'time': timestamp,
            'type': alert_type,
            'message': message,
            'ip': ip,
            'mac': mac
        }
        self.alerts.append(alert)
        
        print(f"\n{'!'*60}")
        print(f"  ⚠️  ATTACK DETECTED!")
        print(f"{'!'*60}")
        print(f"  Time:    {timestamp}")
        print(f"  Type:    {alert_type}")
        print(f"  Details: {message}")
        print(f"  IP:      {ip}")
        print(f"  MAC:     {mac}")
        print(f"{'!'*60}\n")
        
    def packet_handler(self, packet):
        """Handle sniffed packets."""
        self.detect_spoofing(packet)
        
    def start(self):
        """Start the defense system."""
        self.running = True
        
        # Add static ARP entry if specified
        if self.protected_ip and self.protected_mac:
            self.add_static_arp(self.protected_ip, self.protected_mac)
            
        print("[*] Starting ARP monitoring...")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                filter="arp",
                store=False
            )
        except KeyboardInterrupt:
            self.running = False
            
        # Cleanup
        if self.protected_ip:
            self.remove_static_arp(self.protected_ip)
            
        print(f"\n[*] Defense stopped")
        print(f"[*] Packets analyzed: {self.packets_seen}")
        print(f"[*] Alerts generated: {len(self.alerts)}")


def main():
    parser = argparse.ArgumentParser(description="ARP Defense System")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("--protect", help="IP address to protect with static ARP")
    parser.add_argument("--mac", help="Real MAC address of protected IP")
    args = parser.parse_args()
    
    if args.protect and not args.mac:
        print("ERROR: --mac required when using --protect")
        sys.exit(1)
        
    defender = ARPDefender(args.interface, args.protect, args.mac)
    defender.start()


if __name__ == "__main__":
    main()
