"""
ARP Defense Modules

This package contains defense mechanisms against ARP poisoning attacks,
inspired by rnehra01/arp-validator and the ICITSD 2021 paper by Majumdar et al.

Modules:
- ARPDetector: TCP SYN validation-based detection
- MACDiscrepancyDetector: MAC address discrepancy analysis (paper method)
- StaticARPManager: Static ARP entry management (prevention)
- ARPInspector: Real-time ARP traffic inspection
- DynamicARPInspector: Simulated switch-level DAI
"""

from defenses.arp_detector import ARPDetector, ARPAlert
from defenses.static_arp import StaticARPManager
from defenses.arp_inspector import ARPInspector
from defenses.dai_simulator import DynamicARPInspector, SimulatedSwitch
from defenses.mac_discrepancy_detector import MACDiscrepancyDetector, MACDiscrepancy

__all__ = [
    'ARPDetector', 
    'ARPAlert', 
    'StaticARPManager', 
    'ARPInspector',
    'DynamicARPInspector',
    'SimulatedSwitch',
    'MACDiscrepancyDetector',
    'MACDiscrepancy'
]
