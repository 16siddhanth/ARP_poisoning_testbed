"""
ARP Poisoning Attack Modules

This package contains controlled ARP poisoning attack implementations
for security research and testing purposes.

Modules:
- ARPSpoofer: ARP cache poisoning with Scapy
- MITMProxy: Man-in-the-middle packet interception
- AttackToolBenchmark: Compare different attack tools
"""

from attacks.arp_spoofer import ARPSpoofer
from attacks.mitm_proxy import MITMProxy
from attacks.tool_comparison import (
    AttackToolBenchmark,
    AttackResult,
    AttackMode,
    ScapySpoofer,
)

__all__ = [
    'ARPSpoofer', 
    'MITMProxy',
    'AttackToolBenchmark',
    'AttackResult',
    'AttackMode',
    'ScapySpoofer',
]
