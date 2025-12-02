#!/usr/bin/env python3
"""
ARP Testbed Demo Script

This script provides a quick demonstration of the ARP testbed capabilities.
It runs a simplified version of the full experiment.

Usage:
    python demo.py --interface en0 --target 192.168.1.100
    
For full experiments, use the orchestrator:
    python -m orchestration.orchestrator -i en0 -t 192.168.1.100
"""

import sys
import time
import argparse
from datetime import datetime

# Add project root to path
sys.path.insert(0, '.')

from core.network_utils import (
    get_interfaces, get_interface_info, get_gateway_info,
    validate_interface
)
from core.arp_chat import ARPChat
from attacks.arp_spoofer import ARPSpoofer
from defenses.arp_detector import ARPDetector
from defenses.static_arp import StaticARPManager
from metrics.collector import MetricsCollector, TestPhase
from metrics.analyzer import MetricsAnalyzer


def print_banner():
    """Print welcome banner"""
    print("""
╔════════════════════════════════════════════════════════════════╗
║                    ARP POISONING TESTBED                       ║
║                                                                ║
║  A comprehensive demonstration of ARP attacks and defenses     ║
║                                                                ║
║  WARNING: For authorized security testing only!                ║
╚════════════════════════════════════════════════════════════════╝
    """)


def list_interfaces():
    """List available network interfaces"""
    print("\nAvailable Network Interfaces:")
    print("-" * 50)
    
    interfaces = get_interfaces()
    for iface in interfaces:
        if iface and iface.ip:
            print(f"  {iface.name}:")
            print(f"    IP: {iface.ip}")
            print(f"    MAC: {iface.mac}")
            print(f"    Netmask: {iface.netmask or 'N/A'}")
            
            gw = get_gateway_info(iface.name)
            if gw:
                print(f"    Gateway: {gw['ip']}")
            print()
            

def demo_arp_chat(interface: str, duration: float = 10.0):
    """Demonstrate ARP chat functionality"""
    print("\n" + "=" * 50)
    print("  DEMO: ARP Chat")
    print("=" * 50)
    print(f"Sending messages via ARP protocol for {duration} seconds...")
    
    chat = ARPChat(interface=interface, nickname="DemoNode")
    chat.start()
    
    # Send some test messages
    for i in range(5):
        chat.send_message(f"Hello from ARP Chat #{i+1}")
        time.sleep(1)
        
    chat.stop()
    print("✓ ARP Chat demo complete")


def demo_arp_detector(interface: str, duration: float = 15.0):
    """Demonstrate ARP detection"""
    print("\n" + "=" * 50)
    print("  DEMO: ARP Poisoning Detection")
    print("=" * 50)
    print(f"Monitoring ARP traffic for {duration} seconds...")
    
    alerts = []
    
    def alert_handler(alert):
        alerts.append(alert)
        print(f"  ⚠️  Alert: {alert.description}")
        
    detector = ARPDetector(
        interface=interface,
        alert_callback=alert_handler,
        verbose=False
    )
    
    detector.start()
    time.sleep(duration)
    detector.stop()
    
    stats = detector.get_statistics()
    print(f"\nDetection Statistics:")
    print(f"  ARP packets seen: {stats['arp_packets_seen']}")
    print(f"  Requests/Replies: {stats['arp_requests']}/{stats['arp_replies']}")
    print(f"  Alerts generated: {stats['alerts_generated']}")
    print("✓ ARP Detection demo complete")


def demo_static_arp(interface: str):
    """Demonstrate static ARP protection"""
    print("\n" + "=" * 50)
    print("  DEMO: Static ARP Protection")
    print("=" * 50)
    
    manager = StaticARPManager(interface=interface, verbose=True)
    
    print("Protecting gateway with static ARP entry...")
    if manager.protect_gateway():
        print("✓ Gateway protected")
        
        print("Verifying entry...")
        verification = manager.verify_entries()
        for ip, verified in verification.items():
            status = "✓" if verified else "✗"
            print(f"  {status} {ip}")
            
        print("Cleaning up...")
        manager.clear_all()
    else:
        print("✗ Could not protect gateway (may need root privileges)")
        
    print("✓ Static ARP demo complete")


def demo_metrics():
    """Demonstrate metrics collection and analysis"""
    print("\n" + "=" * 50)
    print("  DEMO: Metrics Collection")
    print("=" * 50)
    
    collector = MetricsCollector("demo_experiment")
    
    # Simulate baseline
    print("Simulating baseline phase...")
    collector.start_phase(TestPhase.BASELINE)
    for _ in range(20):
        msg_id = collector.record_send()
        time.sleep(0.01)
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Simulate attack
    print("Simulating attack phase...")
    collector.start_phase(TestPhase.ATTACK)
    for i in range(20):
        msg_id = collector.record_send(intercepted=(i % 3 == 0))
        time.sleep(0.02)
        if i % 4 != 0:  # Some packet loss
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Simulate mitigation
    print("Simulating mitigated phase...")
    collector.start_phase(TestPhase.MITIGATED)
    for _ in range(20):
        msg_id = collector.record_send()
        time.sleep(0.012)
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Analyze
    analyzer = MetricsAnalyzer(collector)
    
    print("\nResults:")
    for phase_name, metrics in collector.get_summary()['phases'].items():
        print(f"\n  {phase_name.upper()}:")
        print(f"    Delivery Rate: {metrics['delivery_rate']}%")
        print(f"    Avg Latency: {metrics['avg_latency_ms']:.2f} ms")
        
    impact = analyzer.calculate_attack_impact()
    print(f"\n  Attack Severity: {impact['severity_score']}/100")
    
    eff = analyzer.calculate_mitigation_effectiveness()
    print(f"  Mitigation Effectiveness: {eff['overall_score']}/100")
    
    print("\n✓ Metrics demo complete")


def run_full_demo(interface: str, target_ip: str):
    """Run the full demonstration"""
    print_banner()
    
    # Check interface
    if not validate_interface(interface):
        print(f"Error: Invalid interface '{interface}'")
        list_interfaces()
        return
        
    info = get_interface_info(interface)
    print(f"Using interface: {interface}")
    print(f"  IP: {info.ip}")
    print(f"  MAC: {info.mac}")
    
    gw = get_gateway_info(interface)
    if gw:
        print(f"  Gateway: {gw['ip']}")
        
    print(f"  Target: {target_ip}")
    
    # Run demos
    try:
        # Demo 1: Metrics (doesn't need network)
        demo_metrics()
        
        # Demo 2: ARP Chat
        demo_arp_chat(interface, duration=5)
        
        # Demo 3: Static ARP
        demo_static_arp(interface)
        
        # Demo 4: Detection
        demo_arp_detector(interface, duration=10)
        
        print("\n" + "=" * 50)
        print("  ALL DEMOS COMPLETE")
        print("=" * 50)
        print("\nFor full attack demonstration, use the orchestrator:")
        print(f"  python -m orchestration.orchestrator -i {interface} -t {target_ip}")
        
    except PermissionError:
        print("\n⚠️  Permission denied. This tool requires root privileges.")
        print("   Run with: sudo python demo.py ...")
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")


def main():
    parser = argparse.ArgumentParser(
        description="ARP Testbed Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-i", "--interface",
                       help="Network interface to use")
    parser.add_argument("-t", "--target",
                       help="Target IP address")
    parser.add_argument("--list-interfaces", action="store_true",
                       help="List available interfaces")
    parser.add_argument("--metrics-only", action="store_true",
                       help="Only run metrics demo (no network required)")
                       
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
        
    if args.metrics_only:
        print_banner()
        demo_metrics()
        return
        
    if not args.interface or not args.target:
        print("Error: Interface and target are required")
        print("Usage: python demo.py -i <interface> -t <target_ip>")
        print("       python demo.py --list-interfaces")
        print("       python demo.py --metrics-only")
        return
        
    run_full_demo(args.interface, args.target)


if __name__ == "__main__":
    main()
