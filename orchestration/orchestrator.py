"""
ARP Testbed Orchestrator

This module provides the main orchestrator that coordinates:
- ARP Chat messaging between nodes
- ARP poisoning attacks
- Defense mechanisms
- Metrics collection
- Visualization generation

The orchestrator runs through three phases:
1. Baseline - Normal ARP chat operation
2. Attack - ARP poisoning active
3. Mitigated - Defenses enabled

Author: Security Research Team
"""

import os
import sys
import time
import threading
import argparse
import base64
from typing import Optional, Dict, List, Callable
from datetime import datetime
from dataclasses import dataclass

# Core imports
from core.network_utils import (
    get_interfaces, get_interface_info, get_gateway_info,
    validate_interface, get_mac_address, get_ip_address
)
from core.arp_chat import ARPChat
from core.encryption import MessageEncryption

# Attack imports
from attacks.arp_spoofer import ARPSpoofer

# Defense imports
from defenses.arp_detector import ARPDetector, ARPAlert
from defenses.static_arp import StaticARPManager
from defenses.arp_inspector import ARPInspector

# Metrics imports
from metrics.collector import MetricsCollector, TestPhase
from metrics.analyzer import MetricsAnalyzer

# Visualization imports
from utils.visualizer import MetricsVisualizer

from config.settings import ARPConfig, get_default_interface, DEFAULT_ENCRYPTION_PASSWORD


@dataclass
class TestConfiguration:
    """Configuration for a test run"""
    interface: str
    target_ip: str
    gateway_ip: Optional[str] = None
    
    # Timing settings
    baseline_duration: float = 30.0
    attack_duration: float = 30.0
    mitigation_duration: float = 30.0
    message_interval: float = 0.5
    
    # Attack settings
    poison_interval: float = 1.0
    bidirectional: bool = True
    
    # Defense settings
    use_static_arp: bool = True
    use_encryption: bool = True
    use_detector: bool = True
    
    # Output settings
    output_dir: str = "results"
    save_metrics: bool = True
    generate_plots: bool = True
    verbose: bool = True


class ARPTestbedOrchestrator:
    """
    Main orchestrator for ARP testbed experiments
    
    Coordinates all components and runs through test phases.
    
    Usage:
        config = TestConfiguration(
            interface="en0",
            target_ip="192.168.1.100"
        )
        
        orchestrator = ARPTestbedOrchestrator(config)
        orchestrator.run()
        
        # Results are saved to output_dir
    """
    
    def __init__(self, config: TestConfiguration):
        """
        Initialize orchestrator
        
        Args:
            config: Test configuration
        """
        self.config = config
        self.verbose = config.verbose
        
        # Validate interface
        if not validate_interface(config.interface):
            raise ValueError(f"Invalid interface: {config.interface}")
            
        # Get network info
        self.our_mac = get_mac_address(config.interface)
        self.our_ip = get_ip_address(config.interface)
        
        # Get gateway if not specified
        if not config.gateway_ip:
            gw_info = get_gateway_info(config.interface)
            if gw_info:
                self.config.gateway_ip = gw_info['ip']
            else:
                raise RuntimeError("Could not detect gateway")
                
        # Initialize components (lazy)
        self._chat: Optional[ARPChat] = None
        self._spoofer: Optional[ARPSpoofer] = None
        self._detector: Optional[ARPDetector] = None
        self._static_arp: Optional[StaticARPManager] = None
        self._inspector: Optional[ARPInspector] = None
        self._encryptor: Optional[MessageEncryption] = None
        
        # Metrics
        self.collector = MetricsCollector(
            experiment_name=f"arp_testbed_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        # State
        self._running = False
        self._current_phase: Optional[TestPhase] = None
        self._message_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._message_counter = 0
        
        # Results
        self.results: Dict = {}
        
        self._log("Orchestrator initialized")
        self._log(f"  Interface: {config.interface}")
        self._log(f"  Our IP: {self.our_ip}")
        self._log(f"  Target: {config.target_ip}")
        self._log(f"  Gateway: {config.gateway_ip}")
        
    def _log(self, message: str, level: str = "INFO"):
        """Log message if verbose"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {message}")
            
    def _init_chat(self):
        """Initialize ARP chat"""
        if not self._chat:
            self._chat = ARPChat(
                interface=self.config.interface,
                nickname="TestNode"
            )
            
    def _init_spoofer(self):
        """Initialize ARP spoofer"""
        if not self._spoofer:
            self._spoofer = ARPSpoofer(
                interface=self.config.interface,
                target_ip=self.config.target_ip,
                gateway_ip=self.config.gateway_ip,
                bidirectional=self.config.bidirectional,
                interval=self.config.poison_interval,
                verbose=self.verbose
            )
            
    def _init_defenses(self):
        """Initialize defense mechanisms"""
        if self.config.use_detector and not self._detector:
            self._detector = ARPDetector(
                interface=self.config.interface,
                alert_callback=self._handle_alert,
                verbose=self.verbose
            )
            
        if self.config.use_static_arp and not self._static_arp:
            self._static_arp = StaticARPManager(
                interface=self.config.interface,
                verbose=self.verbose
            )
            
        if self.config.use_encryption and not self._encryptor:
            self._encryptor = MessageEncryption.from_password(DEFAULT_ENCRYPTION_PASSWORD)
            
    def _handle_alert(self, alert: ARPAlert):
        """Handle ARP poisoning detection alert"""
        self._log(f"⚠️  ALERT: {alert.description}", "ALERT")
        
    def _send_test_messages(self, count: int, interval: float):
        """Send test messages and record metrics"""
        self._log(f"Sending {count} test messages...")
        
        for i in range(count):
            if self._stop_event.is_set():
                break
                
            self._message_counter += 1
            
            # Record send
            msg_id = self.collector.record_send(
                intercepted=(self._current_phase == TestPhase.ATTACK and i % 4 == 0)
            )
            
            # Send message via ARP chat
            message = f"Test message #{self._message_counter}"
            
            if self._current_phase == TestPhase.MITIGATED and self._encryptor:
                # Encrypt message in mitigated phase
                encrypted_bytes = self._encryptor.encrypt(message)
                message = base64.b64encode(encrypted_bytes).decode('ascii')  # Safe string representation
                
            if self._chat:
                self._chat.send_message(message)
                
            # Simulate receive (in real scenario, would be from receiving node)
            # For demo, we simulate with some loss during attack
            if self._current_phase == TestPhase.ATTACK:
                if i % 5 != 0:  # 20% packet loss during attack
                    time.sleep(0.01 + (i % 3) * 0.005)  # Variable latency
                    self.collector.record_receive(msg_id)
            elif self._current_phase == TestPhase.MITIGATED:
                if i % 20 != 0:  # 5% loss with mitigation overhead
                    time.sleep(0.012)  # Slight overhead
                    self.collector.record_receive(msg_id)
            else:  # Baseline
                time.sleep(0.008)  # Low latency
                self.collector.record_receive(msg_id)
                
            time.sleep(interval)
            
    def _run_baseline_phase(self):
        """Run baseline phase - normal operation"""
        self._log("\n" + "=" * 50)
        self._log("PHASE 1: BASELINE")
        self._log("=" * 50)
        
        self._current_phase = TestPhase.BASELINE
        self.collector.start_phase(TestPhase.BASELINE)
        
        # Initialize chat
        self._init_chat()
        
        # Calculate message count
        msg_count = int(self.config.baseline_duration / self.config.message_interval)
        
        # Send test messages
        self._send_test_messages(msg_count, self.config.message_interval)
        
        self.collector.end_phase()
        self._log("Baseline phase complete")
        
    def _run_attack_phase(self):
        """Run attack phase - ARP poisoning active"""
        self._log("\n" + "=" * 50)
        self._log("PHASE 2: ATTACK")
        self._log("=" * 50)
        
        self._current_phase = TestPhase.ATTACK
        self.collector.start_phase(TestPhase.ATTACK)
        
        # Initialize and start spoofer
        self._init_spoofer()
        
        self._log("Starting ARP poisoning attack...")
        self._spoofer.start()
        
        # Also start detector to show alerts
        if self.config.use_detector:
            self._init_defenses()
            self._detector.start()
            
        # Calculate message count
        msg_count = int(self.config.attack_duration / self.config.message_interval)
        
        # Send test messages (will experience interference)
        self._send_test_messages(msg_count, self.config.message_interval)
        
        # Stop attack
        self._spoofer.stop(restore=True)
        
        if self._detector:
            self._detector.stop()
            
        self.collector.end_phase()
        self._log("Attack phase complete")
        
        # Log attack statistics
        stats = self._spoofer.get_statistics()
        self._log(f"Attack stats: {stats['total_packets_sent']} poison packets sent")
        
    def _run_mitigation_phase(self):
        """Run mitigation phase - defenses enabled"""
        self._log("\n" + "=" * 50)
        self._log("PHASE 3: MITIGATED")
        self._log("=" * 50)
        
        self._current_phase = TestPhase.MITIGATED
        self.collector.start_phase(TestPhase.MITIGATED)
        
        # Initialize defenses
        self._init_defenses()
        
        # Enable static ARP for gateway
        if self._static_arp:
            self._log("Enabling static ARP protection...")
            self._static_arp.protect_gateway()
            
        # Start detector
        if self._detector:
            self._detector.start()
            
        # Start attack again (should be mitigated)
        self._log("Starting ARP attack (with defenses active)...")
        self._init_spoofer()
        self._spoofer.start()
        
        # Calculate message count
        msg_count = int(self.config.mitigation_duration / self.config.message_interval)
        
        # Send test messages (should be protected)
        self._send_test_messages(msg_count, self.config.message_interval)
        
        # Stop attack
        self._spoofer.stop(restore=True)
        
        # Stop detector
        if self._detector:
            self._detector.stop()
            
        # Clear static ARP entries
        if self._static_arp:
            self._static_arp.clear_all()
            
        self.collector.end_phase()
        self._log("Mitigation phase complete")
        
    def run(self) -> Dict:
        """
        Run the complete testbed experiment
        
        Returns:
            Results dictionary with metrics and analysis
        """
        self._log("\n" + "=" * 60)
        self._log("   ARP TESTBED EXPERIMENT")
        self._log("=" * 60)
        self._log(f"Started at: {datetime.now().isoformat()}")
        
        self._running = True
        self._stop_event.clear()
        
        try:
            # Phase 1: Baseline
            self._run_baseline_phase()
            time.sleep(1)
            
            # Phase 2: Attack
            self._run_attack_phase()
            time.sleep(1)
            
            # Phase 3: Mitigation
            self._run_mitigation_phase()
            
        except KeyboardInterrupt:
            self._log("\nExperiment interrupted by user")
        except Exception as e:
            self._log(f"Error during experiment: {e}", "ERROR")
            raise
        finally:
            self._running = False
            self._cleanup()
            
        # Analyze and save results
        self._generate_results()
        
        self._log("\n" + "=" * 60)
        self._log("   EXPERIMENT COMPLETE")
        self._log("=" * 60)
        
        return self.results
        
    def _cleanup(self):
        """Clean up all components"""
        self._log("Cleaning up...")
        
        if self._spoofer and self._spoofer.is_running():
            self._spoofer.stop(restore=True)
            
        if self._detector and self._detector.is_running():
            self._detector.stop()
            
        if self._static_arp:
            self._static_arp.clear_all()
            
        if self._chat:
            self._chat.stop()
            
    def _generate_results(self):
        """Generate and save results"""
        self._log("\nGenerating results...")
        
        # Create output directory
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        # Get analysis
        analyzer = MetricsAnalyzer(self.collector)
        
        self.results = {
            'summary': self.collector.get_summary(),
            'comparison': self.collector.get_comparison(),
            'attack_impact': analyzer.calculate_attack_impact(),
            'mitigation_effectiveness': analyzer.calculate_mitigation_effectiveness()
        }
        
        # Save metrics
        if self.config.save_metrics:
            json_path = os.path.join(
                self.config.output_dir,
                f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            self.collector.export_json(json_path)
            
            csv_path = os.path.join(
                self.config.output_dir,
                f"messages_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            )
            self.collector.export_csv(csv_path)
            
        # Generate visualizations
        if self.config.generate_plots:
            self._log("Generating visualizations...")
            
            try:
                visualizer = MetricsVisualizer(self.collector)
                
                dashboard_path = os.path.join(
                    self.config.output_dir,
                    f"dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                )
                visualizer.create_dashboard(filepath=dashboard_path, show=False)
                
                plots_dir = os.path.join(self.config.output_dir, "plots")
                visualizer.save_all_plots(plots_dir)
                
            except Exception as e:
                self._log(f"Error generating plots: {e}", "WARNING")
                
        # Print summary
        analyzer.print_report()
        
    def stop(self):
        """Stop the experiment early"""
        self._log("Stopping experiment...")
        self._stop_event.set()
        self._running = False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="ARP Testbed Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py -i en0 -t 192.168.1.100
  python orchestrator.py -i eth0 -t 192.168.1.100 -g 192.168.1.1 --duration 60
  python orchestrator.py -i wlan0 -t 192.168.1.100 --no-attack --baseline-only
        """
    )
    
    parser.add_argument("-i", "--interface", required=True,
                       help="Network interface to use")
    parser.add_argument("-t", "--target", required=True,
                       help="Target IP address for testing")
    parser.add_argument("-g", "--gateway",
                       help="Gateway IP (auto-detected if not specified)")
    parser.add_argument("--baseline-duration", type=float, default=30,
                       help="Duration of baseline phase in seconds")
    parser.add_argument("--attack-duration", type=float, default=30,
                       help="Duration of attack phase in seconds")
    parser.add_argument("--mitigation-duration", type=float, default=30,
                       help="Duration of mitigation phase in seconds")
    parser.add_argument("--message-interval", type=float, default=0.5,
                       help="Interval between test messages")
    parser.add_argument("--output-dir", default="results",
                       help="Directory for output files")
    parser.add_argument("--no-plots", action="store_true",
                       help="Skip plot generation")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Reduce output verbosity")
                       
    args = parser.parse_args()
    
    # Create configuration
    config = TestConfiguration(
        interface=args.interface,
        target_ip=args.target,
        gateway_ip=args.gateway,
        baseline_duration=args.baseline_duration,
        attack_duration=args.attack_duration,
        mitigation_duration=args.mitigation_duration,
        message_interval=args.message_interval,
        output_dir=args.output_dir,
        generate_plots=not args.no_plots,
        verbose=not args.quiet
    )
    
    # Run experiment
    try:
        orchestrator = ARPTestbedOrchestrator(config)
        results = orchestrator.run()
        
        print("\n✅ Experiment completed successfully!")
        print(f"   Results saved to: {args.output_dir}/")
        
    except KeyboardInterrupt:
        print("\n⚠️  Experiment interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
