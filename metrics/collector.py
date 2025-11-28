"""
Metrics Collector for ARP Testbed

This module collects and stores metrics during baseline, attack,
and mitigated test phases for later analysis and visualization.

Metrics collected:
- Message delivery rate
- End-to-end latency
- Packet loss percentage
- Throughput (messages/second)
- Interception rate (during attacks)
- Defense effectiveness
"""

import threading
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict
import json
import csv


class TestPhase(Enum):
    """Test phases for metrics collection"""
    BASELINE = "baseline"
    ATTACK = "attack"
    MITIGATED = "mitigated"


@dataclass
class MessageMetric:
    """Metrics for a single message"""
    message_id: int
    send_time: float  # Unix timestamp
    receive_time: Optional[float] = None  # Unix timestamp
    delivered: bool = False
    intercepted: bool = False
    latency_ms: Optional[float] = None
    phase: TestPhase = TestPhase.BASELINE
    
    def calculate_latency(self):
        """Calculate latency if received"""
        if self.receive_time and self.send_time:
            self.latency_ms = (self.receive_time - self.send_time) * 1000
            self.delivered = True


@dataclass
class PhaseMetrics:
    """Aggregated metrics for a test phase"""
    phase: TestPhase
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    messages_sent: int = 0
    messages_received: int = 0
    messages_lost: int = 0
    messages_intercepted: int = 0
    total_latency_ms: float = 0
    min_latency_ms: Optional[float] = None
    max_latency_ms: Optional[float] = None
    latencies: List[float] = field(default_factory=list)
    
    # New metrics for retry/abort tracking (per synopsis requirements)
    retry_count: int = 0
    abort_count: int = 0
    recovery_start_time: Optional[float] = None
    recovery_end_time: Optional[float] = None
    attacks_detected: int = 0
    false_positives: int = 0
    
    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0
        
    @property
    def delivery_rate(self) -> float:
        """Percentage of messages delivered"""
        if self.messages_sent == 0:
            return 0
        return (self.messages_received / self.messages_sent) * 100
        
    @property
    def loss_rate(self) -> float:
        """Percentage of messages lost"""
        if self.messages_sent == 0:
            return 0
        return (self.messages_lost / self.messages_sent) * 100
        
    @property
    def interception_rate(self) -> float:
        """Percentage of messages intercepted"""
        if self.messages_sent == 0:
            return 0
        return (self.messages_intercepted / self.messages_sent) * 100
        
    @property
    def avg_latency_ms(self) -> float:
        """Average latency in milliseconds"""
        if not self.latencies:
            return 0
        return sum(self.latencies) / len(self.latencies)
        
    @property
    def throughput(self) -> float:
        """Messages per second"""
        if self.duration_seconds == 0:
            return 0
        return self.messages_received / self.duration_seconds
    
    @property
    def retry_rate(self) -> float:
        """Average retries per message sent"""
        if self.messages_sent == 0:
            return 0
        return self.retry_count / self.messages_sent
    
    @property
    def abort_rate(self) -> float:
        """Percentage of messages aborted"""
        if self.messages_sent == 0:
            return 0
        return (self.abort_count / self.messages_sent) * 100
    
    @property
    def time_to_recovery_sec(self) -> Optional[float]:
        """Time from attack detection to full recovery (seconds)"""
        if self.recovery_start_time and self.recovery_end_time:
            return self.recovery_end_time - self.recovery_start_time
        return None
    
    @property
    def detection_rate(self) -> float:
        """Rate of successful attack detection"""
        # This would be relative to actual attacks - for now return raw count
        return self.attacks_detected
    
    @property
    def false_positive_rate(self) -> float:
        """Percentage of false positive detections"""
        total_detections = self.attacks_detected + self.false_positives
        if total_detections == 0:
            return 0
        return (self.false_positives / total_detections) * 100
        
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'phase': self.phase.value,
            'duration_seconds': self.duration_seconds,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'messages_lost': self.messages_lost,
            'messages_intercepted': self.messages_intercepted,
            'delivery_rate': round(self.delivery_rate, 2),
            'loss_rate': round(self.loss_rate, 2),
            'interception_rate': round(self.interception_rate, 2),
            'avg_latency_ms': round(self.avg_latency_ms, 2),
            'min_latency_ms': round(self.min_latency_ms, 2) if self.min_latency_ms else None,
            'max_latency_ms': round(self.max_latency_ms, 2) if self.max_latency_ms else None,
            'throughput_mps': round(self.throughput, 2),
            # New metrics
            'retry_count': self.retry_count,
            'abort_count': self.abort_count,
            'retry_rate': round(self.retry_rate, 3),
            'abort_rate': round(self.abort_rate, 2),
            'time_to_recovery_sec': round(self.time_to_recovery_sec, 3) if self.time_to_recovery_sec else None,
            'attacks_detected': self.attacks_detected,
            'false_positives': self.false_positives,
            'false_positive_rate': round(self.false_positive_rate, 2),
        }


class MetricsCollector:
    """
    Collects metrics during ARP testbed experiments
    
    Usage:
        collector = MetricsCollector()
        
        # Start baseline phase
        collector.start_phase(TestPhase.BASELINE)
        
        # Record messages
        msg_id = collector.record_send()
        collector.record_receive(msg_id)
        
        # End phase
        collector.end_phase()
        
        # Get results
        results = collector.get_summary()
    """
    
    def __init__(self, experiment_name: str = "arp_testbed"):
        """
        Initialize metrics collector
        
        Args:
            experiment_name: Name for this experiment
        """
        self.experiment_name = experiment_name
        self.start_time = datetime.now()
        
        # Current phase
        self._current_phase: Optional[TestPhase] = None
        
        # Per-phase metrics
        self._phase_metrics: Dict[TestPhase, PhaseMetrics] = {
            TestPhase.BASELINE: PhaseMetrics(phase=TestPhase.BASELINE),
            TestPhase.ATTACK: PhaseMetrics(phase=TestPhase.ATTACK),
            TestPhase.MITIGATED: PhaseMetrics(phase=TestPhase.MITIGATED),
        }
        
        # Individual message tracking
        self._messages: Dict[int, MessageMetric] = {}
        self._message_counter = 0
        self._lock = threading.Lock()
        
        # Time series data for plotting
        self._time_series: Dict[TestPhase, List[Dict]] = defaultdict(list)
        
    def start_phase(self, phase: TestPhase):
        """Start a test phase"""
        with self._lock:
            self._current_phase = phase
            self._phase_metrics[phase].start_time = datetime.now()
            print(f"[MetricsCollector] Started phase: {phase.value}")
            
    def end_phase(self):
        """End the current test phase"""
        with self._lock:
            if self._current_phase:
                phase = self._current_phase
                self._phase_metrics[phase].end_time = datetime.now()
                
                # Calculate lost messages
                for msg in self._messages.values():
                    if msg.phase == phase and not msg.delivered:
                        self._phase_metrics[phase].messages_lost += 1
                        
                print(f"[MetricsCollector] Ended phase: {phase.value}")
                self._current_phase = None
                
    def record_send(self, intercepted: bool = False) -> int:
        """
        Record a message being sent
        
        Args:
            intercepted: If True, message was intercepted by attacker
            
        Returns:
            Message ID for tracking
        """
        with self._lock:
            self._message_counter += 1
            msg_id = self._message_counter
            
            phase = self._current_phase or TestPhase.BASELINE
            
            self._messages[msg_id] = MessageMetric(
                message_id=msg_id,
                send_time=time.time(),
                phase=phase,
                intercepted=intercepted
            )
            
            self._phase_metrics[phase].messages_sent += 1
            
            if intercepted:
                self._phase_metrics[phase].messages_intercepted += 1
                
            # Record time series point
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'send',
                'message_id': msg_id,
                'intercepted': intercepted
            })
            
            return msg_id
            
    def record_receive(self, message_id: int):
        """
        Record a message being received
        
        Args:
            message_id: ID from record_send
        """
        with self._lock:
            if message_id not in self._messages:
                return
                
            msg = self._messages[message_id]
            msg.receive_time = time.time()
            msg.calculate_latency()
            
            phase = msg.phase
            metrics = self._phase_metrics[phase]
            
            metrics.messages_received += 1
            
            if msg.latency_ms is not None:
                metrics.latencies.append(msg.latency_ms)
                metrics.total_latency_ms += msg.latency_ms
                
                if metrics.min_latency_ms is None or msg.latency_ms < metrics.min_latency_ms:
                    metrics.min_latency_ms = msg.latency_ms
                if metrics.max_latency_ms is None or msg.latency_ms > metrics.max_latency_ms:
                    metrics.max_latency_ms = msg.latency_ms
                    
            # Record time series point
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'receive',
                'message_id': message_id,
                'latency_ms': msg.latency_ms
            })
            
    def record_custom_metric(self, name: str, value: Any, phase: Optional[TestPhase] = None):
        """Record a custom metric"""
        phase = phase or self._current_phase or TestPhase.BASELINE
        
        self._time_series[phase].append({
            'timestamp': time.time(),
            'event': 'custom',
            'name': name,
            'value': value
        })
    
    def record_retry(self, message_id: Optional[int] = None):
        """
        Record a message retry attempt.
        
        This tracks when a message needs to be re-sent due to delivery failure.
        """
        with self._lock:
            phase = self._current_phase or TestPhase.BASELINE
            self._phase_metrics[phase].retry_count += 1
            
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'retry',
                'message_id': message_id
            })
    
    def record_abort(self, message_id: Optional[int] = None, reason: str = ""):
        """
        Record a message abort.
        
        This tracks when a message is abandoned after failed delivery attempts.
        """
        with self._lock:
            phase = self._current_phase or TestPhase.BASELINE
            self._phase_metrics[phase].abort_count += 1
            
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'abort',
                'message_id': message_id,
                'reason': reason
            })
    
    def record_attack_detected(self, is_false_positive: bool = False):
        """
        Record an attack detection event.
        
        Args:
            is_false_positive: If True, this detection was a false positive
        """
        with self._lock:
            phase = self._current_phase or TestPhase.BASELINE
            
            if is_false_positive:
                self._phase_metrics[phase].false_positives += 1
            else:
                self._phase_metrics[phase].attacks_detected += 1
            
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'detection',
                'false_positive': is_false_positive
            })
    
    def start_recovery_timer(self):
        """
        Start the recovery timer.
        
        Call this when an attack is detected and mitigation begins.
        """
        with self._lock:
            phase = self._current_phase or TestPhase.BASELINE
            self._phase_metrics[phase].recovery_start_time = time.time()
            
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'recovery_start'
            })
    
    def stop_recovery_timer(self):
        """
        Stop the recovery timer.
        
        Call this when normal operation is restored after mitigation.
        """
        with self._lock:
            phase = self._current_phase or TestPhase.BASELINE
            self._phase_metrics[phase].recovery_end_time = time.time()
            
            recovery_time = self._phase_metrics[phase].time_to_recovery_sec
            
            self._time_series[phase].append({
                'timestamp': time.time(),
                'event': 'recovery_complete',
                'recovery_time_sec': recovery_time
            })
            
            return recovery_time
        
    def get_phase_metrics(self, phase: TestPhase) -> Dict:
        """Get metrics for a specific phase"""
        with self._lock:
            return self._phase_metrics[phase].to_dict()
            
    def get_all_phases(self) -> Dict[str, Dict]:
        """Get metrics for all phases"""
        with self._lock:
            return {
                phase.value: self._phase_metrics[phase].to_dict()
                for phase in TestPhase
            }
            
    def get_summary(self) -> Dict:
        """Get complete experiment summary"""
        with self._lock:
            return {
                'experiment_name': self.experiment_name,
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_messages': len(self._messages),
                'phases': {
                    phase.value: self._phase_metrics[phase].to_dict()
                    for phase in TestPhase
                }
            }
            
    def get_comparison(self) -> Dict:
        """Get comparison metrics between phases"""
        baseline = self._phase_metrics[TestPhase.BASELINE]
        attack = self._phase_metrics[TestPhase.ATTACK]
        mitigated = self._phase_metrics[TestPhase.MITIGATED]
        
        comparison = {
            'delivery_rate': {
                'baseline': baseline.delivery_rate,
                'attack': attack.delivery_rate,
                'mitigated': mitigated.delivery_rate,
                'attack_impact': baseline.delivery_rate - attack.delivery_rate,
                'mitigation_recovery': mitigated.delivery_rate - attack.delivery_rate
            },
            'latency_ms': {
                'baseline': baseline.avg_latency_ms,
                'attack': attack.avg_latency_ms,
                'mitigated': mitigated.avg_latency_ms,
                'attack_overhead': attack.avg_latency_ms - baseline.avg_latency_ms,
                'mitigation_overhead': mitigated.avg_latency_ms - baseline.avg_latency_ms
            },
            'throughput': {
                'baseline': baseline.throughput,
                'attack': attack.throughput,
                'mitigated': mitigated.throughput
            },
            'interception_rate': {
                'attack': attack.interception_rate,
                'mitigated': mitigated.interception_rate,
                'reduction': attack.interception_rate - mitigated.interception_rate
            }
        }
        
        # Calculate overall effectiveness
        if attack.delivery_rate < baseline.delivery_rate:
            attack_severity = baseline.delivery_rate - attack.delivery_rate
            if attack_severity > 0:
                recovery = mitigated.delivery_rate - attack.delivery_rate
                comparison['mitigation_effectiveness'] = (recovery / attack_severity) * 100
            else:
                comparison['mitigation_effectiveness'] = 100
        else:
            comparison['mitigation_effectiveness'] = 100
            
        return comparison
        
    def get_time_series(self, phase: Optional[TestPhase] = None) -> Dict[str, List[Dict]]:
        """Get time series data for plotting"""
        with self._lock:
            if phase:
                return {phase.value: list(self._time_series[phase])}
            else:
                return {
                    p.value: list(self._time_series[p])
                    for p in TestPhase
                }
                
    def get_latency_distribution(self, phase: TestPhase) -> List[float]:
        """Get latency distribution for a phase"""
        with self._lock:
            return list(self._phase_metrics[phase].latencies)
            
    def export_json(self, filepath: str):
        """Export all metrics to JSON file"""
        data = {
            'summary': self.get_summary(),
            'comparison': self.get_comparison(),
            'time_series': self.get_time_series()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
        print(f"[MetricsCollector] Exported to {filepath}")
        
    def export_csv(self, filepath: str):
        """Export message-level metrics to CSV"""
        with self._lock:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'message_id', 'phase', 'send_time', 'receive_time',
                    'delivered', 'intercepted', 'latency_ms'
                ])
                
                for msg in self._messages.values():
                    writer.writerow([
                        msg.message_id,
                        msg.phase.value,
                        msg.send_time,
                        msg.receive_time,
                        msg.delivered,
                        msg.intercepted,
                        msg.latency_ms
                    ])
                    
        print(f"[MetricsCollector] Exported to {filepath}")
        
    def reset(self):
        """Reset all metrics"""
        with self._lock:
            self._messages.clear()
            self._message_counter = 0
            self._time_series.clear()
            
            for phase in TestPhase:
                self._phase_metrics[phase] = PhaseMetrics(phase=phase)
                
            print("[MetricsCollector] Reset all metrics")


class LatencyTracker:
    """Helper class for tracking latency of specific operations"""
    
    def __init__(self, collector: MetricsCollector):
        self.collector = collector
        self._start_times: Dict[str, float] = {}
        
    def start(self, operation_id: str):
        """Start timing an operation"""
        self._start_times[operation_id] = time.time()
        
    def end(self, operation_id: str) -> Optional[float]:
        """End timing and return latency in ms"""
        if operation_id in self._start_times:
            latency = (time.time() - self._start_times[operation_id]) * 1000
            del self._start_times[operation_id]
            return latency
        return None
        
    def __enter__(self):
        """Context manager for timing code blocks"""
        self._context_start = time.time()
        return self
        
    def __exit__(self, *args):
        self.latency_ms = (time.time() - self._context_start) * 1000


if __name__ == "__main__":
    # Demo usage
    collector = MetricsCollector("demo_experiment")
    
    # Simulate baseline
    collector.start_phase(TestPhase.BASELINE)
    for i in range(10):
        msg_id = collector.record_send()
        time.sleep(0.01)  # Simulate network delay
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Simulate attack (some messages lost/intercepted)
    collector.start_phase(TestPhase.ATTACK)
    for i in range(10):
        intercepted = i % 3 == 0
        msg_id = collector.record_send(intercepted=intercepted)
        time.sleep(0.02)  # Higher latency during attack
        if i % 4 != 0:  # Some messages lost
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Simulate mitigated
    collector.start_phase(TestPhase.MITIGATED)
    for i in range(10):
        msg_id = collector.record_send()
        time.sleep(0.015)  # Slight overhead from mitigation
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Print summary
    print("\n=== Experiment Summary ===")
    summary = collector.get_summary()
    for phase, metrics in summary['phases'].items():
        print(f"\n{phase.upper()}:")
        print(f"  Delivery Rate: {metrics['delivery_rate']}%")
        print(f"  Loss Rate: {metrics['loss_rate']}%")
        print(f"  Avg Latency: {metrics['avg_latency_ms']:.2f} ms")
        print(f"  Throughput: {metrics['throughput_mps']:.2f} msg/s")
        
    print("\n=== Comparison ===")
    comparison = collector.get_comparison()
    print(f"Attack Impact on Delivery: -{comparison['delivery_rate']['attack_impact']:.1f}%")
    print(f"Mitigation Effectiveness: {comparison['mitigation_effectiveness']:.1f}%")
