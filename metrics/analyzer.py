"""
Metrics Analyzer for ARP Testbed

This module provides analysis and statistical functions for
the collected metrics data.
"""

import statistics
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from metrics.collector import MetricsCollector, TestPhase


@dataclass
class StatisticalSummary:
    """Statistical summary of a metric"""
    count: int
    mean: float
    median: float
    std_dev: float
    min_val: float
    max_val: float
    percentile_25: float
    percentile_75: float
    percentile_95: float
    percentile_99: float
    
    def to_dict(self) -> Dict:
        return {
            'count': self.count,
            'mean': round(self.mean, 2),
            'median': round(self.median, 2),
            'std_dev': round(self.std_dev, 2),
            'min': round(self.min_val, 2),
            'max': round(self.max_val, 2),
            'p25': round(self.percentile_25, 2),
            'p75': round(self.percentile_75, 2),
            'p95': round(self.percentile_95, 2),
            'p99': round(self.percentile_99, 2)
        }


class MetricsAnalyzer:
    """
    Analyzes collected metrics and provides statistical insights
    """
    
    def __init__(self, collector: MetricsCollector):
        """
        Initialize analyzer with a metrics collector
        
        Args:
            collector: MetricsCollector with data
        """
        self.collector = collector
        
    def _calculate_percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile of sorted data"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = (len(sorted_data) - 1) * (percentile / 100)
        lower = int(index)
        upper = lower + 1
        if upper >= len(sorted_data):
            return sorted_data[-1]
        weight = index - lower
        return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight
        
    def get_latency_stats(self, phase: TestPhase) -> Optional[StatisticalSummary]:
        """Get statistical summary of latencies for a phase"""
        latencies = self.collector.get_latency_distribution(phase)
        
        if not latencies:
            return None
            
        return StatisticalSummary(
            count=len(latencies),
            mean=statistics.mean(latencies),
            median=statistics.median(latencies),
            std_dev=statistics.stdev(latencies) if len(latencies) > 1 else 0,
            min_val=min(latencies),
            max_val=max(latencies),
            percentile_25=self._calculate_percentile(latencies, 25),
            percentile_75=self._calculate_percentile(latencies, 75),
            percentile_95=self._calculate_percentile(latencies, 95),
            percentile_99=self._calculate_percentile(latencies, 99)
        )
        
    def compare_latencies(self) -> Dict:
        """Compare latency statistics across phases"""
        result = {}
        
        for phase in TestPhase:
            stats = self.get_latency_stats(phase)
            if stats:
                result[phase.value] = stats.to_dict()
                
        return result
        
    def calculate_attack_impact(self) -> Dict:
        """Calculate the impact of the attack on performance"""
        baseline = self.collector.get_phase_metrics(TestPhase.BASELINE)
        attack = self.collector.get_phase_metrics(TestPhase.ATTACK)
        
        impact = {
            'delivery_rate_change': attack['delivery_rate'] - baseline['delivery_rate'],
            'latency_change_ms': attack['avg_latency_ms'] - baseline['avg_latency_ms'],
            'throughput_change': attack['throughput_mps'] - baseline['throughput_mps'],
            'messages_intercepted': attack['messages_intercepted'],
            'interception_rate': attack['interception_rate']
        }
        
        # Calculate severity score (0-100)
        severity = 0
        
        # Delivery rate impact (up to 40 points)
        if impact['delivery_rate_change'] < 0:
            severity += min(40, abs(impact['delivery_rate_change']) * 0.4)
            
        # Latency impact (up to 30 points)
        if baseline['avg_latency_ms'] > 0:
            latency_increase = impact['latency_change_ms'] / baseline['avg_latency_ms'] * 100
            severity += min(30, latency_increase * 0.3)
            
        # Interception impact (up to 30 points)
        severity += impact['interception_rate'] * 0.3
        
        impact['severity_score'] = round(min(100, severity), 1)
        
        return impact
        
    def calculate_mitigation_effectiveness(self) -> Dict:
        """Calculate how effective the mitigations were"""
        baseline = self.collector.get_phase_metrics(TestPhase.BASELINE)
        attack = self.collector.get_phase_metrics(TestPhase.ATTACK)
        mitigated = self.collector.get_phase_metrics(TestPhase.MITIGATED)
        
        effectiveness = {
            'delivery_rate': {
                'baseline': baseline['delivery_rate'],
                'attack': attack['delivery_rate'],
                'mitigated': mitigated['delivery_rate'],
                'recovery_percent': 0
            },
            'latency': {
                'baseline': baseline['avg_latency_ms'],
                'attack': attack['avg_latency_ms'],
                'mitigated': mitigated['avg_latency_ms'],
                'overhead_from_baseline': mitigated['avg_latency_ms'] - baseline['avg_latency_ms']
            },
            'interception': {
                'attack_rate': attack['interception_rate'],
                'mitigated_rate': mitigated['interception_rate'],
                'reduction_percent': attack['interception_rate'] - mitigated['interception_rate']
            }
        }
        
        # Calculate delivery recovery
        attack_drop = baseline['delivery_rate'] - attack['delivery_rate']
        if attack_drop > 0:
            recovery = mitigated['delivery_rate'] - attack['delivery_rate']
            effectiveness['delivery_rate']['recovery_percent'] = (recovery / attack_drop) * 100
            
        # Overall effectiveness score (0-100)
        score = 0
        
        # Delivery recovery (up to 40 points)
        score += min(40, effectiveness['delivery_rate']['recovery_percent'] * 0.4)
        
        # Interception reduction (up to 40 points)
        score += min(40, effectiveness['interception']['reduction_percent'] * 0.4)
        
        # Latency preservation (up to 20 points)
        if baseline['avg_latency_ms'] > 0:
            overhead_ratio = effectiveness['latency']['overhead_from_baseline'] / baseline['avg_latency_ms']
            if overhead_ratio < 0.5:
                score += 20 * (1 - overhead_ratio)
                
        effectiveness['overall_score'] = round(min(100, score), 1)
        
        return effectiveness
        
    def get_full_report(self) -> Dict:
        """Generate a comprehensive analysis report"""
        return {
            'experiment': self.collector.experiment_name,
            'summary': self.collector.get_summary(),
            'latency_statistics': self.compare_latencies(),
            'attack_impact': self.calculate_attack_impact(),
            'mitigation_effectiveness': self.calculate_mitigation_effectiveness(),
            'comparison': self.collector.get_comparison()
        }
        
    def print_report(self):
        """Print a formatted analysis report"""
        report = self.get_full_report()
        
        print("\n" + "=" * 60)
        print(f"  ARP TESTBED ANALYSIS REPORT")
        print(f"  Experiment: {report['experiment']}")
        print("=" * 60)
        
        # Phase summaries
        print("\n📊 PHASE SUMMARIES")
        print("-" * 40)
        
        for phase_name, metrics in report['summary']['phases'].items():
            print(f"\n{phase_name.upper()}:")
            print(f"  Messages: {metrics['messages_sent']} sent, "
                  f"{metrics['messages_received']} received")
            print(f"  Delivery Rate: {metrics['delivery_rate']}%")
            print(f"  Loss Rate: {metrics['loss_rate']}%")
            if metrics['interception_rate'] > 0:
                print(f"  Interception Rate: {metrics['interception_rate']}%")
            print(f"  Avg Latency: {metrics['avg_latency_ms']} ms")
            print(f"  Throughput: {metrics['throughput_mps']} msg/s")
            
        # Attack impact
        print("\n⚔️  ATTACK IMPACT")
        print("-" * 40)
        impact = report['attack_impact']
        print(f"  Delivery Rate Change: {impact['delivery_rate_change']:+.1f}%")
        print(f"  Latency Change: {impact['latency_change_ms']:+.2f} ms")
        print(f"  Messages Intercepted: {impact['messages_intercepted']}")
        print(f"  Severity Score: {impact['severity_score']}/100")
        
        # Mitigation effectiveness
        print("\n🛡️  MITIGATION EFFECTIVENESS")
        print("-" * 40)
        eff = report['mitigation_effectiveness']
        print(f"  Delivery Recovery: {eff['delivery_rate']['recovery_percent']:.1f}%")
        print(f"  Interception Reduction: {eff['interception']['reduction_percent']:.1f}%")
        print(f"  Latency Overhead: {eff['latency']['overhead_from_baseline']:.2f} ms")
        print(f"  Overall Score: {eff['overall_score']}/100")
        
        # Latency statistics
        print("\n⏱️  LATENCY STATISTICS")
        print("-" * 40)
        for phase_name, stats in report['latency_statistics'].items():
            print(f"\n{phase_name.upper()}:")
            print(f"  Mean: {stats['mean']} ms, Median: {stats['median']} ms")
            print(f"  Std Dev: {stats['std_dev']} ms")
            print(f"  Range: {stats['min']} - {stats['max']} ms")
            print(f"  P95: {stats['p95']} ms, P99: {stats['p99']} ms")
            
        print("\n" + "=" * 60)


if __name__ == "__main__":
    # Demo with synthetic data
    from metrics.collector import MetricsCollector
    import time
    import random
    
    collector = MetricsCollector("analysis_demo")
    
    # Generate test data
    # Baseline: good performance
    collector.start_phase(TestPhase.BASELINE)
    for _ in range(50):
        msg_id = collector.record_send()
        time.sleep(random.uniform(0.005, 0.015))
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Attack: degraded performance
    collector.start_phase(TestPhase.ATTACK)
    for i in range(50):
        intercepted = random.random() < 0.3
        msg_id = collector.record_send(intercepted=intercepted)
        time.sleep(random.uniform(0.015, 0.04))
        if random.random() > 0.2:  # 20% packet loss
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Mitigated: recovered performance
    collector.start_phase(TestPhase.MITIGATED)
    for _ in range(50):
        msg_id = collector.record_send()
        time.sleep(random.uniform(0.008, 0.018))
        if random.random() > 0.02:  # 2% packet loss
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Analyze
    analyzer = MetricsAnalyzer(collector)
    analyzer.print_report()
