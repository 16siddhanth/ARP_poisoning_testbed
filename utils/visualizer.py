"""
Metrics Visualizer for ARP Testbed

Creates matplotlib visualizations for comparing baseline, attack,
and mitigated test scenarios.

Generates:
- Bar charts comparing delivery rates
- Latency distribution histograms
- Time series plots
- Combined dashboard figures
"""

import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.gridspec import GridSpec
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    print("Warning: matplotlib not available. Visualization disabled.")

from metrics.collector import MetricsCollector, TestPhase
from metrics.analyzer import MetricsAnalyzer


# Color scheme
COLORS = {
    TestPhase.BASELINE: '#2ecc71',   # Green
    TestPhase.ATTACK: '#e74c3c',     # Red
    TestPhase.MITIGATED: '#3498db',  # Blue
}

PHASE_NAMES = {
    TestPhase.BASELINE: 'Baseline',
    TestPhase.ATTACK: 'Under Attack',
    TestPhase.MITIGATED: 'Mitigated',
}


class MetricsVisualizer:
    """
    Creates visualizations for ARP testbed metrics
    
    Usage:
        visualizer = MetricsVisualizer(collector)
        
        # Individual plots
        visualizer.plot_delivery_rates()
        visualizer.plot_latency_distribution()
        
        # Save all visualizations
        visualizer.save_all_plots("output/")
        
        # Generate dashboard
        visualizer.create_dashboard("output/dashboard.png")
    """
    
    def __init__(
        self,
        collector: MetricsCollector,
        style: str = 'seaborn-v0_8-whitegrid',
        figsize: Tuple[int, int] = (10, 6)
    ):
        """
        Initialize visualizer
        
        Args:
            collector: MetricsCollector with data
            style: Matplotlib style to use
            figsize: Default figure size
        """
        if not MATPLOTLIB_AVAILABLE:
            raise RuntimeError("matplotlib is required for visualization")
            
        self.collector = collector
        self.analyzer = MetricsAnalyzer(collector)
        self.figsize = figsize
        
        # Try to set style, fall back if not available
        try:
            plt.style.use(style)
        except:
            try:
                plt.style.use('seaborn-whitegrid')
            except:
                pass  # Use default
                
    def _get_phase_color(self, phase: TestPhase) -> str:
        """Get color for a phase"""
        return COLORS.get(phase, '#95a5a6')
        
    def _get_phase_name(self, phase: TestPhase) -> str:
        """Get display name for a phase"""
        return PHASE_NAMES.get(phase, phase.value)
        
    def plot_delivery_rates(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot delivery rates comparison bar chart
        
        Args:
            ax: Optional axes to plot on
            show: Whether to display the plot
            
        Returns:
            matplotlib Figure
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        phases = [TestPhase.BASELINE, TestPhase.ATTACK, TestPhase.MITIGATED]
        metrics = [self.collector.get_phase_metrics(p) for p in phases]
        
        x = np.arange(len(phases))
        rates = [m['delivery_rate'] for m in metrics]
        colors = [self._get_phase_color(p) for p in phases]
        labels = [self._get_phase_name(p) for p in phases]
        
        bars = ax.bar(x, rates, color=colors, edgecolor='white', linewidth=2)
        
        # Add value labels on bars
        for bar, rate in zip(bars, rates):
            height = bar.get_height()
            ax.annotate(f'{rate:.1f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=12, fontweight='bold')
                       
        ax.set_ylabel('Delivery Rate (%)', fontsize=12)
        ax.set_title('Message Delivery Rate Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=11)
        ax.set_ylim(0, 110)
        ax.axhline(y=100, color='gray', linestyle='--', alpha=0.5)
        
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_latency_comparison(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot latency comparison bar chart
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        phases = [TestPhase.BASELINE, TestPhase.ATTACK, TestPhase.MITIGATED]
        
        x = np.arange(len(phases))
        width = 0.35
        
        avg_latencies = []
        p95_latencies = []
        
        for phase in phases:
            metrics = self.collector.get_phase_metrics(phase)
            stats = self.analyzer.get_latency_stats(phase)
            
            avg_latencies.append(metrics['avg_latency_ms'])
            p95_latencies.append(stats.percentile_95 if stats else 0)
            
        colors = [self._get_phase_color(p) for p in phases]
        labels = [self._get_phase_name(p) for p in phases]
        
        bars1 = ax.bar(x - width/2, avg_latencies, width, label='Average',
                       color=colors, edgecolor='white', alpha=0.8)
        bars2 = ax.bar(x + width/2, p95_latencies, width, label='P95',
                       color=colors, edgecolor='white', alpha=0.5,
                       hatch='//')
                       
        ax.set_ylabel('Latency (ms)', fontsize=12)
        ax.set_title('Latency Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=11)
        ax.legend()
        
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_latency_distribution(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True,
        bins: int = 20
    ) -> plt.Figure:
        """
        Plot latency distribution histograms
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        phases = [TestPhase.BASELINE, TestPhase.ATTACK, TestPhase.MITIGATED]
        
        for phase in phases:
            latencies = self.collector.get_latency_distribution(phase)
            if latencies:
                ax.hist(latencies, bins=bins, alpha=0.5,
                       color=self._get_phase_color(phase),
                       label=self._get_phase_name(phase),
                       edgecolor='white')
                       
        ax.set_xlabel('Latency (ms)', fontsize=12)
        ax.set_ylabel('Frequency', fontsize=12)
        ax.set_title('Latency Distribution', fontsize=14, fontweight='bold')
        ax.legend()
        
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_throughput(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot throughput comparison
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        phases = [TestPhase.BASELINE, TestPhase.ATTACK, TestPhase.MITIGATED]
        metrics = [self.collector.get_phase_metrics(p) for p in phases]
        
        x = np.arange(len(phases))
        throughputs = [m['throughput_mps'] for m in metrics]
        colors = [self._get_phase_color(p) for p in phases]
        labels = [self._get_phase_name(p) for p in phases]
        
        bars = ax.bar(x, throughputs, color=colors, edgecolor='white', linewidth=2)
        
        for bar, tp in zip(bars, throughputs):
            height = bar.get_height()
            ax.annotate(f'{tp:.1f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=12, fontweight='bold')
                       
        ax.set_ylabel('Messages/Second', fontsize=12)
        ax.set_title('Throughput Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=11)
        
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_attack_impact(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot attack impact metrics
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        impact = self.analyzer.calculate_attack_impact()
        
        # Create a stacked horizontal bar showing attack impact
        metrics = ['Delivery\nRate', 'Throughput']
        
        baseline = self.collector.get_phase_metrics(TestPhase.BASELINE)
        attack = self.collector.get_phase_metrics(TestPhase.ATTACK)
        
        baseline_vals = [baseline['delivery_rate'], baseline['throughput_mps']]
        attack_vals = [attack['delivery_rate'], attack['throughput_mps']]
        
        # Normalize to percentages
        normalized_baseline = [100, 100]
        normalized_attack = [
            (attack['delivery_rate'] / baseline['delivery_rate'] * 100) 
            if baseline['delivery_rate'] > 0 else 0,
            (attack['throughput_mps'] / baseline['throughput_mps'] * 100)
            if baseline['throughput_mps'] > 0 else 0
        ]
        
        y = np.arange(len(metrics))
        height = 0.35
        
        bars1 = ax.barh(y - height/2, normalized_baseline, height,
                       label='Baseline (100%)',
                       color=COLORS[TestPhase.BASELINE],
                       edgecolor='white')
        bars2 = ax.barh(y + height/2, normalized_attack, height,
                       label='Under Attack',
                       color=COLORS[TestPhase.ATTACK],
                       edgecolor='white')
                       
        ax.set_xlabel('Percentage of Baseline (%)', fontsize=12)
        ax.set_title('Attack Impact on Performance', fontsize=14, fontweight='bold')
        ax.set_yticks(y)
        ax.set_yticklabels(metrics, fontsize=11)
        ax.legend(loc='lower right')
        ax.axvline(x=100, color='gray', linestyle='--', alpha=0.5)
        ax.set_xlim(0, 120)
        
        # Add severity score
        ax.text(0.98, 0.02, f'Severity Score: {impact["severity_score"]}/100',
               transform=ax.transAxes, fontsize=11,
               verticalalignment='bottom', horizontalalignment='right',
               bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
               
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_mitigation_effectiveness(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot mitigation effectiveness
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=self.figsize)
        else:
            fig = ax.figure
            
        eff = self.analyzer.calculate_mitigation_effectiveness()
        
        # Create radar/bar chart for effectiveness metrics
        metrics = ['Delivery\nRecovery', 'Interception\nReduction', 'Latency\nPreservation']
        
        # Calculate latency preservation (inverse of overhead percentage)
        baseline_lat = eff['latency']['baseline']
        overhead = eff['latency']['overhead_from_baseline']
        if baseline_lat > 0:
            latency_preservation = max(0, 100 - (overhead / baseline_lat * 100))
        else:
            latency_preservation = 100
            
        values = [
            eff['delivery_rate']['recovery_percent'],
            eff['interception']['reduction_percent'],
            latency_preservation
        ]
        
        x = np.arange(len(metrics))
        colors = ['#3498db', '#9b59b6', '#1abc9c']
        
        bars = ax.bar(x, values, color=colors, edgecolor='white', linewidth=2)
        
        for bar, val in zip(bars, values):
            height = bar.get_height()
            ax.annotate(f'{val:.1f}%',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom',
                       fontsize=12, fontweight='bold')
                       
        ax.set_ylabel('Effectiveness (%)', fontsize=12)
        ax.set_title('Mitigation Effectiveness', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(metrics, fontsize=11)
        ax.set_ylim(0, 120)
        ax.axhline(y=100, color='gray', linestyle='--', alpha=0.5)
        
        # Add overall score
        ax.text(0.98, 0.02, f'Overall Score: {eff["overall_score"]}/100',
               transform=ax.transAxes, fontsize=11,
               verticalalignment='bottom', horizontalalignment='right',
               bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.5))
               
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def plot_time_series(
        self,
        ax: Optional[plt.Axes] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Plot latency over time for all phases
        """
        if ax is None:
            fig, ax = plt.subplots(figsize=(12, 6))
        else:
            fig = ax.figure
            
        time_data = self.collector.get_time_series()
        
        for phase_name, events in time_data.items():
            phase = TestPhase(phase_name)
            
            # Extract receive events with latency
            times = []
            latencies = []
            
            for event in events:
                if event['event'] == 'receive' and event.get('latency_ms'):
                    times.append(event['timestamp'])
                    latencies.append(event['latency_ms'])
                    
            if times:
                # Normalize times to start from 0
                start_time = min(times)
                rel_times = [(t - start_time) for t in times]
                
                ax.plot(rel_times, latencies,
                       color=self._get_phase_color(phase),
                       label=self._get_phase_name(phase),
                       marker='o', markersize=3, alpha=0.7)
                       
        ax.set_xlabel('Time (seconds)', fontsize=12)
        ax.set_ylabel('Latency (ms)', fontsize=12)
        ax.set_title('Latency Over Time', fontsize=14, fontweight='bold')
        ax.legend()
        
        if show:
            plt.tight_layout()
            plt.show()
            
        return fig
        
    def create_dashboard(
        self,
        filepath: Optional[str] = None,
        show: bool = True
    ) -> plt.Figure:
        """
        Create a comprehensive dashboard with all visualizations
        
        Args:
            filepath: Path to save the dashboard image
            show: Whether to display the dashboard
            
        Returns:
            matplotlib Figure
        """
        fig = plt.figure(figsize=(16, 12))
        gs = GridSpec(3, 3, figure=fig, hspace=0.3, wspace=0.3)
        
        # Title
        fig.suptitle(f'ARP Testbed Results: {self.collector.experiment_name}',
                    fontsize=16, fontweight='bold', y=0.98)
                    
        # Delivery rates (top left)
        ax1 = fig.add_subplot(gs[0, 0])
        self.plot_delivery_rates(ax=ax1, show=False)
        
        # Latency comparison (top middle)
        ax2 = fig.add_subplot(gs[0, 1])
        self.plot_latency_comparison(ax=ax2, show=False)
        
        # Throughput (top right)
        ax3 = fig.add_subplot(gs[0, 2])
        self.plot_throughput(ax=ax3, show=False)
        
        # Latency distribution (middle left)
        ax4 = fig.add_subplot(gs[1, 0])
        self.plot_latency_distribution(ax=ax4, show=False)
        
        # Attack impact (middle center)
        ax5 = fig.add_subplot(gs[1, 1])
        self.plot_attack_impact(ax=ax5, show=False)
        
        # Mitigation effectiveness (middle right)
        ax6 = fig.add_subplot(gs[1, 2])
        self.plot_mitigation_effectiveness(ax=ax6, show=False)
        
        # Time series (bottom, full width)
        ax7 = fig.add_subplot(gs[2, :])
        self.plot_time_series(ax=ax7, show=False)
        
        # Add timestamp
        fig.text(0.99, 0.01, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                ha='right', va='bottom', fontsize=8, color='gray')
                
        if filepath:
            plt.savefig(filepath, dpi=150, bbox_inches='tight',
                       facecolor='white', edgecolor='none')
            print(f"Dashboard saved to: {filepath}")
            
        if show:
            plt.show()
            
        return fig
        
    def save_all_plots(self, output_dir: str):
        """
        Save all individual plots to a directory
        
        Args:
            output_dir: Directory to save plots
        """
        os.makedirs(output_dir, exist_ok=True)
        
        plots = [
            ('delivery_rates.png', self.plot_delivery_rates),
            ('latency_comparison.png', self.plot_latency_comparison),
            ('latency_distribution.png', self.plot_latency_distribution),
            ('throughput.png', self.plot_throughput),
            ('attack_impact.png', self.plot_attack_impact),
            ('mitigation_effectiveness.png', self.plot_mitigation_effectiveness),
            ('time_series.png', self.plot_time_series),
        ]
        
        for filename, plot_func in plots:
            fig = plot_func(show=False)
            filepath = os.path.join(output_dir, filename)
            fig.savefig(filepath, dpi=150, bbox_inches='tight',
                       facecolor='white', edgecolor='none')
            plt.close(fig)
            print(f"Saved: {filepath}")
            
        # Also save dashboard
        self.create_dashboard(
            filepath=os.path.join(output_dir, 'dashboard.png'),
            show=False
        )
        plt.close('all')


if __name__ == "__main__":
    # Demo with synthetic data
    from metrics.collector import MetricsCollector
    import time
    import random
    
    # Generate test data
    collector = MetricsCollector("visualization_demo")
    
    # Baseline
    collector.start_phase(TestPhase.BASELINE)
    for _ in range(100):
        msg_id = collector.record_send()
        time.sleep(random.uniform(0.008, 0.012))
        collector.record_receive(msg_id)
    collector.end_phase()
    
    # Attack
    collector.start_phase(TestPhase.ATTACK)
    for i in range(100):
        intercepted = random.random() < 0.25
        msg_id = collector.record_send(intercepted=intercepted)
        time.sleep(random.uniform(0.015, 0.035))
        if random.random() > 0.15:
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Mitigated
    collector.start_phase(TestPhase.MITIGATED)
    for _ in range(100):
        msg_id = collector.record_send()
        time.sleep(random.uniform(0.010, 0.015))
        if random.random() > 0.03:
            collector.record_receive(msg_id)
    collector.end_phase()
    
    # Create visualizer and dashboard
    visualizer = MetricsVisualizer(collector)
    visualizer.create_dashboard()
