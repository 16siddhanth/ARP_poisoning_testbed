# ARP Poisoning Testbed: Attack, Defense, and Metrics

A comprehensive, cross-platform testbed demonstrating ARP-based messaging, ARP poisoning attacks, and layered defense mechanisms with quantitative metrics and visualization.


## Project Overview

This project demonstrates how address-resolution-layer (ARP) messaging can be disrupted by ARP poisoning and how layered defenses restore secure communications. It includes:

- **ARP Chat**: Real-time messaging using ARP packets
- **ARP Poisoning Attacks**: Controlled attacks to disrupt/intercept messages
- **Layered Defenses**: Static ARP entries, detection daemons, encrypted transport
- **Metrics & Visualization**: Quantitative analysis with matplotlib graphs
- **Virtual Network**: Single-machine testing without physical network hardware

## Features

### Attack Demonstration
- ARP spoofing via requests and replies
- Bidirectional man-in-the-middle attacks
- Controlled mode to avoid collateral damage
- Multiple attack tool implementations
- Attack tools comparison benchmark

### Defense Mechanisms
- Static ARP entries for critical hosts
- ARP packet inspection/detection daemon
- MAC discrepancy analysis (as per ICITSD 2021 paper)
- Encrypted transport for message payloads (Fernet encryption)
- Simulated switch-level inspection (Dynamic ARP Inspection)

### Metrics Collection
- Message delivery rate
- End-to-end latency
- Packet loss percentage
- Throughput measurement
- Abort/retry rates
- Time-to-recovery after mitigation
- Detection precision/recall/F1 score

### Visualization
- Time-series graphs
- Bar chart comparisons
- Heatmap analysis
- Normal vs Attack vs Mitigated state comparisons

## Project Structure

```
san/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── demo.py                      # Quick demo script
├── config/
│   ├── __init__.py
│   └── settings.py              # Configuration and platform detection
├── core/
│   ├── __init__.py
│   ├── arp_chat.py              # ARP-based chat implementation
│   ├── arp_packet.py            # ARP packet crafting with Scapy
│   ├── network_utils.py         # Network interface utilities
│   ├── encryption.py            # Fernet message encryption
│   └── virtual_network.py       # Virtual network for single-machine testing
├── attacks/
│   ├── __init__.py
│   ├── arp_spoofer.py           # ARP spoofing/poisoning attack
│   ├── mitm_proxy.py            # Man-in-the-middle packet proxy
│   └── tool_comparison.py       # Attack tools comparison benchmark
├── defenses/
│   ├── __init__.py
│   ├── static_arp.py            # Static ARP entry management
│   ├── arp_detector.py          # TCP SYN validation detection
│   ├── arp_inspector.py         # Dynamic ARP inspection daemon
│   ├── mac_discrepancy_detector.py  # MAC analysis (paper method)
│   └── dai_simulator.py         # Simulated switch-level DAI
├── metrics/
│   ├── __init__.py
│   ├── collector.py             # Metrics collection engine
│   └── analyzer.py              # Statistical analysis utilities
├── utils/
│   ├── __init__.py
│   └── visualizer.py            # Matplotlib visualization
├── orchestration/
│   ├── __init__.py
│   └── orchestrator.py          # Main experiment orchestrator
└── results/                     # Output directory for results
```

## Requirements

- Python 3.8+
- Root/Administrator privileges (for raw socket access)
- Network interface with ARP support

### Platform-Specific Requirements

**Linux:**
- libpcap-dev: `sudo apt-get install libpcap-dev`

**macOS:**
- libpcap (pre-installed)

**Windows:**
- Npcap: https://npcap.com/#download (Install with "WinPcap API-compatible Mode")

## Installation

```bash
# Clone or navigate to the project directory
cd san

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# On Linux, grant network capabilities
sudo setcap CAP_NET_RAW+ep $(which python3)
```

## Quick Start

### 1. List Available Interfaces
```bash
python demo.py --list-interfaces
```

### 2. Run Quick Demo
```bash
sudo python demo.py -i en0 -t 192.168.1.100
```

### 3. Run Metrics Demo (No Root Required)
```bash
python demo.py --metrics-only
```

### 4. Run Full Experiment
```bash
sudo python -m orchestration.orchestrator -i en0 -t 192.168.1.100
```

## Individual Components

**ARP Chat Module:**
```python
from core.arp_chat import ARPChat

chat = ARPChat(interface="en0", nickname="Alice")
chat.start()
chat.send_message("Hello via ARP!")
chat.stop()
```

**ARP Spoofer (Attack):**
```python
from attacks.arp_spoofer import ARPSpoofer

spoofer = ARPSpoofer(
    interface="en0",
    target_ip="192.168.1.100",
    gateway_ip="192.168.1.1"
)
spoofer.start()
# ... attack runs ...
spoofer.stop(restore=True)
```

**ARP Detector (Defense):**
```python
from defenses.arp_detector import ARPDetector

def alert_handler(alert):
    print(f"Alert: {alert.description}")

detector = ARPDetector(interface="en0", alert_callback=alert_handler)
detector.start()
```

**MAC Discrepancy Detector (Paper Method):**
```python
from defenses.mac_discrepancy_detector import MACDiscrepancyDetector

# As per Majumdar et al. (2021) - analyzes real MAC vs response MAC
detector = MACDiscrepancyDetector(interface="en0")
detector.add_trusted_binding("192.168.1.1", "aa:bb:cc:dd:ee:ff", is_gateway=True)
detector.start()

# Check for attacks
discrepancies = detector.get_high_confidence_attacks()
```

**Static ARP Protection:**
```python
from defenses.static_arp import StaticARPManager

manager = StaticARPManager(interface="en0")
manager.protect_gateway()  # Add static entry for gateway
```

**Virtual Network Testing (Single Machine):**
```python
from core.virtual_network import VirtualNetwork, VirtualARPSpoofer, VirtualARPDetector

# Create simulated network environment
network = VirtualNetwork()

# Set up detector
detector = VirtualARPDetector(network, "veth0")
detector.add_trusted_binding("10.0.0.1", "aa:bb:cc:dd:00:ff")  # Gateway

# Simulate attack
spoofer = VirtualARPSpoofer(network, "veth1")
network.send_arp_reply("veth1", "10.0.0.2", spoofed_ip="10.0.0.1")

# Detect attack
anomalies = detector.check_arp_table()
```

**Attack Tools Comparison:**
```python
from attacks.tool_comparison import AttackToolBenchmark

benchmark = AttackToolBenchmark()
benchmark.add_default_tools()
results = benchmark.run_comparison(
    victim_ip="192.168.1.10",
    gateway_ip="192.168.1.1"
)
benchmark.print_comparison()
```

## Demo Scenarios

The orchestrator runs through three phases automatically:

```bash
# Full experiment with all phases
sudo python -m orchestration.orchestrator -i en0 -t 192.168.1.100

# Custom durations
sudo python -m orchestration.orchestrator -i en0 -t 192.168.1.100 \
    --baseline-duration 60 \
    --attack-duration 60 \
    --mitigation-duration 60
```

### Phase 1: Baseline
- Normal ARP chat operation
- Measures baseline delivery rate and latency

### Phase 2: Under Attack
- ARP poisoning attack active
- Measures impact on delivery and interception rate

### Phase 3: Mitigated
- Defenses enabled (static ARP, detection, encryption)
- Attack still running but mitigated
- Measures recovery and mitigation effectiveness

### Full Comparison (Generates Graphs)
```bash
sudo python -m scripts.run_demo --full-comparison --interface eth0
```

### Virtual Network Demo (No Root Required)
```bash
python -c "from core.virtual_network import run_virtual_network_demo; run_virtual_network_demo()"
```

### DAI Simulation Demo
```bash
python -c "from defenses.dai_simulator import run_dai_demo; run_dai_demo()"
```

## Metrics and Visualization

After running scenarios, generate visualizations:

```bash
python -m visualization.graphs --input data/logs/ --output data/graphs/
```

Or use the Jupyter notebook for interactive analysis:

```bash
jupyter notebook notebooks/analysis.ipynb
```

This produces:
- `delivery_rate_comparison.png` - Message delivery rates across scenarios
- `latency_timeseries.png` - Latency over time
- `packet_loss_heatmap.png` - Packet loss distribution
- `throughput_comparison.png` - Throughput analysis
- `recovery_time.png` - Time to recovery after mitigation
- `attack_tools_comparison.png` - Comparison of attack tools
- `retry_abort_analysis.png` - Retry and abort metrics

## Configuration

Edit `config/settings.py` to customize:

```python
# Network settings
INTERFACE = "eth0"  # Default network interface
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# ARP Chat settings
CHAT_ETHER_TYPE = 0x88b5  # Experimental Ethernet type
MESSAGE_PREFIX = b"ARPCHAT"

# Attack settings
SPOOF_INTERVAL = 2  # Seconds between spoof packets

# Defense settings
DETECTION_THRESHOLD = 5  # MAC changes before alert
HEARTBEAT_INTERVAL = 3  # Seconds

# Metrics settings
SAMPLE_RATE = 0.1  # Seconds between samples
```

## Research Reference

This project implements techniques from:

> **ARP Poisoning Detection and Prevention using Scapy**
> Aayush Majumdar, Shruti Raj, and T. Subbulakshmi
> Journal of Physics: Conference Series, Volume 1911 (ICITSD 2021)
> [DOI: 10.1088/1742-6596/1911/1/012022](https://doi.org/10.1088/1742-6596/1911/1/012022)

Key contributions implemented:
- ARP spoofing attack tool using Python/Scapy
- Detection algorithm based on MAC address discrepancy analysis
- Prevention via static ARP table entries

## Safety Notice

⚠️ **WARNING**: This tool is for educational and authorized testing purposes only.

- Only use on networks you own or have explicit permission to test
- ARP spoofing can disrupt network communications
- The attack components are designed for controlled environments
- Misuse may be illegal in your jurisdiction

## Credits

This project combines concepts from:
- [kognise/arpchat](https://github.com/kognise/arpchat) - ARP-based chat concept
- [byt3bl33d3r/arpspoof](https://github.com/byt3bl33d3r/arpspoof) - Python ARP spoofing
- [rnehra01/arp-validator](https://github.com/rnehra01/arp-validator) - ARP detection techniques
- [alandau/arpspoof](https://github.com/alandau/arpspoof) - Windows ARP spoofing concepts

**Reference Paper:** Based on "ARP Poisoning Detection and Prevention using Scapy" (ICITSD 2021)
by Aayush Majumdar, Shruti Raj, and T. Subbulakshmi
([DOI: 10.1088/1742-6596/1911/1/012022](https://doi.org/10.1088/1742-6596/1911/1/012022))

## License

MIT License - See LICENSE file for details.
