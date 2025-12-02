"""
Configuration settings for the ARP Poisoning Testbed.
"""

import os
import platform

# =============================================================================
# Platform Detection
# =============================================================================
PLATFORM = platform.system().lower()
IS_WINDOWS = PLATFORM == "windows"
IS_LINUX = PLATFORM == "linux"
IS_MACOS = PLATFORM == "darwin"

# =============================================================================
# Network Settings
# =============================================================================
# Default network interface (will be auto-detected if None)
INTERFACE = None

# Broadcast MAC address
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# ARP operation codes
ARP_REQUEST = 1
ARP_REPLY = 2

# Ethernet types
ETH_TYPE_ARP = 0x0806
ETH_TYPE_IPV4 = 0x0800

# =============================================================================
# ARP Chat Settings
# =============================================================================
# Use experimental Ethernet type for chat (IEEE 802 Local Experimental)
CHAT_ETHER_TYPES = {
    "experimental1": 0x88b5,
    "experimental2": 0x88b6,
    "ipv4": 0x0800,  # Fallback for some networks
}
DEFAULT_CHAT_ETHER_TYPE = "experimental1"

# Message packet structure
MESSAGE_PREFIX = b"ARPCHAT"  # Prefix to identify our packets
MESSAGE_VERSION = 1

# Packet types
PACKET_TYPE_MESSAGE = 0
PACKET_TYPE_PRESENCE_REQ = 1
PACKET_TYPE_PRESENCE = 2
PACKET_TYPE_DISCONNECT = 3

# Unique ID size for sessions
ID_SIZE = 8

# Presence/heartbeat settings
HEARTBEAT_INTERVAL = 3  # Seconds between heartbeats
INACTIVE_TIMEOUT = 6    # Seconds before marking user as inactive
OFFLINE_TIMEOUT = 12    # Seconds before marking user as offline

# Maximum message length (considering ARP packet size limits)
MAX_MESSAGE_LENGTH = 200

# =============================================================================
# Attack Settings
# =============================================================================
# Interval between spoofed ARP packets (seconds)
SPOOF_INTERVAL = 2.0

# Attack modes
ATTACK_MODE_REQUEST = "request"
ATTACK_MODE_REPLY = "reply"
DEFAULT_ATTACK_MODE = ATTACK_MODE_REPLY

# Enable/disable packet forwarding during MITM
FORWARD_PACKETS = True

# Attack intensity levels
ATTACK_INTENSITY_LOW = 1      # 1 packet every 3 seconds
ATTACK_INTENSITY_MEDIUM = 2   # 1 packet every 2 seconds
ATTACK_INTENSITY_HIGH = 3     # 1 packet every 1 second
ATTACK_INTENSITY_AGGRESSIVE = 4  # 2+ packets per second

# =============================================================================
# Defense Settings
# =============================================================================
# Detection thresholds
MAC_CHANGE_THRESHOLD = 3       # Number of MAC changes before alert
DETECTION_WINDOW = 60          # Window in seconds for threshold
GRATUITOUS_ARP_THRESHOLD = 10  # Gratuitous ARPs before alert

# Validation settings
TCP_SYN_PORT = 31337           # Port for TCP SYN validation
VALIDATION_TIMEOUT = 2.0       # Seconds to wait for RST/ACK

# Static ARP settings
STATIC_ARP_REFRESH = 300       # Seconds between static entry refresh

# =============================================================================
# Metrics Settings
# =============================================================================
# Sampling rate for metrics collection
SAMPLE_RATE = 0.1  # Seconds between samples

# Metrics to collect
METRICS_ENABLED = {
    "delivery_rate": True,
    "latency": True,
    "packet_loss": True,
    "throughput": True,
    "jitter": True,
    "abort_retry_rate": True,
    "recovery_time": True,
}

# Metric aggregation intervals
AGGREGATION_INTERVAL = 1.0  # Seconds

# =============================================================================
# Visualization Settings
# =============================================================================
# Graph output format
GRAPH_FORMAT = "png"
GRAPH_DPI = 150

# Color scheme for states
COLOR_NORMAL = "#2ecc71"     # Green
COLOR_ATTACK = "#e74c3c"     # Red
COLOR_MITIGATED = "#3498db"  # Blue

# Graph sizes
FIGURE_SIZE_SMALL = (8, 6)
FIGURE_SIZE_MEDIUM = (12, 8)
FIGURE_SIZE_LARGE = (16, 10)

# =============================================================================
# Logging Settings
# =============================================================================
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Log directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data", "logs")
GRAPH_DIR = os.path.join(BASE_DIR, "data", "graphs")

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR, exist_ok=True)

# =============================================================================
# Demo Settings
# =============================================================================
# Default scenario durations (seconds)
DEMO_DURATION_NORMAL = 30
DEMO_DURATION_ATTACK = 30
DEMO_DURATION_MITIGATED = 30

# Delay between scenarios
SCENARIO_TRANSITION_DELAY = 5

# =============================================================================
# Encryption Settings
# =============================================================================
# Enable message encryption
ENCRYPTION_ENABLED = False  # Set to True for encrypted chat mode

# Key derivation settings
KEY_DERIVATION_ITERATIONS = 100000
SALT_LENGTH = 16

# =============================================================================
# Safety Settings
# =============================================================================
# Require explicit confirmation for attacks
REQUIRE_ATTACK_CONFIRMATION = True

# Restrict to local network only
RESTRICT_TO_LOCAL = True

# Maximum attack duration (seconds, 0 = unlimited)
MAX_ATTACK_DURATION = 300

# Auto-restore ARP tables on exit
AUTO_RESTORE_ARP = True


# =============================================================================
# Helper Functions
# =============================================================================

def get_platform() -> str:
    """
    Get the current platform name.
    
    Returns:
        Platform name: 'linux', 'darwin', or 'windows'.
    """
    return PLATFORM


def get_default_interface() -> str:
    """
    Get the default network interface for the current platform.
    
    Returns:
        Interface name as a string, or None if cannot be determined.
    """
    if INTERFACE:
        return INTERFACE
    
    # Try to auto-detect based on platform
    if IS_LINUX:
        import subprocess
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                   capture_output=True, text=True)
            parts = result.stdout.split()
            if 'dev' in parts:
                idx = parts.index('dev')
                return parts[idx + 1]
        except Exception:
            pass
        return 'eth0'
    elif IS_MACOS:
        import subprocess
        try:
            result = subprocess.run(['route', '-n', 'get', 'default'],
                                   capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    return line.split(':')[1].strip()
        except Exception:
            pass
        return 'en0'
    elif IS_WINDOWS:
        return 'Ethernet'
    
    return None


class ARPConfig:
    """
    Configuration class for ARP operations.
    
    This class provides a convenient interface to access ARP-related settings.
    """
    
    def __init__(
        self,
        interface: str = None,
        spoof_interval: float = SPOOF_INTERVAL,
        attack_mode: str = DEFAULT_ATTACK_MODE,
        forward_packets: bool = FORWARD_PACKETS
    ):
        """
        Initialize ARP configuration.
        
        Args:
            interface: Network interface to use (auto-detected if None).
            spoof_interval: Interval between spoofed ARP packets.
            attack_mode: Attack mode ('request' or 'reply').
            forward_packets: Whether to forward packets during MITM.
        """
        self.interface = interface or get_default_interface()
        self.spoof_interval = spoof_interval
        self.attack_mode = attack_mode
        self.forward_packets = forward_packets
    
    @property
    def is_valid(self) -> bool:
        """Check if the configuration is valid."""
        return self.interface is not None
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            'interface': self.interface,
            'spoof_interval': self.spoof_interval,
            'attack_mode': self.attack_mode,
            'forward_packets': self.forward_packets
        }
