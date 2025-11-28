"""
ARP-based Chat Implementation.

This module provides a chat system that transmits messages using ARP packets,
inspired by the kognise/arpchat project.
"""

import os
import sys
import time
import threading
import queue
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

try:
    from scapy.all import Ether, ARP, Raw, sendp, sniff, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from config import settings
from .network_utils import get_interface_info, get_mac_address
from .arp_packet import ARPPacketBuilder
from .encryption import (
    MessageEncryption, 
    compress_message, 
    decompress_message,
    generate_session_id
)


@dataclass
class ChatMessage:
    """Represents a chat message."""
    message_id: bytes
    sender_id: bytes
    username: str
    content: str
    timestamp: datetime
    is_own: bool = False
    delivered: bool = False


@dataclass
class Presence:
    """Represents a user's presence information."""
    user_id: bytes
    username: str
    last_seen: datetime
    is_active: bool = True


class ARPChat:
    """
    ARP-based chat implementation.
    
    Sends and receives messages using ARP packets on the local network.
    """
    
    def __init__(self, interface: str, username: str,
                 encryption: Optional[MessageEncryption] = None,
                 on_message: Optional[Callable[[ChatMessage], None]] = None,
                 on_presence: Optional[Callable[[Presence], None]] = None):
        """
        Initialize the ARP chat.
        
        Args:
            interface: Network interface to use.
            username: Display name for this user.
            encryption: Optional encryption handler.
            on_message: Callback for received messages.
            on_presence: Callback for presence updates.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for ARP chat")
        
        self.interface = interface
        self.username = username
        self.encryption = encryption
        self.on_message = on_message
        self.on_presence = on_presence
        
        # Get interface info
        iface_info = get_interface_info(interface)
        if not iface_info or not iface_info.mac:
            raise ValueError(f"Cannot get MAC address for interface {interface}")
        
        self.mac_address = iface_info.mac
        self.ip_address = iface_info.ip or "0.0.0.0"
        
        # Generate unique session ID
        self.session_id = generate_session_id()
        
        # Packet builder
        self.packet_builder = ARPPacketBuilder(self.mac_address, self.ip_address)
        
        # Message tracking
        self.message_queue: queue.Queue = queue.Queue()
        self.received_ids: Set[bytes] = set()  # Deduplication
        self.recent_ids: List[bytes] = []  # Ring buffer for recent IDs
        self.max_recent = 100
        
        # Presence tracking
        self.online_users: Dict[bytes, Presence] = {}
        
        # Threading
        self._running = False
        self._recv_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        
        # Ether type
        self.ether_type = settings.CHAT_ETHER_TYPES[settings.DEFAULT_CHAT_ETHER_TYPE]
        
        # Metrics
        self.messages_sent = 0
        self.messages_received = 0
        self.packets_dropped = 0
    
    def start(self):
        """Start the chat service."""
        if self._running:
            return
        
        self._running = True
        
        # Start receiver thread
        self._recv_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._recv_thread.start()
        
        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        
        # Send initial presence request
        time.sleep(0.5)  # Brief delay to let receiver start
        self._send_presence_request()
    
    def stop(self):
        """Stop the chat service."""
        if not self._running:
            return
        
        # Send disconnect notification
        self._send_disconnect()
        
        self._running = False
        
        # Wait for threads
        if self._recv_thread:
            self._recv_thread.join(timeout=2)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
    
    def send_message(self, content: str) -> bool:
        """
        Send a chat message.
        
        Args:
            content: Message content.
        
        Returns:
            True if message was sent successfully.
        """
        if not content or len(content) > settings.MAX_MESSAGE_LENGTH:
            return False
        
        try:
            # Compress message
            compressed = compress_message(content)
            
            # Encrypt if enabled
            if self.encryption:
                payload = self.encryption.encrypt_bytes(compressed)
            else:
                payload = compressed
            
            # Build packet
            message_id = generate_session_id()
            
            # Payload format: session_id(8) + compressed_message
            full_payload = self.session_id + payload
            
            packet = self._build_chat_packet(
                settings.PACKET_TYPE_MESSAGE,
                message_id,
                full_payload
            )
            
            # Send
            sendp(packet, iface=self.interface, verbose=False)
            
            # Track
            self.messages_sent += 1
            
            # Create local message record
            msg = ChatMessage(
                message_id=message_id,
                sender_id=self.session_id,
                username=self.username,
                content=content,
                timestamp=datetime.now(),
                is_own=True,
                delivered=True
            )
            
            if self.on_message:
                self.on_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Error sending message: {e}")
            return False
    
    def _build_chat_packet(self, msg_type: int, msg_id: bytes, 
                           payload: bytes) -> 'Ether':
        """Build a chat packet using ARP format."""
        # Custom packet structure embedded in ARP
        # We use the ARP protocol address fields to carry our data
        
        header = (
            settings.MESSAGE_PREFIX +
            bytes([settings.MESSAGE_VERSION, msg_type]) +
            msg_id
        )
        
        data = header + payload
        
        # Build as Ethernet/ARP with payload
        pkt = (
            Ether(src=self.mac_address, dst=settings.BROADCAST_MAC, type=0x0806) /
            ARP(
                hwtype=1,
                ptype=self.ether_type,
                hwlen=6,
                plen=min(len(data), 255),
                op=1,
                hwsrc=self.mac_address,
                psrc=self.ip_address,
                hwdst="00:00:00:00:00:00",
                pdst="0.0.0.0"
            ) /
            Raw(load=data)
        )
        
        return pkt
    
    def _receive_loop(self):
        """Background thread for receiving packets."""
        def packet_handler(packet):
            if not self._running:
                return
            self._handle_packet(packet)
        
        try:
            # Filter for ARP packets
            sniff(
                iface=self.interface,
                filter="arp",
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except Exception as e:
            if self._running:
                print(f"Receive error: {e}")
    
    def _handle_packet(self, packet):
        """Process a received packet."""
        try:
            # Check if it's our chat packet
            if not packet.haslayer(Raw):
                return
            
            data = bytes(packet[Raw].load)
            
            # Check prefix
            if not data.startswith(settings.MESSAGE_PREFIX):
                return
            
            # Parse header
            prefix_len = len(settings.MESSAGE_PREFIX)
            if len(data) < prefix_len + 2 + settings.ID_SIZE:
                return
            
            version = data[prefix_len]
            if version != settings.MESSAGE_VERSION:
                return
            
            msg_type = data[prefix_len + 1]
            msg_id = data[prefix_len + 2:prefix_len + 2 + settings.ID_SIZE]
            payload = data[prefix_len + 2 + settings.ID_SIZE:]
            
            # Deduplication
            if msg_id in self.received_ids:
                return
            self._add_to_recent(msg_id)
            
            # Handle by type
            if msg_type == settings.PACKET_TYPE_MESSAGE:
                self._handle_message(msg_id, payload, packet)
            elif msg_type == settings.PACKET_TYPE_PRESENCE_REQ:
                self._handle_presence_request()
            elif msg_type == settings.PACKET_TYPE_PRESENCE:
                self._handle_presence(msg_id, payload)
            elif msg_type == settings.PACKET_TYPE_DISCONNECT:
                self._handle_disconnect(payload)
                
        except Exception as e:
            self.packets_dropped += 1
    
    def _handle_message(self, msg_id: bytes, payload: bytes, packet):
        """Handle a received message."""
        try:
            if len(payload) < settings.ID_SIZE:
                return
            
            sender_id = payload[:settings.ID_SIZE]
            message_data = payload[settings.ID_SIZE:]
            
            # Skip own messages
            if sender_id == self.session_id:
                return
            
            # Decrypt if enabled
            if self.encryption:
                try:
                    message_data = self.encryption.decrypt_bytes(message_data)
                except Exception:
                    return  # Decryption failed
            
            # Decompress
            content = decompress_message(message_data)
            
            # Get username from presence or use default
            username = "unknown"
            if sender_id in self.online_users:
                username = self.online_users[sender_id].username
            
            # Create message object
            msg = ChatMessage(
                message_id=msg_id,
                sender_id=sender_id,
                username=username,
                content=content,
                timestamp=datetime.now(),
                is_own=False,
                delivered=True
            )
            
            self.messages_received += 1
            
            if self.on_message:
                self.on_message(msg)
                
        except Exception as e:
            self.packets_dropped += 1
    
    def _handle_presence_request(self):
        """Handle presence request - respond with our presence."""
        self._send_presence(is_join=False)
    
    def _handle_presence(self, msg_id: bytes, payload: bytes):
        """Handle presence announcement."""
        try:
            if len(payload) < settings.ID_SIZE + 1:
                return
            
            user_id = payload[:settings.ID_SIZE]
            is_join = payload[settings.ID_SIZE] > 0
            username = payload[settings.ID_SIZE + 1:].decode('utf-8', errors='replace')
            
            # Update presence
            now = datetime.now()
            
            if user_id in self.online_users:
                old_presence = self.online_users[user_id]
                old_presence.last_seen = now
                old_presence.username = username
                old_presence.is_active = True
            else:
                presence = Presence(
                    user_id=user_id,
                    username=username,
                    last_seen=now,
                    is_active=True
                )
                self.online_users[user_id] = presence
                
                if self.on_presence:
                    self.on_presence(presence)
                    
        except Exception:
            pass
    
    def _handle_disconnect(self, payload: bytes):
        """Handle disconnect notification."""
        try:
            if len(payload) < settings.ID_SIZE:
                return
            
            user_id = payload[:settings.ID_SIZE]
            
            if user_id in self.online_users:
                presence = self.online_users[user_id]
                presence.is_active = False
                
                if self.on_presence:
                    self.on_presence(presence)
                    
        except Exception:
            pass
    
    def _send_presence(self, is_join: bool = False):
        """Send presence announcement."""
        try:
            payload = (
                self.session_id +
                bytes([1 if is_join else 0]) +
                self.username.encode('utf-8')
            )
            
            msg_id = generate_session_id()
            packet = self._build_chat_packet(
                settings.PACKET_TYPE_PRESENCE,
                msg_id,
                payload
            )
            
            sendp(packet, iface=self.interface, verbose=False)
            
        except Exception:
            pass
    
    def _send_presence_request(self):
        """Send presence request to discover other users."""
        try:
            msg_id = generate_session_id()
            packet = self._build_chat_packet(
                settings.PACKET_TYPE_PRESENCE_REQ,
                msg_id,
                b""
            )
            
            sendp(packet, iface=self.interface, verbose=False)
            
            # Also send our presence
            self._send_presence(is_join=True)
            
        except Exception:
            pass
    
    def _send_disconnect(self):
        """Send disconnect notification."""
        try:
            msg_id = generate_session_id()
            packet = self._build_chat_packet(
                settings.PACKET_TYPE_DISCONNECT,
                msg_id,
                self.session_id
            )
            
            sendp(packet, iface=self.interface, verbose=False)
            
        except Exception:
            pass
    
    def _heartbeat_loop(self):
        """Background thread for heartbeat/presence."""
        last_heartbeat = time.time()
        
        while self._running:
            time.sleep(1)
            
            now = time.time()
            
            # Send heartbeat
            if now - last_heartbeat >= settings.HEARTBEAT_INTERVAL:
                self._send_presence(is_join=False)
                last_heartbeat = now
                
                # Check for inactive users
                self._check_inactive_users()
    
    def _check_inactive_users(self):
        """Check for and remove inactive users."""
        now = datetime.now()
        
        for user_id, presence in list(self.online_users.items()):
            elapsed = (now - presence.last_seen).total_seconds()
            
            if elapsed > settings.OFFLINE_TIMEOUT:
                presence.is_active = False
                if self.on_presence:
                    self.on_presence(presence)
            elif elapsed > settings.INACTIVE_TIMEOUT:
                presence.is_active = False
    
    def _add_to_recent(self, msg_id: bytes):
        """Add message ID to recent set and ring buffer."""
        self.received_ids.add(msg_id)
        self.recent_ids.append(msg_id)
        
        # Maintain ring buffer size
        while len(self.recent_ids) > self.max_recent:
            old_id = self.recent_ids.pop(0)
            self.received_ids.discard(old_id)
    
    def get_online_users(self) -> List[Presence]:
        """Get list of online users."""
        return [p for p in self.online_users.values() if p.is_active]
    
    def get_stats(self) -> Dict:
        """Get chat statistics."""
        return {
            "messages_sent": self.messages_sent,
            "messages_received": self.messages_received,
            "packets_dropped": self.packets_dropped,
            "online_users": len(self.get_online_users()),
        }


def run_chat_cli(interface: str, username: str):
    """Run a simple CLI chat interface."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    
    console = Console()
    
    def on_message(msg: ChatMessage):
        if msg.is_own:
            style = "bold green"
            prefix = "You"
        else:
            style = "bold cyan"
            prefix = msg.username
        
        timestamp = msg.timestamp.strftime("%H:%M:%S")
        text = Text()
        text.append(f"[{timestamp}] ", style="dim")
        text.append(f"{prefix}: ", style=style)
        text.append(msg.content)
        console.print(text)
    
    def on_presence(presence: Presence):
        if presence.is_active:
            console.print(f"[dim]> {presence.username} is online[/dim]")
        else:
            console.print(f"[dim]> {presence.username} went offline[/dim]")
    
    # Create chat
    chat = ARPChat(
        interface=interface,
        username=username,
        on_message=on_message,
        on_presence=on_presence
    )
    
    console.print(Panel(
        f"[bold]ARP Chat[/bold]\n"
        f"Interface: {interface}\n"
        f"Username: {username}\n"
        f"Type messages and press Enter. Ctrl+C to quit.",
        title="Welcome"
    ))
    
    # Start chat
    chat.start()
    
    try:
        while True:
            try:
                message = input()
                if message.strip():
                    if message == "/quit":
                        break
                    elif message == "/users":
                        users = chat.get_online_users()
                        console.print(f"[dim]Online users: {', '.join(u.username for u in users)}[/dim]")
                    elif message == "/stats":
                        stats = chat.get_stats()
                        console.print(f"[dim]Stats: {stats}[/dim]")
                    else:
                        chat.send_message(message)
            except EOFError:
                break
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down...[/yellow]")
    finally:
        chat.stop()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ARP Chat")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-u", "--username", default=None, help="Username")
    
    args = parser.parse_args()
    
    username = args.username or os.environ.get("USER", "anonymous")
    
    run_chat_cli(args.interface, username)
