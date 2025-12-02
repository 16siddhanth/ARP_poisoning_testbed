# ARP Poisoning Demo - Professor Presentation

## Quick Setup

**Requirements on all 3 laptops:**
```bash
pip install scapy netifaces matplotlib
```

**On Windows:** Also install [Npcap](https://npcap.com)

---

## Demo Flow

### STEP 1: ARP Chat (Laptops A & B)

Show normal communication working between two laptops.

**Laptop A (e.g., 192.168.1.10) - Sender:**
```bash
sudo python scripts/1_chat_sender.py -i en0 -t 192.168.1.20
```

**Laptop B (e.g., 192.168.1.20) - Receiver:**
```bash
sudo python scripts/1_chat_receiver.py -i en0
```
 python -c "from scapy.all import get_if_list, conf; print('\n'.join(get_if_list())); print(f'\nDefault: {conf.iface}')"
 copy default

python scripts/1_chat_receiver.py -i "\Device\NPF_{744EB904-71EE-46B0-A10D-0E3505BE2D2C}" 

Type messages on Laptop A → They appear on Laptop B ✓

---

### STEP 2: ARP Attack (Laptop C)

Launch attack from third laptop to intercept traffic.

**Laptop C (Attacker):**
```bash
sudo python scripts/2_attacker.py -i en0 -v 192.168.1.10 -g 192.168.1.20
```

**What happens:**
- Attacker sends fake ARP replies every 2 seconds
- Laptop A thinks Attacker is Laptop B
- Laptop B thinks Attacker is Laptop A
- Messages get intercepted/lost ✗

**To show interception:** Try sending messages again - they won't arrive properly.

---

### STEP 3: Enable Defense (Laptop A or B)

Stop the attack with static ARP protection.

**On Laptop A (or B):**
```bash
# First, get the real MAC address of the other laptop
# On Laptop B, run: ifconfig | grep ether

# Then protect with static ARP
sudo python scripts/3_defender.py -i en0 --protect 192.168.1.20 --mac aa:bb:cc:dd:ee:ff
```

**What happens:**
- Static ARP entry added (cannot be overwritten)
- Attack is detected and blocked
- Messages work again ✓

---

### STEP 4: Generate Report (Any Laptop)

Generate graphs and statistics.

```bash
python scripts/4_generate_report.py
```

**Output:**
- `data/graphs/summary_dashboard.png` - Key metrics comparison
- `data/graphs/delivery_rate_comparison.png`
- `data/graphs/latency_comparison.png`
- `data/graphs/interception_rate.png`
- `data/report.txt` - Full text report

---

## Quick Reference Card

| Laptop | Role | IP Example | Command |
|--------|------|------------|---------|
| A | Chat Sender | 192.168.1.10 | `sudo python scripts/1_chat_sender.py -i en0 -t 192.168.1.20` |
| B | Chat Receiver | 192.168.1.20 | `sudo python scripts/1_chat_receiver.py -i en0` |
| C | Attacker | 192.168.1.30 | `sudo python scripts/2_attacker.py -i en0 -v 192.168.1.10 -g 192.168.1.20` |
| A/B | Defender | - | `sudo python scripts/3_defender.py -i en0 --protect <other_ip> --mac <other_mac>` |

---

## Find Your Interface & IP

**macOS:**
```bash
ifconfig en0 | grep "inet "    # IP
ifconfig en0 | grep "ether"    # MAC
```

**Linux:**
```bash
ip addr show eth0
```

**Windows (PowerShell):**
```powershell
ipconfig
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Permission denied" | Use `sudo` |
| "Cannot resolve MAC" | Check if target is reachable (`ping`) |
| "Interface not found" | Run `ifconfig` to find correct name |
| Messages not arriving | Check both on same network, same subnet |

---

## Presentation Talking Points

1. **Phase 1 (Chat):** "This is normal Layer 2 communication using ARP protocol"

2. **Phase 2 (Attack):** "The attacker sends fake ARP replies, making victims believe the attacker's MAC is the legitimate destination"

3. **Phase 3 (Defense):** "Static ARP entries cannot be overwritten by network traffic, blocking the attack"

4. **Phase 4 (Report):** "We see delivery dropped from 98% to 65% during attack, then recovered to 97% with defenses"
