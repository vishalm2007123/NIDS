# NetWatch — Network Intrusion Monitor v2.0

A real-time network packet sniffer with a live web dashboard.

---

## Project Structure

```
packet_sniffer.py   ← Core sniffer engine (fixed & improved)
main.py             ← CLI entry point
web_server.py       ← Flask server — bridges sniffer → browser
dashboard.html      ← Web UI (served by Flask)
requirements.txt    ← Python dependencies
```

---

## Bug Fixes & Improvements

| Issue | Fix |
|---|---|
| Protocol shown as number (e.g., `6`) | Added `PROTOCOL_MAP` → shows `TCP`, `UDP`, etc. |
| No error handling | `try/except` for PermissionError, OSError, parse errors |
| `sniff()` runs forever, no stop | Added `stop_filter` + `threading.Event` for graceful stop |
| No packet count / timeout | `count` and `timeout` args added |
| Protocol `17` instead of `UDP` | Human-readable name lookup |
| TCP flags not decoded | Full flag parsing: SYN, ACK, FIN, RST, PSH, URG |
| ARP packets ignored | ARP layer handled |
| Data only printed, lost | JSON logging to `packet_log.json` |
| No interface selection | `--interface` CLI arg |
| Duplicate `main.py` files | Removed duplicate, single clean entry point |
| No graceful Ctrl+C | `signal.SIGINT` / `SIGTERM` handlers |

---

## Installation

```bash
pip install flask scapy
```

---

## Usage

### Option 1 — CLI (terminal output only)

```bash
# Basic (requires root/admin)
sudo python main.py

# With options
sudo python main.py --interface eth0 --filter "tcp port 80" --count 100 --timeout 30
```

**CLI Arguments:**

| Argument | Short | Description |
|---|---|---|
| `--interface` | `-i` | Network interface (e.g., `eth0`, `wlan0`) |
| `--filter` | `-f` | BPF filter (e.g., `tcp port 80`) |
| `--count` | `-c` | Max packets (0 = unlimited) |
| `--timeout` | `-t` | Stop after N seconds |

### Option 2 — Web Dashboard (recommended)

```bash
# Make sure dashboard.html is in the same folder as web_server.py
sudo python web_server.py
```

Then open your browser at: **http://localhost:5000**

**Dashboard features:**
- ▶ Start / ■ Stop capture from browser
- Live packet feed table (auto-scrolling, newest first)
- Protocol breakdown: TCP / UDP / ICMP / ARP / Other
- Animated donut chart + bar charts
- Top destination ports panel (with port name labels)
- Filter by IP address or protocol
- Packet stats counter

---

## Notes

- **Root/sudo required** — packet sniffing needs raw socket access.
- Packets are logged to `packet_log.json` (one JSON object per line).
- The web server uses Server-Sent Events (SSE) for real-time streaming — no WebSocket dependency needed.
