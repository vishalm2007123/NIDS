from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
import json
import time
import logging
import threading
from datetime import datetime
import ddos_guard
import db

logging.basicConfig(
    filename="packet_log.json",
    level=logging.INFO,
    format="%(message)s"
)

PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

_stop_event = threading.Event()
_packet_callback = None 
_packet_count = 0
_lock = threading.Lock()


def get_protocol_name(proto_num: int) -> str:
    """Convert protocol number to human-readable name."""
    return PROTOCOL_MAP.get(proto_num, f"UNKNOWN({proto_num})")


def process_packet(packet) -> dict | None:
    """
    Parse a raw packet and return a structured dict.
    Handles IP, TCP, UDP, ICMP, ARP layers.
    Returns None if packet is not relevant.
    """
    global _packet_count

    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "protocol": "UNKNOWN",
        "src_port": "N/A",
        "dst_port": "N/A",
        "length": len(packet),
        "flags": "N/A",
        "summary": packet.summary(),
    }

    try:
        if packet.haslayer(ARP):
            arp = packet[ARP]
            packet_info["protocol"] = "ARP"
            packet_info["src_ip"] = arp.psrc
            packet_info["dst_ip"] = arp.pdst
            packet_info["flags"] = "REQUEST" if arp.op == 1 else "REPLY"

        elif packet.haslayer(IP):
            ip = packet[IP]
            packet_info["src_ip"] = ip.src
            packet_info["dst_ip"] = ip.dst
            packet_info["protocol"] = get_protocol_name(ip.proto)

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                packet_info["src_port"] = tcp.sport
                packet_info["dst_port"] = tcp.dport
                flag_names = []
                if tcp.flags.S: flag_names.append("SYN")
                if tcp.flags.A: flag_names.append("ACK")
                if tcp.flags.F: flag_names.append("FIN")
                if tcp.flags.R: flag_names.append("RST")
                if tcp.flags.P: flag_names.append("PSH")
                if tcp.flags.U: flag_names.append("URG")
                packet_info["flags"] = "|".join(flag_names) if flag_names else "NONE"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                packet_info["src_port"] = udp.sport
                packet_info["dst_port"] = udp.dport

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                packet_info["flags"] = f"type={icmp.type} code={icmp.code}"

        else:
            return None  
      
        with _lock:
            _packet_count += 1

        
        ddos_guard.record_packet(packet_info["src_ip"])

        threading.Thread(target=db.save_packet, args=(packet_info,), daemon=True).start()

        
        logging.info(json.dumps(packet_info))

        
        print(
            f"[{packet_info['timestamp']}] "
            f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
            f"{packet_info['dst_ip']}:{packet_info['dst_port']} | "
            f"Proto: {packet_info['protocol']} | "
            f"Flags: {packet_info['flags']} | "
            f"Len: {packet_info['length']}"
        )

      
        if _packet_callback:
            _packet_callback(packet_info)

        return packet_info

    except Exception as e:
        print(f"[ERROR] Failed to process packet: {e}")
        return None


def register_callback(fn):
    """Register a callback function to receive parsed packet dicts."""
    global _packet_callback
    _packet_callback = fn


def get_packet_count() -> int:
    """Return total packets captured so far."""
    with _lock:
        return _packet_count


def stop_sniffing():
    """Signal the sniffer to stop."""
    _stop_event.set()
    print("\n[INFO] Stop signal sent.")


def start_sniffing(
    interface: str = None,
    packet_filter: str = "",
    count: int = 0,
    timeout: int = None,
):
    """
    Start packet capture.

    Args:
        interface: Network interface name (e.g., 'eth0', 'wlan0').
                   If None, Scapy picks the default.
        packet_filter: BPF filter string (e.g., 'tcp port 80').
        count: Max packets to capture. 0 = unlimited.
        timeout: Stop after N seconds. None = no timeout.
    """
    global _packet_count
    _packet_count = 0
    _stop_event.clear()

    print(f"[INFO] Starting packet capture...")
    print(f"       Interface : {interface or 'default'}")
    print(f"       Filter    : {packet_filter or 'none'}")
    print(f"       Count     : {count or 'unlimited'}")
    print(f"       Timeout   : {timeout or 'none'} seconds\n")

    try:
        sniff(
            iface=interface,
            filter=packet_filter,
            prn=process_packet,
            store=False,
            count=count,
            timeout=timeout,
            stop_filter=lambda _: _stop_event.is_set(),
        )
    except PermissionError:
        print("[ERROR] Permission denied. Run as root/administrator (sudo).")
    except OSError as e:
        print(f"[ERROR] Interface error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error during sniffing: {e}")
    finally:
        print(f"\n[INFO] Capture stopped. Total packets: {get_packet_count()}")
