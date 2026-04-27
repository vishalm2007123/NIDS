"""
Network Intrusion Monitor — CLI Entry Point
Usage:
    sudo python main.py
    sudo python main.py --interface eth0 --filter "tcp port 80" --count 100 --timeout 30
"""

import argparse
import signal
import sys
from packet_sniffer import start_sniffing, stop_sniffing, get_packet_count


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Intrusion Monitor — Packet Sniffer"
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g., eth0, wlan0). Default: auto-detect."
    )
    parser.add_argument(
        "--filter", "-f",
        type=str,
        default="",
        dest="pkt_filter",
        help="BPF filter string (e.g., 'tcp port 80', 'udp', 'host 192.168.1.1')."
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture. 0 = unlimited (default)."
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=None,
        help="Stop capture after N seconds. Default: no timeout."
    )
    return parser.parse_args()


def handle_interrupt(signum, frame):
    """Gracefully stop on Ctrl+C."""
    print("\n[INFO] Interrupt received. Stopping capture...")
    stop_sniffing()
    sys.exit(0)


def main():
    args = parse_args()

    print("=" * 42)
    print("   Network Intrusion Monitor v2.0")
    print("=" * 42)
    print("Press Ctrl+C to stop.\n")

    # Register graceful shutdown
    signal.signal(signal.SIGINT, handle_interrupt)
    signal.signal(signal.SIGTERM, handle_interrupt)

    start_sniffing(
        interface=args.interface,
        packet_filter=args.pkt_filter,
        count=args.count,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
