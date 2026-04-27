"""
web_server.py — Flask web server for the Network Intrusion Monitor dashboard.

Usage:
    python web_server.py  (run as Administrator on Windows)
    Then open http://localhost:5000 in your browser.

Requirements:
    pip install flask scapy
"""

from flask import Flask, Response, render_template_string, jsonify, request
import threading
import json
import queue
import time
from packet_sniffer import start_sniffing, stop_sniffing, register_callback, get_packet_count
import ddos_guard
import db

# Connect to MongoDB at startup
db.connect()

app = Flask(__name__)

# Thread-safe queue for streaming packets to browser
packet_queue = queue.Queue(maxsize=500)
alert_queue  = queue.Queue(maxsize=200)
sniff_thread = None
is_sniffing = False
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0,
}
stats_lock = threading.Lock()


def on_packet(pkt: dict):
    """Called by packet_sniffer for each captured packet."""
    with stats_lock:
        stats["total"] += 1
        proto = pkt.get("protocol", "").upper()
        if proto == "TCP":
            stats["tcp"] += 1
        elif proto == "UDP":
            stats["udp"] += 1
        elif proto == "ICMP":
            stats["icmp"] += 1
        elif proto == "ARP":
            stats["arp"] += 1
        else:
            stats["other"] += 1

    try:
        packet_queue.put_nowait(pkt)
    except queue.Full:
        try:
            packet_queue.get_nowait()
            packet_queue.put_nowait(pkt)
        except Exception:
            pass


register_callback(on_packet)


# ── Background thread: push new DDoS alerts to alert_queue ──
_last_alert_count = 0

def _alert_watcher():
    global _last_alert_count
    while True:
        alerts = ddos_guard.get_alerts()
        if len(alerts) > _last_alert_count:
            new = alerts[:len(alerts) - _last_alert_count]
            for a in reversed(new):
                try:
                    alert_queue.put_nowait(a)
                except queue.Full:
                    pass
            _last_alert_count = len(alerts)
        time.sleep(0.5)

threading.Thread(target=_alert_watcher, daemon=True).start()


@app.route("/")
def index():
    return render_template_string(open("dashboard.html").read())


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint."""
    def generate():
        while True:
            try:
                pkt = packet_queue.get(timeout=1)
                yield f"data: {json.dumps(pkt)}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/stats")
def get_stats():
    with stats_lock:
        return jsonify(dict(stats))


@app.route("/start", methods=["POST"])
def start():
    global sniff_thread, is_sniffing
    if is_sniffing:
        return jsonify({"status": "already running"})
    is_sniffing = True

    def run():
        global is_sniffing
        start_sniffing(timeout=None)
        is_sniffing = False

    sniff_thread = threading.Thread(target=run, daemon=True)
    sniff_thread.start()
    return jsonify({"status": "started"})


@app.route("/stop", methods=["POST"])
def stop():
    global is_sniffing
    stop_sniffing()
    is_sniffing = False
    return jsonify({"status": "stopped"})


@app.route("/status")
def status():
    return jsonify({
        "sniffing": is_sniffing,
        "packet_count": get_packet_count(),
        "db_connected": db.is_connected(),
    })


# ── DDoS / Security routes ────────────────────────────

@app.route("/ddos/alerts")
def ddos_alerts():
    return jsonify(ddos_guard.get_alerts())


@app.route("/ddos/blocked")
def ddos_blocked():
    return jsonify(ddos_guard.get_blocked_ips())


@app.route("/ddos/talkers")
def ddos_talkers():
    return jsonify(ddos_guard.get_top_talkers())


@app.route("/ddos/unblock", methods=["POST"])
def ddos_unblock():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"status": "error", "message": "No IP provided"}), 400
    success = ddos_guard.unblock_ip(ip)
    return jsonify({"status": "ok" if success else "error", "ip": ip})


@app.route("/ddos/stream")
def ddos_stream():
    """SSE stream for real-time DDoS alerts."""
    def generate():
        while True:
            try:
                alert = alert_queue.get(timeout=1)
                yield f"data: {json.dumps(alert)}\n\n"
            except queue.Empty:
                yield ": keep-alive\n\n"
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── MongoDB query routes ──────────────────────────────

@app.route("/db/packets")
def db_packets():
    limit    = int(request.args.get("limit", 100))
    protocol = request.args.get("protocol", None)
    src_ip   = request.args.get("src_ip", None)
    return jsonify(db.get_recent_packets(limit=limit, protocol=protocol, src_ip=src_ip))


@app.route("/db/alerts")
def db_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(db.get_recent_alerts(limit=limit))


@app.route("/db/blocked")
def db_blocked():
    limit = int(request.args.get("limit", 50))
    return jsonify(db.get_blocked_history(limit=limit))


@app.route("/db/stats")
def db_stats():
    return jsonify(db.get_stats_summary())


if __name__ == "__main__":
    print("=" * 42)
    print("  Network Monitor Web Dashboard")
    print("  Open: http://localhost:5000")
    print("=" * 42)
    app.run(debug=False, threaded=True, port=5000)
