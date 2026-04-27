import subprocess
import threading
import time
import logging
from collections import defaultdict, deque
from datetime import datetime
import db


WINDOW_SECONDS = 5
THRESHOLD      = 100
COOLDOWN       = 60


_lock          = threading.Lock()
_ip_timestamps = defaultdict(deque)
_blocked_ips   = {}
_flagged_ips   = {}
_cooldown_ips  = {}
_alert_log     = []

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")


def record_packet(src_ip: str):
    if not src_ip or src_ip in ("N/A", "0.0.0.0"):
        return

    now = time.time()

    with _lock:
        if src_ip in _blocked_ips:
            return
        if src_ip in _cooldown_ips and now < _cooldown_ips[src_ip]:
            return

        dq = _ip_timestamps[src_ip]
        dq.append(now)

        while dq and dq[0] < now - WINDOW_SECONDS:
            dq.popleft()

        count = len(dq)

    if count >= THRESHOLD:
        _trigger_block(src_ip, count)


def _trigger_block(ip: str, count: int):
    with _lock:
        if ip in _blocked_ips:
            return

        reason = f"{count} packets in {WINDOW_SECONDS}s (threshold: {THRESHOLD})"
        _flagged_ips[ip] = {
            "flagged_at": datetime.now().isoformat(),
            "count": count,
        }

    logging.warning(f"[DDoS] Blocking {ip} — {reason}")
    _add_alert(ip, reason)

    success = _block_ip_windows(ip)

    with _lock:
        _blocked_ips[ip] = {
            "blocked_at": datetime.now().isoformat(),
            "reason": reason,
            "rule_name": _rule_name(ip),
            "success": success,
            "active": True,
        }
        _cooldown_ips[ip] = time.time() + COOLDOWN
        _ip_timestamps[ip].clear()

    threading.Thread(target=db.save_blocked, args=(ip, _blocked_ips[ip]), daemon=True).start()


def _rule_name(ip: str) -> str:
    return f"NetMonitor_Block_{ip.replace('.', '_')}"


def _block_ip_windows(ip: str) -> bool:
    rule = _rule_name(ip)
    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "protocol=any",
                "enable=yes",
            ],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logging.info(f"[Firewall] Blocked {ip} — rule '{rule}' added.")
            return True
        else:
            logging.error(f"[Firewall] Failed to block {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        logging.error(f"[Firewall] Exception blocking {ip}: {e}")
        return False


def unblock_ip(ip: str) -> bool:
    rule = _rule_name(ip)
    try:
        result = subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule}",
            ],
            capture_output=True, text=True, timeout=10
        )
        with _lock:
            _blocked_ips.pop(ip, None)
            _flagged_ips.pop(ip, None)
            _cooldown_ips.pop(ip, None)
            _ip_timestamps[ip].clear()

        if result.returncode == 0:
            logging.info(f"[Firewall] Unblocked {ip} — rule '{rule}' removed.")
            _add_alert(ip, "Manually unblocked", level="info")
            threading.Thread(target=db.save_unblocked, args=(ip,), daemon=True).start()
            return True
        else:
            logging.error(f"[Firewall] Failed to unblock {ip}: {result.stderr.strip()}")
            return False
    except Exception as e:
        logging.error(f"[Firewall] Exception unblocking {ip}: {e}")
        return False


def _add_alert(ip: str, reason: str, level: str = "danger"):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "reason": reason,
        "level": level,
    }
    with _lock:
        _alert_log.insert(0, alert)
        if len(_alert_log) > 100:
            _alert_log.pop()
    threading.Thread(target=db.save_alert, args=(alert,), daemon=True).start()


def get_blocked_ips() -> dict:
    with _lock:
        return dict(_blocked_ips)


def get_flagged_ips() -> dict:
    with _lock:
        return dict(_flagged_ips)


def get_alerts() -> list:
    with _lock:
        return list(_alert_log)


def get_ip_rate(ip: str) -> int:
    now = time.time()
    with _lock:
        dq = _ip_timestamps.get(ip, deque())
        return sum(1 for t in dq if t >= now - WINDOW_SECONDS)


def get_top_talkers(n: int = 10) -> list:
    now = time.time()
    with _lock:
        rates = []
        for ip, dq in _ip_timestamps.items():
            count = sum(1 for t in dq if t >= now - WINDOW_SECONDS)
            if count > 0:
                rates.append({"ip": ip, "rate": count, "blocked": ip in _blocked_ips})
        rates.sort(key=lambda x: x["rate"], reverse=True)
        return rates[:n]