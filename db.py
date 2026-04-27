import os
import threading
import logging
from datetime import datetime

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME   = os.environ.get("DB_NAME",   "network_monitor")

COL_PACKETS = "packets"
COL_ALERTS  = "ddos_alerts"
COL_BLOCKED = "blocked_ips"

_client = None
_db     = None
_lock   = threading.Lock()
_connected = False

def connect():
    global _client, _db, _connected
    try:
        from pymongo import MongoClient, ASCENDING, DESCENDING
        from pymongo.errors import ConnectionFailure

        with _lock:
            _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
            _client.admin.command("ping")
            _db = _client[DB_NAME]

            _db[COL_PACKETS].create_index([("timestamp", DESCENDING)])
            _db[COL_PACKETS].create_index([("src_ip", ASCENDING)])
            _db[COL_PACKETS].create_index([("protocol", ASCENDING)])
            _db[COL_ALERTS].create_index([("timestamp", DESCENDING)])
            _db[COL_ALERTS].create_index([("ip", ASCENDING)])
            _db[COL_BLOCKED].create_index([("ip", ASCENDING)], unique=True)

            _connected = True
            logging.info(f"[MongoDB] Connected → {MONGO_URI} / {DB_NAME}")
            return True

    except Exception as e:
        logging.error(f"[MongoDB] Connection failed: {e}")
        logging.warning("[MongoDB] Running without database — data will NOT be saved.")
        _connected = False
        return False


def is_connected() -> bool:
    return _connected


def save_packet(pkt: dict):
    if not _connected:
        return
    try:
        doc = dict(pkt)
        if isinstance(doc.get("timestamp"), str):
            try:
                doc["timestamp"] = datetime.fromisoformat(doc["timestamp"])
            except Exception:
                doc["timestamp"] = datetime.utcnow()
        with _lock:
            _db[COL_PACKETS].insert_one(doc)
    except Exception as e:
        logging.error(f"[MongoDB] save_packet error: {e}")


def save_alert(alert: dict):
    if not _connected:
        return
    try:
        doc = dict(alert)
        if isinstance(doc.get("timestamp"), str):
            try:
                doc["timestamp"] = datetime.fromisoformat(doc["timestamp"])
            except Exception:
                doc["timestamp"] = datetime.utcnow()
        with _lock:
            _db[COL_ALERTS].insert_one(doc)
    except Exception as e:
        logging.error(f"[MongoDB] save_alert error: {e}")


def save_blocked(ip: str, info: dict):
    if not _connected:
        return
    try:
        from pymongo import UpdateOne
        doc = dict(info)
        doc["ip"] = ip
        if isinstance(doc.get("blocked_at"), str):
            try:
                doc["blocked_at"] = datetime.fromisoformat(doc["blocked_at"])
            except Exception:
                doc["blocked_at"] = datetime.utcnow()
        with _lock:
            _db[COL_BLOCKED].update_one(
                {"ip": ip},
                {"$set": doc},
                upsert=True
            )
    except Exception as e:
        logging.error(f"[MongoDB] save_blocked error: {e}")


def save_unblocked(ip: str):
    if not _connected:
        return
    try:
        with _lock:
            _db[COL_BLOCKED].update_one(
                {"ip": ip},
                {"$set": {"unblocked_at": datetime.utcnow(), "active": False}},
                upsert=False
            )
    except Exception as e:
        logging.error(f"[MongoDB] save_unblocked error: {e}")


def get_recent_packets(limit: int = 100, protocol: str = None, src_ip: str = None) -> list:
    if not _connected:
        return []
    try:
        query = {}
        if protocol:
            query["protocol"] = protocol.upper()
        if src_ip:
            query["src_ip"] = src_ip
        cursor = _db[COL_PACKETS].find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
        docs = list(cursor)
        for d in docs:
            if isinstance(d.get("timestamp"), datetime):
                d["timestamp"] = d["timestamp"].isoformat()
        return docs
    except Exception as e:
        logging.error(f"[MongoDB] get_recent_packets error: {e}")
        return []


def get_recent_alerts(limit: int = 50) -> list:
    if not _connected:
        return []
    try:
        cursor = _db[COL_ALERTS].find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
        docs = list(cursor)
        for d in docs:
            if isinstance(d.get("timestamp"), datetime):
                d["timestamp"] = d["timestamp"].isoformat()
        return docs
    except Exception as e:
        logging.error(f"[MongoDB] get_recent_alerts error: {e}")
        return []


def get_blocked_history(limit: int = 50) -> list:
    if not _connected:
        return []
    try:
        cursor = _db[COL_BLOCKED].find({}, {"_id": 0}).sort("blocked_at", -1).limit(limit)
        docs = list(cursor)
        for d in docs:
            for key in ("blocked_at", "unblocked_at"):
                if isinstance(d.get(key), datetime):
                    d[key] = d[key].isoformat()
        return docs
    except Exception as e:
        logging.error(f"[MongoDB] get_blocked_history error: {e}")
        return []


def get_stats_summary() -> dict:
    if not _connected:
        return {"packets": 0, "alerts": 0, "blocked": 0, "connected": False}
    try:
        with _lock:
            return {
                "packets":   _db[COL_PACKETS].estimated_document_count(),
                "alerts":    _db[COL_ALERTS].estimated_document_count(),
                "blocked":   _db[COL_BLOCKED].count_documents({"active": {"$ne": False}}),
                "connected": True,
            }
    except Exception as e:
        logging.error(f"[MongoDB] get_stats_summary error: {e}")
        return {"packets": 0, "alerts": 0, "blocked": 0, "connected": False}