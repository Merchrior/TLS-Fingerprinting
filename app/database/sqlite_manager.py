import sqlite3
import logging
import os
from app.core.config_loader import Config

class SQLiteManager:
    def __init__(self):
        self.db_path = Config().data['system']['database_path']
        self._init_db()

    def _get_connection(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            # SRS FR 3.1: Orijinal Whitelist Tablosu
            conn.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    ja3_hash TEXT PRIMARY KEY,
                    app_label TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    discovery_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # YENİ: UI için Canlı Trafik Tablosu
            conn.execute("""
                CREATE TABLE IF NOT EXISTS live_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT,
                    dst_ip TEXT,
                    ja3_hash TEXT,
                    status TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON whitelist(ja3_hash)")

    def check_fast_path(self, ja3_hash: str) -> str:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT app_label FROM whitelist WHERE ja3_hash = ?", (ja3_hash,))
            result = cursor.fetchone()
            return result[0] if result else None

    def autonomous_update(self, ja3_hash: str, label: str, confidence: float):
        threshold = Config().data['ai_kubernetes']['confidence_threshold']
        if confidence >= threshold:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO whitelist (ja3_hash, app_label, confidence) VALUES (?, ?, ?)",
                    (ja3_hash, label, confidence)
                )

    # YENİ: Arayüzde göstermek için her paketi kaydeder
    def log_live_traffic(self, src_ip: str, dst_ip: str, ja3_hash: str, status: str):
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO live_traffic (src_ip, dst_ip, ja3_hash, status) VALUES (?, ?, ?, ?)",
                (src_ip, dst_ip, ja3_hash, status)
            )