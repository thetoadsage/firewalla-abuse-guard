"""SQLite persistence; every successful unit of work commits independently."""
import json
from pathlib import Path
import sqlite3
import time


class State:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS processed_alarms (
                scope TEXT NOT NULL, alarm_id TEXT NOT NULL, processed_at REAL NOT NULL,
                PRIMARY KEY (scope, alarm_id)
            );
            CREATE TABLE IF NOT EXISTS ip_checks (
                ip TEXT NOT NULL, max_age INTEGER NOT NULL, checked_at REAL NOT NULL,
                metadata TEXT NOT NULL, PRIMARY KEY (ip, max_age)
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                scope TEXT NOT NULL, ip TEXT NOT NULL, alarm_id TEXT NOT NULL,
                target_list_id TEXT NOT NULL, blocked_at REAL NOT NULL,
                PRIMARY KEY (scope, ip)
            );
        """)

    def processed(self, scope, alarm_id):
        return self.db.execute("SELECT 1 FROM processed_alarms WHERE scope=? AND alarm_id=?",
                               (scope, alarm_id)).fetchone() is not None

    def mark_processed(self, scope, alarm_id):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO processed_alarms VALUES (?, ?, ?)",
                            (scope, alarm_id, time.time()))

    def cached_check(self, ip, max_age, ttl_seconds):
        row = self.db.execute("SELECT checked_at, metadata FROM ip_checks WHERE ip=? AND max_age=?",
                              (ip, max_age)).fetchone()
        if row and 0 <= time.time() - row[0] < ttl_seconds:
            return json.loads(row[1])
        return None

    def save_check(self, ip, max_age, metadata):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO ip_checks VALUES (?, ?, ?, ?)",
                            (ip, max_age, time.time(), json.dumps(metadata)))

    def blocked(self, scope, ip):
        return self.db.execute("SELECT 1 FROM blocked_ips WHERE scope=? AND ip=?",
                               (scope, ip)).fetchone() is not None

    def mark_blocked(self, scope, ip, alarm_id, target_list_id):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?, ?, ?, ?, ?)",
                            (scope, ip, alarm_id, target_list_id, time.time()))

    def close(self):
        self.db.close()
