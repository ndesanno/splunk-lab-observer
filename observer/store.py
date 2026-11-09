"""Timestamped observations, state changes, owner labels, and saved layouts."""

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


RETENTION_SECONDS = 30 * 24 * 60 * 60
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "splunk-lab-observer"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Store:
    """One SQLite file under the data directory. Safe to share between threads."""

    def __init__(self, data_dir=DEFAULT_DATA_DIR):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(self.data_dir / "observer.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock, self.db:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY, component TEXT NOT NULL, kind TEXT NOT NULL,
                    observed_at TEXT NOT NULL, epoch REAL NOT NULL, source TEXT NOT NULL, value TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS observations_component ON observations (component, kind, epoch);
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY, component TEXT NOT NULL, signal TEXT NOT NULL,
                    observed_at TEXT NOT NULL, epoch REAL NOT NULL, previous TEXT, current TEXT,
                    source TEXT NOT NULL, observation_id INTEGER);
                CREATE INDEX IF NOT EXISTS changes_component ON changes (component, epoch);
                CREATE TABLE IF NOT EXISTS signals (
                    component TEXT NOT NULL, signal TEXT NOT NULL, value TEXT, PRIMARY KEY (component, signal));
                CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)

    def record(self, component, kind, source, value, signals=None, observed_at=None):
        """Store one observation. Each signal (a short status such as "health") that differs
        from its last recorded value also produces a change linked to this observation."""
        observed_at = observed_at or utc_now()
        epoch = datetime.fromisoformat(observed_at.replace("Z", "+00:00")).timestamp()
        with self.lock, self.db:
            cursor = self.db.execute(
                "INSERT INTO observations (component, kind, observed_at, epoch, source, value) VALUES (?, ?, ?, ?, ?, ?)",
                (component, kind, observed_at, epoch, source, json.dumps(value, sort_keys=True)))
            observation_id = cursor.lastrowid
            for signal, current in (signals or {}).items():
                current = None if current is None else str(current)
                row = self.db.execute("SELECT value FROM signals WHERE component = ? AND signal = ?",
                                      (component, signal)).fetchone()
                if row is not None and row["value"] == current:
                    continue
                self.db.execute("INSERT OR REPLACE INTO signals (component, signal, value) VALUES (?, ?, ?)",
                                (component, signal, current))
                self.db.execute(
                    "INSERT INTO changes (component, signal, observed_at, epoch, previous, current, source, observation_id)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (component, signal, observed_at, epoch, None if row is None else row["value"], current, source, observation_id))
        return observation_id

    def observation(self, observation_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM observations WHERE id = ?", (observation_id,)).fetchone()
        return self._observation(row) if row else None

    def latest(self, component, kind):
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM observations WHERE component = ? AND kind = ? ORDER BY epoch DESC, id DESC LIMIT 1",
                (component, kind)).fetchone()
        return self._observation(row) if row else None

    def latest_before(self, component, kind, epoch):
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM observations WHERE component = ? AND kind = ? AND epoch <= ? ORDER BY epoch DESC, id DESC LIMIT 1",
                (component, kind, epoch)).fetchone()
        return self._observation(row) if row else None

    def changes(self, component=None, limit=200):
        query = "SELECT * FROM changes"
        args = []
        if component:
            query += " WHERE component = ?"
            args.append(component)
        query += " ORDER BY epoch DESC, id DESC LIMIT ?"
        args.append(limit)
        with self.lock:
            rows = self.db.execute(query, args).fetchall()
        return [{key: row[key] for key in ("id", "component", "signal", "observed_at", "previous", "current", "source", "observation_id")}
                for row in rows]

    def prune(self, now=None):
        cutoff = (now or time.time()) - RETENTION_SECONDS
        with self.lock, self.db:
            self.db.execute("DELETE FROM observations WHERE epoch < ?", (cutoff,))
            self.db.execute("DELETE FROM changes WHERE epoch < ?", (cutoff,))

    def get_setting(self, name, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM settings WHERE name = ?", (name,)).fetchone()
        return json.loads(row["value"]) if row else default

    def put_setting(self, name, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO settings (name, value) VALUES (?, ?)", (name, json.dumps(value)))

    @staticmethod
    def _observation(row):
        return {"id": row["id"], "component": row["component"], "kind": row["kind"],
                "observed_at": row["observed_at"], "source": row["source"], "value": json.loads(row["value"])}
