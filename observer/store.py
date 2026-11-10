"""Timestamped observations, state changes, owner labels, and saved layouts."""

import json
import shutil
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
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, created_at TEXT NOT NULL, epoch REAL NOT NULL, updated_at TEXT NOT NULL,
                    status TEXT NOT NULL, title TEXT NOT NULL, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS page_requests (
                    id TEXT PRIMARY KEY, run_id TEXT NOT NULL, status TEXT NOT NULL, ok INTEGER, result TEXT,
                    created_at TEXT NOT NULL, done_at TEXT);
                CREATE TABLE IF NOT EXISTS page_watch (run_id TEXT PRIMARY KEY, seen REAL NOT NULL, paused INTEGER NOT NULL DEFAULT 0);
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

    def latest_capture_before(self, component, epoch):
        """The newest successful preview at or before a time."""
        with self.lock:
            row = self.db.execute(
                "SELECT * FROM observations WHERE component = ? AND kind = 'capture' AND epoch <= ?"
                " AND json_extract(value, '$.file') IS NOT NULL ORDER BY epoch DESC, id DESC LIMIT 1",
                (component, epoch)).fetchone()
        return self._observation(row) if row else None

    def changes_between(self, start_epoch, end_epoch, limit=300):
        with self.lock:
            rows = self.db.execute("SELECT * FROM changes WHERE epoch BETWEEN ? AND ? ORDER BY epoch, id LIMIT ?",
                                   (start_epoch, end_epoch, limit)).fetchall()
        return [{key: row[key] for key in ("id", "component", "signal", "observed_at", "previous", "current", "source", "observation_id")}
                for row in rows]

    def earliest(self):
        with self.lock:
            row = self.db.execute("SELECT observed_at FROM observations ORDER BY epoch LIMIT 1").fetchone()
        return row["observed_at"] if row else None

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
        """Drop observations and unpinned runs (with their evidence files) older than the retention period."""
        cutoff = (now or time.time()) - RETENTION_SECONDS
        with self.lock, self.db:
            self.db.execute("DELETE FROM observations WHERE epoch < ?", (cutoff,))
            self.db.execute("DELETE FROM changes WHERE epoch < ?", (cutoff,))
            expired = [row["id"] for row in self.db.execute(
                "SELECT id FROM runs WHERE epoch < ? AND coalesce(json_extract(record, '$.pinned'), 0) = 0", (cutoff,))]
            self.db.executemany("DELETE FROM runs WHERE id = ?", [(run_id,) for run_id in expired])
        for run_id in expired:
            shutil.rmtree(self.data_dir / "runs" / run_id, ignore_errors=True)
        return expired

    def save_run(self, record):
        """One assistant run: its prompt, every step and the evidence sent to the model."""
        epoch = datetime.fromisoformat(record["created_at"].replace("Z", "+00:00")).timestamp()
        with self.lock, self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO runs (id, created_at, epoch, updated_at, status, title, record) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record["id"], record["created_at"], epoch, utc_now(), record["status"], record["title"], json.dumps(record)))

    def run(self, run_id):
        with self.lock:
            row = self.db.execute("SELECT record FROM runs WHERE id = ?", (run_id,)).fetchone()
        return json.loads(row["record"]) if row else None

    def latest_run(self):
        """The most recently updated run, so an open page can follow one started elsewhere."""
        with self.lock:
            row = self.db.execute("SELECT id, status, updated_at, json_extract(record, '$.origin') AS origin FROM runs"
                                  " ORDER BY updated_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def runs(self, limit=30):
        with self.lock:
            rows = self.db.execute("SELECT id, created_at, updated_at, status, title, json_extract(record, '$.origin') AS origin,"
                                   " json_extract(record, '$.pinned') AS pinned, json_extract(record, '$.verdict.verdict') AS verdict"
                                   " FROM runs ORDER BY epoch DESC LIMIT ?",
                                   (limit,)).fetchall()
        return [dict(row) for row in rows]

    # --- the shared view for runs outside this process (Claude Code in the terminal) ----------

    def page_watched(self, run_id, paused=None):
        """An observer page polled this run (and, with paused, the owner paused or resumed it)."""
        with self.lock, self.db:
            self.db.execute("INSERT INTO page_watch (run_id, seen, paused) VALUES (?, ?, ?) ON CONFLICT(run_id) DO UPDATE "
                            "SET seen = excluded.seen, paused = COALESCE(?, paused)",
                            (run_id, time.time(), int(bool(paused)), None if paused is None else int(bool(paused))))

    def page_watch(self, run_id):
        with self.lock:
            row = self.db.execute("SELECT seen, paused FROM page_watch WHERE run_id = ?", (run_id,)).fetchone()
        return {"seen": row["seen"], "paused": bool(row["paused"])} if row else {"seen": 0.0, "paused": False}

    def add_page_request(self, request_id, run_id):
        with self.lock, self.db:
            self.db.execute("INSERT INTO page_requests (id, run_id, status, created_at) VALUES (?, ?, 'pending', ?)",
                            (request_id, run_id, utc_now()))

    def answer_page_request(self, run_id, request_id, ok, result):
        """The page's answer; False if there is no such pending request."""
        with self.lock, self.db:
            cursor = self.db.execute("UPDATE page_requests SET status = 'done', ok = ?, result = ?, done_at = ? "
                                     "WHERE id = ? AND run_id = ? AND status = 'pending'",
                                     (int(bool(ok)), json.dumps(result if isinstance(result, dict) else {}), utc_now(),
                                      request_id, run_id))
        return cursor.rowcount == 1

    def page_request(self, request_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM page_requests WHERE id = ?", (request_id,)).fetchone()
        if row is None:
            return None
        return {"status": row["status"], "ok": bool(row["ok"]), "result": json.loads(row["result"] or "{}")}

    def close_page_request(self, request_id, status):
        with self.lock, self.db:
            self.db.execute("UPDATE page_requests SET status = ? WHERE id = ? AND status = 'pending'", (status, request_id))

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
