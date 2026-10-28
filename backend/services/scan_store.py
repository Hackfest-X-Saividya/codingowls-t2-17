"""Persist finished scans in SQLite so results and history survive restarts.

Running scans live in the in-memory dict in routers/scan.py (progress changes
every second); a scan is written here once it completes or fails.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from typing import Any, Optional

from utils.config import settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        settings.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(settings.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                scan_id      TEXT PRIMARY KEY,
                repo_url     TEXT NOT NULL,
                repo_name    TEXT NOT NULL,
                status       TEXT NOT NULL,
                started_at   TEXT NOT NULL,
                finished_at  TEXT,
                error        TEXT,
                total        INTEGER DEFAULT 0,
                critical     INTEGER DEFAULT 0,
                high         INTEGER DEFAULT 0,
                state_json   TEXT NOT NULL
            )"""
        )
        _conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC)")
        logger.info("Scan store: %s", settings.DB_PATH)
    return _conn


def save(scan_id: str, state: dict[str, Any], summary: dict[str, int]) -> None:
    payload = json.dumps(state, default=lambda o: o.model_dump() if hasattr(o, "model_dump") else str(o))
    with _lock:
        db = _db()
        db.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, repo_url, repo_name, status, started_at, finished_at, error,
                total, critical, high, state_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id, state["repo_url"], state["repo_name"], str(state["status"].value
                if hasattr(state["status"], "value") else state["status"]),
                state["started_at"], state.get("finished_at"), state.get("error"),
                summary.get("total", 0), summary.get("critical", 0), summary.get("high", 0),
                payload,
            ),
        )
        db.commit()


def load(scan_id: str) -> Optional[dict[str, Any]]:
    with _lock:
        row = _db().execute("SELECT state_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    return json.loads(row["state_json"]) if row else None


def all_states() -> list[dict[str, Any]]:
    """Every stored scan state (used for validation statistics)."""
    with _lock:
        rows = _db().execute("SELECT state_json FROM scans").fetchall()
    return [json.loads(r["state_json"]) for r in rows]


def recent(limit: int = 20) -> list[dict[str, Any]]:
    with _lock:
        rows = _db().execute(
            """SELECT scan_id, repo_url, repo_name, status, started_at, finished_at,
                      total, critical, high
               FROM scans ORDER BY started_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
