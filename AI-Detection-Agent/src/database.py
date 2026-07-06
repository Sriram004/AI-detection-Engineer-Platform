import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .validator import final_status, validation_score


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / os.getenv("INCIDENT_DB_PATH", "database/incidents.db")


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                alert_name TEXT NOT NULL,
                host TEXT,
                user TEXT,
                technique_id TEXT,
                technique_name TEXT,
                severity TEXT,
                confidence INTEGER,
                status TEXT,
                validation_score INTEGER,
                alert_json TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                validation_json TEXT NOT NULL
            )
            """
        )


def save_incident(alert: dict, analysis: dict, validation: dict) -> int:
    init_db()
    mapping = analysis["mitre_mapping"]
    status = final_status(validation)
    score = validation_score(validation)
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO incidents (
                created_at, alert_name, host, user, technique_id, technique_name,
                severity, confidence, status, validation_score, alert_json,
                analysis_json, validation_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                analysis["alert_name"],
                alert.get("hostname") or alert.get("host"),
                alert.get("user") or alert.get("account") or alert.get("user_principal_name"),
                mapping["technique_id"],
                mapping["technique_name"],
                analysis["severity"],
                analysis["confidence"],
                status,
                score,
                json.dumps(alert),
                json.dumps(analysis),
                json.dumps(validation),
            ),
        )
        return int(cursor.lastrowid)


def list_incidents() -> list[dict]:
    init_db()
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, created_at, alert_name, host, user, technique_id, severity,
                   confidence, status, validation_score
            FROM incidents
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()
    return [dict(row) for row in rows]
