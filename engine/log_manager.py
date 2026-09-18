import hashlib
import json
import sqlite3
from datetime import datetime, timezone


class ComplianceLogger:

    def __init__(self, db_path: str = "audit_trail.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    model_used TEXT NOT NULL,
                    redaction_counts TEXT NOT NULL,
                    zdr_enforced INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
            """)
            conn.commit()

    def _calculate_hash(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def log_request(
        self,
        model: str,
        redactions: dict,
        zdr: bool,
        status: str = "SUCCESS"
    ):
        timestamp = datetime.now(timezone.utc).isoformat()

        with sqlite3.connect(self.db_path) as conn:

            row = conn.execute("""
                SELECT record_hash
                FROM logs
                ORDER BY id DESC
                LIMIT 1
            """).fetchone()

            previous_hash = row[0] if row else "GENESIS"

            redaction_json = json.dumps(
                redactions,
                sort_keys=True,
                separators=(",", ":")
            )

            record = (
                timestamp,
                model,
                redaction_json,
                int(zdr),
                status,
                previous_hash
            )

            record_hash = self._calculate_hash(
                json.dumps(record, separators=(",", ":"))
            )

            conn.execute("""
                INSERT INTO logs (
                    timestamp,
                    model_used,
                    redaction_counts,
                    zdr_enforced,
                    status,
                    previous_hash,
                    record_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                model,
                redaction_json,
                int(zdr),
                status,
                previous_hash,
                record_hash
            ))

            conn.commit()
