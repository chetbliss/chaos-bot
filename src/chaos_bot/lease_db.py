"""SQLite lease history for chaos-bot VLAN hop tracking."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH = Path.home() / ".chaos-bot" / "lease_history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS leases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vlan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    timestamp TEXT NOT NULL,
    modules_run TEXT,
    duration_sec REAL
);
CREATE INDEX IF NOT EXISTS idx_leases_vlan ON leases(vlan_id);
CREATE INDEX IF NOT EXISTS idx_leases_ip ON leases(ip);
"""


class LeaseDB:
    """Manage DHCP lease history in SQLite."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def record_lease(self, vlan_id: int, ip: str, mac: str,
                     modules_run: list[str], duration_sec: float) -> int:
        """Insert a lease record, return row ID."""
        cur = self._conn.execute(
            "INSERT INTO leases (vlan_id, ip, mac, timestamp, modules_run, duration_sec) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (vlan_id, ip, mac,
             datetime.now(timezone.utc).isoformat(),
             json.dumps(modules_run),
             round(duration_sec, 1)),
        )
        self._conn.commit()
        return cur.lastrowid

    def check_duplicate(self, vlan_id: int, ip: str) -> bool:
        """Check if this IP is the same as the immediately previous lease on this VLAN.

        Only rejects if the very last lease used this exact IP, to avoid
        getting stuck when DHCP consistently assigns the same address.
        """
        row = self._conn.execute(
            "SELECT ip FROM leases WHERE vlan_id = ? ORDER BY id DESC LIMIT 1",
            (vlan_id,),
        ).fetchone()
        return row is not None and row["ip"] == ip

    def get_history(self, vlan_id: int | None = None, last: int = 50) -> list[dict]:
        """Get lease history, optionally filtered by VLAN."""
        if vlan_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM leases WHERE vlan_id = ? ORDER BY id DESC LIMIT ?",
                (vlan_id, last),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM leases ORDER BY id DESC LIMIT ?",
                (last,),
            ).fetchall()
        return [dict(r) for r in rows]

    def clear(self) -> int:
        """Delete all lease records, return count deleted."""
        cur = self._conn.execute("DELETE FROM leases")
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()
