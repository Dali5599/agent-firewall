import os
import sqlite3
from typing import Optional

DB_PATH = os.path.abspath(os.environ.get("AGENT_FIREWALL_DB", "agent_firewall.db"))

class UnclosableConnection:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def close(self):
        pass

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)

    def __getattr__(self, name):
        return getattr(self._conn, name)

_shared_mem_conn = None

def get_db_path() -> str:
    return os.environ.get("DATABASE_URL", DB_PATH)

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    global _shared_mem_conn
    target = db_path or get_db_path()
    if target == ":memory:":
        if _shared_mem_conn is None:
            raw = sqlite3.connect(":memory:", check_same_thread=False)
            raw.row_factory = sqlite3.Row
            _shared_mem_conn = UnclosableConnection(raw)
        return _shared_mem_conn
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Optional[str] = None) -> None:
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                model TEXT,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                total_tokens INTEGER DEFAULT 0,
                status_code INTEGER DEFAULT 200,
                blocked INTEGER DEFAULT 0,
                blocked_reason TEXT,
                secrets_redacted INTEGER DEFAULT 0
            );
        """)
        conn.execute("DELETE FROM audit_logs;")
        conn.commit()
    target = db_path or get_db_path()
    if target != ":memory:":
        conn.close()
