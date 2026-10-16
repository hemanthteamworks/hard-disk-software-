from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import html
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
from difflib import SequenceMatcher
from datetime import datetime
from functools import lru_cache
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from urllib.parse import parse_qs, urlencode, urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
EXPORT_DIR = BASE_DIR / "exports"
BACKUP_DIR = BASE_DIR / "backups"
DB_PATH = DATA_DIR / "catalog.db"
HOST = "127.0.0.1"
PORT = 5000
SESSION_COOKIE = "disk_catalog_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
SEARCH_RESULT_LIMIT = 200
BATCH_SIZE = 5_000
PROGRESS_INTERVAL_SECONDS = 1.0
STALL_WARNING_SECONDS = 60
LONG_DIRECTORY_SECONDS = 10.0
EXCLUDED_DIRECTORY_NAMES = {
    "$RECYCLE.BIN",
    "SYSTEM VOLUME INFORMATION",
    "WUDOWNLOADCACHE",
}
SCAN_JOBS: dict[str, dict[str, object]] = {}
SCAN_JOBS_LOCK = threading.Lock()


def folder_from_path(value: str) -> str:
    parent = str(PureWindowsPath(value).parent)
    return "" if parent == "." else parent


def normalize_search_text(value: str) -> str:
    return " ".join(re.findall(r"[^\W_]+", (value or "").casefold(), flags=re.UNICODE))


def parent_path(value: str) -> str:
    return folder_from_path(value)


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    EXPORT_DIR.mkdir(exist_ok=True)
    BACKUP_DIR.mkdir(exist_ok=True)


def ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def get_conn() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disk_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            full_path TEXT NOT NULL,
            extension TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_date TEXT,
            modified_date TEXT,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disk_id TEXT NOT NULL,
            folder_name TEXT NOT NULL,
            full_path TEXT NOT NULL,
            created_date TEXT,
            modified_date TEXT,
            scanned_at TEXT NOT NULL,
            UNIQUE(disk_id, full_path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_files_stage (
            job_id TEXT NOT NULL,
            disk_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            full_path TEXT NOT NULL,
            extension TEXT NOT NULL,
            size INTEGER NOT NULL,
            created_date TEXT,
            modified_date TEXT,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_folders_stage (
            job_id TEXT NOT NULL,
            disk_id TEXT NOT NULL,
            folder_name TEXT NOT NULL,
            full_path TEXT NOT NULL,
            created_date TEXT,
            modified_date TEXT,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            disk_id TEXT NOT NULL,
            root_path TEXT NOT NULL,
            file_count INTEGER NOT NULL,
            error_count INTEGER NOT NULL,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_cache (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_files INTEGER NOT NULL DEFAULT 0,
            total_size INTEGER NOT NULL DEFAULT 0,
            total_disks INTEGER NOT NULL DEFAULT 0,
            latest_disk_id TEXT,
            latest_file_count INTEGER,
            latest_scanned_at TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_top_types_cache (
            extension TEXT PRIMARY KEY,
            count INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS disk_summary_cache (
            disk_id TEXT PRIMARY KEY,
            file_count INTEGER NOT NULL DEFAULT 0,
            total_size INTEGER NOT NULL DEFAULT 0,
            last_scanned TEXT,
            total_capacity INTEGER,
            used_space INTEGER,
            available_space INTEGER,
            usage_percent REAL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS disk_extension_cache (
            disk_id TEXT NOT NULL,
            extension TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (disk_id, extension)
        )
        """
    )
    ensure_column(conn, "scan_history", "status", "TEXT NOT NULL DEFAULT 'completed'")
    ensure_column(conn, "scan_history", "folder_count", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "current_folder", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "scan_history", "started_at", "TEXT")
    ensure_column(conn, "scan_history", "finished_at", "TEXT")
    ensure_column(conn, "scan_history", "error_message", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "scan_history", "excluded_count", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "job_id", "TEXT")
    ensure_column(conn, "scan_history", "scan_rate", "REAL NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "insert_rate", "REAL NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "last_progress_at", "TEXT")
    ensure_column(conn, "scan_history", "long_directory_count", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "network_path", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "scan_history", "total_capacity", "INTEGER")
    ensure_column(conn, "scan_history", "used_space", "INTEGER")
    ensure_column(conn, "scan_history", "available_space", "INTEGER")
    ensure_column(conn, "scan_history", "usage_percent", "REAL")
    ensure_column(conn, "files", "parent_path", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "scan_files_stage", "parent_path", "TEXT NOT NULL DEFAULT ''")
    ensure_column(conn, "folders", "created_date", "TEXT")
    ensure_column(conn, "folders", "modified_date", "TEXT")
    ensure_column(conn, "scan_folders_stage", "created_date", "TEXT")
    ensure_column(conn, "scan_folders_stage", "modified_date", "TEXT")
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS catalog_search
        USING fts5(item_type UNINDEXED, disk_id UNINDEXED, name, full_path,
                   tokenize='unicode61 remove_diacritics 2')
        """
    )
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS catalog_search_trigram
        USING fts5(item_type UNINDEXED, disk_id UNINDEXED, name, full_path,
                   tokenize='trigram')
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_disk_id ON files(disk_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_extension ON files(extension)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_modified ON files(modified_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_files_name ON files(file_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_folders_disk_id ON folders(disk_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_folders_name ON folders(folder_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_job ON scan_history(job_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_files_stage_job ON scan_files_stage(job_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_folders_stage_job ON scan_folders_stage(job_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_disk_extension_extension ON disk_extension_cache(extension)")
    return conn


def ensure_folder_catalog() -> int:
    """Backfill non-empty folders from existing file paths once, without changing files."""
    with get_conn() as conn:
        migrated = conn.execute(
            "SELECT value FROM settings WHERE key = 'folders_backfilled_v1'"
        ).fetchone()
        if migrated:
            return conn.execute("SELECT COUNT(*) AS value FROM folders").fetchone()["value"]

        batch: set[tuple[str, str, str, str]] = set()
        for row in conn.execute("SELECT disk_id, full_path, scanned_at FROM files"):
            parent = PureWindowsPath(row["full_path"]).parent
            if str(parent) == ".":
                continue
            current = PureWindowsPath()
            for part in parent.parts:
                current /= part
                batch.add((row["disk_id"], part, str(current), row["scanned_at"]))
            if len(batch) >= 10_000:
                conn.executemany(
                    "INSERT OR IGNORE INTO folders(disk_id, folder_name, full_path, scanned_at) VALUES(?, ?, ?, ?)",
                    batch,
                )
                batch.clear()
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO folders(disk_id, folder_name, full_path, scanned_at) VALUES(?, ?, ?, ?)",
                batch,
            )
        conn.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES('folders_backfilled_v1', 'complete')"
        )
        conn.commit()
        return conn.execute("SELECT COUNT(*) AS value FROM folders").fetchone()["value"]


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp() -> int:
    return int(datetime.now().timestamp())


def fmt_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def dt_from_ts(value: float) -> str:
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")


def fmt_date(value: str | None) -> str:
    if not value:
        return "Unknown"
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%d %b %Y, %I:%M %p")
    except ValueError:
        return value


def normalize_disk_id(value: str) -> str:
    return value.strip().upper()


def esc(value: object) -> str:
    return html.escape(str(value or ""))


def setting(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return "pbkdf2_sha256$180000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def password_is_set() -> bool:
    with get_conn() as conn:
        return setting(conn, "password_hash") is not None


def set_password(password: str) -> None:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    with get_conn() as conn:
        set_setting(conn, "password_hash", hash_password(password))
        conn.commit()


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    created_at = timestamp()
    expires_at = created_at + SESSION_TTL_SECONDS
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (created_at,))
        conn.execute(
            "INSERT INTO sessions(token_hash, created_at, expires_at) VALUES(?, ?, ?)",
            (token_hash, created_at, expires_at),
        )
        conn.commit()
    return token


def session_is_valid(token: str) -> bool:
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT expires_at FROM sessions WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        return bool(row and row["expires_at"] >= timestamp())


def delete_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        conn.commit()


def attempt_login(password: str) -> str | None:
    with get_conn() as conn:
        stored = setting(conn, "password_hash")
    if stored and verify_password(password, stored):
        return create_session()
    return None


def password_matches(password: str) -> bool:
    with get_conn() as conn:
        stored = setting(conn, "password_hash")
    return bool(stored and verify_password(password, stored))


def disk_delete_token(session_token: str, disk_id: str) -> str:
    return hmac.new(
        session_token.encode("utf-8"),
        f"remove-disk:{normalize_disk_id(disk_id)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def recompute_dashboard_cache(conn: sqlite3.Connection) -> None:
    latest_scan = conn.execute(
        """
        SELECT disk_id, file_count, scanned_at
        FROM scan_history
        WHERE status = 'completed'
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    totals = conn.execute(
        """
        SELECT
            COALESCE(SUM(file_count), 0) AS total_files,
            COALESCE(SUM(total_size), 0) AS total_size,
            COUNT(*) AS total_disks
        FROM disk_summary_cache
        """
    ).fetchone()
    conn.execute(
        """
        INSERT INTO dashboard_cache(
            id, total_files, total_size, total_disks,
            latest_disk_id, latest_file_count, latest_scanned_at, updated_at
        ) VALUES(1, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            total_files = excluded.total_files,
            total_size = excluded.total_size,
            total_disks = excluded.total_disks,
            latest_disk_id = excluded.latest_disk_id,
            latest_file_count = excluded.latest_file_count,
            latest_scanned_at = excluded.latest_scanned_at,
            updated_at = excluded.updated_at
        """,
        (
            int(totals["total_files"] or 0),
            int(totals["total_size"] or 0),
            int(totals["total_disks"] or 0),
            latest_scan["disk_id"] if latest_scan else None,
            latest_scan["file_count"] if latest_scan else None,
            latest_scan["scanned_at"] if latest_scan else None,
            now_text(),
        ),
    )
    conn.execute("DELETE FROM dashboard_top_types_cache")
    conn.execute(
        """
        INSERT INTO dashboard_top_types_cache(extension, count)
        SELECT extension, SUM(count) AS count
        FROM disk_extension_cache
        GROUP BY extension
        ORDER BY count DESC
        LIMIT 8
        """
    )


def refresh_disk_summary_cache(conn: sqlite3.Connection, disk_id: str) -> None:
    disk_id = normalize_disk_id(disk_id)
    latest = conn.execute(
        """
        SELECT scanned_at, total_capacity, used_space, available_space, usage_percent
        FROM scan_history
        WHERE disk_id = ? AND status = 'completed'
        ORDER BY id DESC
        LIMIT 1
        """,
        (disk_id,),
    ).fetchone()
    totals = conn.execute(
        """
        SELECT COUNT(*) AS file_count, COALESCE(SUM(size), 0) AS total_size,
               MAX(scanned_at) AS last_scanned
        FROM files
        WHERE disk_id = ?
        """,
        (disk_id,),
    ).fetchone()
    file_count = int(totals["file_count"] or 0)
    if file_count == 0:
        conn.execute("DELETE FROM disk_summary_cache WHERE disk_id = ?", (disk_id,))
        conn.execute("DELETE FROM disk_extension_cache WHERE disk_id = ?", (disk_id,))
        return
    conn.execute(
        """
        INSERT INTO disk_summary_cache(
            disk_id, file_count, total_size, last_scanned,
            total_capacity, used_space, available_space, usage_percent, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(disk_id) DO UPDATE SET
            file_count = excluded.file_count,
            total_size = excluded.total_size,
            last_scanned = excluded.last_scanned,
            total_capacity = excluded.total_capacity,
            used_space = excluded.used_space,
            available_space = excluded.available_space,
            usage_percent = excluded.usage_percent,
            updated_at = excluded.updated_at
        """,
        (
            disk_id,
            file_count,
            int(totals["total_size"] or 0),
            latest["scanned_at"] if latest else totals["last_scanned"],
            latest["total_capacity"] if latest else None,
            latest["used_space"] if latest else None,
            latest["available_space"] if latest else None,
            latest["usage_percent"] if latest else None,
            now_text(),
        ),
    )
    conn.execute("DELETE FROM disk_extension_cache WHERE disk_id = ?", (disk_id,))
    conn.execute(
        """
        INSERT INTO disk_extension_cache(disk_id, extension, count)
        SELECT disk_id, COALESCE(NULLIF(extension, ''), '(none)') AS extension, COUNT(*) AS count
        FROM files
        WHERE disk_id = ?
        GROUP BY disk_id, extension
        """,
        (disk_id,),
    )


def rebuild_summary_cache() -> None:
    with get_conn() as conn:
        with conn:
            conn.execute("DELETE FROM disk_summary_cache")
            conn.execute("DELETE FROM disk_extension_cache")
            for row in conn.execute("SELECT DISTINCT disk_id FROM files ORDER BY disk_id"):
                refresh_disk_summary_cache(conn, row["disk_id"])
            recompute_dashboard_cache(conn)
    invalidate_summary_cache()


def refresh_summary_cache_for_disk(disk_id: str) -> None:
    with get_conn() as conn:
        with conn:
            refresh_disk_summary_cache(conn, disk_id)
            recompute_dashboard_cache(conn)
    invalidate_summary_cache()


def disk_summary(disk_id: str) -> sqlite3.Row | None:
    disk_id = normalize_disk_id(disk_id)
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT disk_id, COUNT(*) AS file_count,
                   COALESCE(SUM(size), 0) AS total_size,
                   MAX(scanned_at) AS last_scanned
            FROM files WHERE disk_id = ? GROUP BY disk_id
            """,
            (disk_id,),
        ).fetchone()


def remove_disk_catalog(disk_id: str) -> tuple[int, int, Path]:
    disk_id = normalize_disk_id(disk_id)
    if not disk_id:
        raise ValueError("Disk ID is required.")
    with SCAN_JOBS_LOCK:
        if any(
            job["status"] in {"scanning", "saving", "cancelling"}
            for job in SCAN_JOBS.values()
        ):
            raise ValueError("Wait for the active scan to finish or cancel it first.")
        with get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS files FROM files WHERE disk_id = ?", (disk_id,)
            ).fetchone()
            file_count = int(row["files"])
            folder_count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM folders WHERE disk_id = ?", (disk_id,)
                ).fetchone()[0]
            )
        if file_count == 0 and folder_count == 0:
            raise ValueError("That disk is not present in the catalog.")

        backup = backup_catalog(prefix=f"catalog_before_remove_{disk_id}")
        with get_conn() as conn:
            with conn:
                conn.execute("DELETE FROM catalog_search WHERE disk_id = ?", (disk_id,))
                conn.execute(
                    "DELETE FROM catalog_search_trigram WHERE disk_id = ?", (disk_id,)
                )
                conn.execute("DELETE FROM scan_files_stage WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM scan_folders_stage WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM files WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM folders WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM scan_history WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM disk_summary_cache WHERE disk_id = ?", (disk_id,))
                conn.execute("DELETE FROM disk_extension_cache WHERE disk_id = ?", (disk_id,))
                recompute_dashboard_cache(conn)
        invalidate_summary_cache()
        return file_count, folder_count, backup


def ensure_search_catalog() -> tuple[int, int]:
    """Migrate paths and rebuild FTS indexes when catalog counts change."""
    with get_conn() as conn:
        conn.execute("DROP TABLE IF EXISTS file_usage")
        migrated = setting(conn, "parent_paths_v1") == "complete"
        if not migrated:
            last_id = 0
            while True:
                rows = conn.execute(
                    "SELECT id, full_path FROM files WHERE id > ? ORDER BY id LIMIT ?",
                    (last_id, BATCH_SIZE),
                ).fetchall()
                if not rows:
                    break
                conn.executemany(
                    "UPDATE files SET parent_path = ? WHERE id = ?",
                    [(parent_path(row["full_path"]), row["id"]) for row in rows],
                )
                conn.commit()
                last_id = rows[-1]["id"]
            set_setting(conn, "parent_paths_v1", "complete")
            conn.commit()

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_disk_parent ON files(disk_id, parent_path)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_files_disk_path ON files(disk_id, full_path)"
        )
        file_count = conn.execute("SELECT COUNT(*) FROM files").fetchone()[0]
        folder_count = conn.execute("SELECT COUNT(*) FROM folders").fetchone()[0]
        expected = file_count + folder_count
        indexed = conn.execute("SELECT COUNT(*) FROM catalog_search").fetchone()[0]
        indexed_trigram = conn.execute("SELECT COUNT(*) FROM catalog_search_trigram").fetchone()[0]
        rebuild_tables = []
        if indexed != expected:
            rebuild_tables.append("catalog_search")
        if indexed_trigram != expected:
            rebuild_tables.append("catalog_search_trigram")
        if rebuild_tables:
            print(
                f"[{now_text()}] Rebuilding {', '.join(rebuild_tables)} "
                f"for {expected:,} catalog entries."
            )
            with conn:
                for table in rebuild_tables:
                    conn.execute(f"DELETE FROM {table}")
                    conn.execute(
                        f"INSERT INTO {table}(item_type, disk_id, name, full_path) "
                        "SELECT 'file', disk_id, file_name, full_path FROM files"
                    )
                    conn.execute(
                        f"INSERT INTO {table}(item_type, disk_id, name, full_path) "
                        "SELECT 'folder', disk_id, folder_name, full_path FROM folders"
                    )
            print(f"[{now_text()}] Search indexes ready.")
        return file_count, folder_count


class ScanCancelled(Exception):
    pass


def update_scan_job(job_id: str, **changes: object) -> None:
    force_persist = bool(changes.pop("force_persist", False))
    snapshot = None
    with SCAN_JOBS_LOCK:
        if job_id in SCAN_JOBS:
            if SCAN_JOBS[job_id]["status"] == "cancelling" and changes.get("status") == "scanning":
                changes.pop("status")
            job = SCAN_JOBS[job_id]
            job.update(changes)
            now_monotonic = time.monotonic()
            if force_persist or now_monotonic - float(job["last_persist_monotonic"]) >= PROGRESS_INTERVAL_SECONDS:
                job["last_persist_monotonic"] = now_monotonic
                snapshot = dict(job)
    if snapshot:
        with sqlite3.connect(DB_PATH, timeout=30) as conn:
            conn.execute("PRAGMA busy_timeout = 30000")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute(
                """
                UPDATE scan_history
                SET status = ?, file_count = ?, folder_count = ?, error_count = ?,
                    excluded_count = ?, current_folder = ?, scan_rate = ?, insert_rate = ?,
                    last_progress_at = ?, long_directory_count = ?, error_message = ?,
                    finished_at = ?
                WHERE job_id = ?
                """,
                (
                    snapshot["status"],
                    snapshot["file_count"],
                    snapshot["folder_count"],
                    snapshot["error_count"],
                    snapshot["excluded_count"],
                    snapshot["current_folder"],
                    snapshot["scan_rate"],
                    snapshot["insert_rate"],
                    datetime.fromtimestamp(float(snapshot["last_progress_at"])).strftime("%Y-%m-%d %H:%M:%S"),
                    snapshot["long_directory_count"],
                    snapshot["error"],
                    datetime.fromtimestamp(float(snapshot["finished_at"])).strftime("%Y-%m-%d %H:%M:%S")
                    if snapshot["finished_at"]
                    else None,
                    job_id,
                ),
            )
            conn.commit()


def scan_job(job_id: str) -> dict[str, object] | None:
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        return dict(job) if job else None


def active_scan_job() -> tuple[str, dict[str, object]] | None:
    with SCAN_JOBS_LOCK:
        for job_id, job in SCAN_JOBS.items():
            if job["status"] in {"scanning", "saving", "cancelling"}:
                return job_id, dict(job)
    return None


def run_scan_job(job_id: str) -> None:
    job = scan_job(job_id)
    if not job:
        return
    try:
        result = scan_disk(
            job_id,
            str(job["disk_id"]),
            str(job["root_path"]),
            progress_callback=lambda **changes: update_scan_job(job_id, **changes),
            cancel_event=job["cancel_event"],
        )
        update_scan_job(
            job_id,
            status="completed",
            file_count=result["file_count"],
            folder_count=result["folder_count"],
            error_count=result["error_count"],
            excluded_count=result["excluded_count"],
            errors=result["errors"],
            finished_at=time.time(),
            last_progress_at=time.time(),
            force_persist=True,
        )
        refresh_summary_cache_for_disk(str(job["disk_id"]))
    except ScanCancelled:
        cleanup_scan_stage(job_id)
        update_scan_job(
            job_id,
            status="cancelled",
            error="Cancelled by user. Previous catalog preserved.",
            finished_at=time.time(),
            last_progress_at=time.time(),
            force_persist=True,
        )
    except Exception as exc:
        cleanup_scan_stage(job_id)
        update_scan_job(
            job_id,
            status="failed",
            error=str(exc),
            finished_at=time.time(),
            last_progress_at=time.time(),
            force_persist=True,
        )


def cleanup_scan_stage(job_id: str) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_files_stage WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM scan_folders_stage WHERE job_id = ?", (job_id,))
        conn.commit()


def recover_interrupted_scans() -> None:
    finished = now_text()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE scan_history
            SET status = 'interrupted', finished_at = ?,
                error_message = 'Application stopped before scan completion. Previous catalog preserved.'
            WHERE status IN ('scanning', 'saving', 'cancelling')
            """,
            (finished,),
        )
        conn.execute("DELETE FROM scan_files_stage")
        conn.execute("DELETE FROM scan_folders_stage")
        conn.commit()


def start_scan_job(disk_id: str, root_path: str) -> str:
    disk_id = normalize_disk_id(disk_id)
    root = Path(root_path).expanduser().resolve()
    if not disk_id:
        raise ValueError("Disk ID is required.")
    if not root.exists() or not root.is_dir():
        raise ValueError("Selected disk path does not exist or is not a folder.")

    try:
        usage = shutil.disk_usage(root)
        total_capacity = usage.total
        used_space = usage.used
        available_space = usage.free
        usage_percent = (used_space / total_capacity * 100) if total_capacity else 0.0
    except OSError:
        total_capacity = None
        used_space = None
        available_space = None
        usage_percent = None

    with SCAN_JOBS_LOCK:
        if any(job["status"] in {"scanning", "saving", "cancelling"} for job in SCAN_JOBS.values()):
            raise ValueError("Another disk scan is already running.")
        job_id = secrets.token_urlsafe(12)
        started_at = time.time()
        with get_conn() as conn:
            previous = conn.execute(
                """
                SELECT file_count FROM scan_history
                WHERE disk_id = ? AND status = 'completed'
                ORDER BY id DESC LIMIT 1
                """,
                (disk_id,),
            ).fetchone()
            conn.execute(
                """
                INSERT INTO scan_history(
                    disk_id, root_path, file_count, error_count, scanned_at,
                    status, folder_count, current_folder, started_at,
                    excluded_count, job_id, last_progress_at, network_path,
                    total_capacity, used_space, available_space, usage_percent
                ) VALUES(?, ?, 0, 0, ?, 'scanning', 0, '(disk root)', ?, 0, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    disk_id,
                    str(root),
                    datetime.fromtimestamp(started_at).strftime("%Y-%m-%d %H:%M:%S"),
                    datetime.fromtimestamp(started_at).strftime("%Y-%m-%d %H:%M:%S"),
                    job_id,
                    datetime.fromtimestamp(started_at).strftime("%Y-%m-%d %H:%M:%S"),
                    1 if str(root).startswith("\\\\") else 0,
                    total_capacity,
                    used_space,
                    available_space,
                    usage_percent,
                ),
            )
            conn.commit()
        invalidate_summary_cache()
        SCAN_JOBS[job_id] = {
            "disk_id": disk_id,
            "root_path": str(root),
            "status": "scanning",
            "file_count": 0,
            "folder_count": 0,
            "error_count": 0,
            "current_folder": "(disk root)",
            "started_at": started_at,
            "finished_at": None,
            "last_progress_at": started_at,
            "last_persist_monotonic": time.monotonic(),
            "errors": [],
            "error": "",
            "excluded_count": 0,
            "long_directory_count": 0,
            "scan_rate": 0.0,
            "insert_rate": 0.0,
            "expected_files": int(previous["file_count"]) if previous else 0,
            "network_path": str(root).startswith("\\\\"),
            "cancel_event": threading.Event(),
        }
        if len(SCAN_JOBS) > 20:
            completed_ids = [
                key
                for key, value in SCAN_JOBS.items()
                if value["status"] in {"completed", "cancelled", "failed"} and key != job_id
            ]
            for old_id in completed_ids[:-10]:
                SCAN_JOBS.pop(old_id, None)

    threading.Thread(target=run_scan_job, args=(job_id,), daemon=True).start()
    return job_id


def cancel_scan_job(job_id: str) -> bool:
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job or job["status"] != "scanning":
            return False
        job["status"] = "cancelling"
        job["cancel_event"].set()
    update_scan_job(job_id, status="cancelling", force_persist=True)
    return True


def scan_disk(
    job_id: str,
    disk_id: str,
    root_path: str,
    progress_callback=None,
    cancel_event: threading.Event | None = None,
) -> dict[str, object]:
    disk_id = normalize_disk_id(disk_id)
    root = Path(root_path).expanduser().resolve()
    if not disk_id:
        raise ValueError("Disk ID is required.")
    if not root.exists() or not root.is_dir():
        raise ValueError("Selected disk path does not exist or is not a folder.")

    scanned_at = now_text()
    file_batch: list[tuple[object, ...]] = []
    folder_batch: list[tuple[object, ...]] = []
    errors: list[str] = []
    file_count = 0
    folder_count = 0
    error_count = 0
    excluded_count = 0
    long_directory_count = 0
    latest_insert_rate = 0.0
    started_monotonic = time.monotonic()
    last_report = 0.0
    stack = [root]

    def record_error(path: object, exc: BaseException) -> None:
        nonlocal error_count
        error_count += 1
        if len(errors) < 20:
            errors.append(f"{path}: {exc}")

    def flush_batches(conn: sqlite3.Connection) -> None:
        nonlocal latest_insert_rate
        inserted = len(file_batch) + len(folder_batch)
        if not inserted:
            return
        insert_started = time.monotonic()
        with conn:
            if file_batch:
                conn.executemany(
                    """
                    INSERT INTO scan_files_stage(
                        job_id, disk_id, file_name, full_path, extension, size,
                        created_date, modified_date, scanned_at, parent_path
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    file_batch,
                )
            if folder_batch:
                conn.executemany(
                    """
                    INSERT INTO scan_folders_stage(
                        job_id, disk_id, folder_name, full_path,
                        created_date, modified_date, scanned_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    folder_batch,
                )
        duration = max(time.monotonic() - insert_started, 0.001)
        latest_insert_rate = inserted / duration
        file_batch.clear()
        folder_batch.clear()

    def report(current_folder: str, force: bool = False, status: str = "scanning") -> None:
        nonlocal last_report
        current = time.monotonic()
        if not force and current - last_report < PROGRESS_INTERVAL_SECONDS:
            return
        last_report = current
        elapsed = max(current - started_monotonic, 0.001)
        if progress_callback:
            progress_callback(
                status=status,
                file_count=file_count,
                folder_count=folder_count,
                error_count=error_count,
                excluded_count=excluded_count,
                long_directory_count=long_directory_count,
                current_folder=current_folder,
                scan_rate=file_count / elapsed,
                insert_rate=latest_insert_rate,
                last_progress_at=time.time(),
                errors=list(errors),
                force_persist=force,
            )

    with get_conn() as conn:
        conn.execute("DELETE FROM scan_files_stage WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM scan_folders_stage WHERE job_id = ?", (job_id,))
        conn.commit()

        while stack:
            if cancel_event and cancel_event.is_set():
                raise ScanCancelled()
            current_root = stack.pop()
            relative_folder = current_root.relative_to(root)
            relative_text = str(relative_folder) if str(relative_folder) != "." else "(disk root)"
            report(relative_text)
            directory_started = time.monotonic()
            try:
                with os.scandir(current_root) as entries:
                    for entry in entries:
                        if cancel_event and cancel_event.is_set():
                            raise ScanCancelled()
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name.upper() in EXCLUDED_DIRECTORY_NAMES:
                                    excluded_count += 1
                                    continue
                                child_path = Path(entry.path)
                                child_relative = child_path.relative_to(root)
                                folder_stat = entry.stat(follow_symlinks=False)
                                folder_batch.append(
                                    (
                                        job_id,
                                        disk_id,
                                        entry.name,
                                        str(child_relative),
                                        dt_from_ts(folder_stat.st_ctime),
                                        dt_from_ts(folder_stat.st_mtime),
                                        scanned_at,
                                    )
                                )
                                folder_count += 1
                                stack.append(child_path)
                            elif entry.is_file(follow_symlinks=False):
                                stat = entry.stat(follow_symlinks=False)
                                relative_path = Path(entry.path).relative_to(root)
                                file_batch.append(
                                    (
                                        job_id,
                                        disk_id,
                                        entry.name,
                                        str(relative_path),
                                        Path(entry.name).suffix.lower().lstrip("."),
                                        stat.st_size,
                                        dt_from_ts(stat.st_ctime),
                                        dt_from_ts(stat.st_mtime),
                                        scanned_at,
                                        parent_path(str(relative_path)),
                                    )
                                )
                                file_count += 1
                                if file_count % 10_000 == 0:
                                    print(f"[{now_text()}] Scanned {file_count:,} files; current folder: {relative_text}")
                        except OSError as exc:
                            record_error(entry.path, exc)
                        if len(file_batch) + len(folder_batch) >= BATCH_SIZE:
                            flush_batches(conn)
                        report(relative_text)
            except OSError as exc:
                record_error(current_root, exc)

            directory_duration = time.monotonic() - directory_started
            if directory_duration >= LONG_DIRECTORY_SECONDS:
                long_directory_count += 1
                print(
                    f"[{now_text()}] Slow directory ({directory_duration:.1f}s): {current_root}"
                )

        flush_batches(conn)
        if cancel_event and cancel_event.is_set():
            raise ScanCancelled()

        report("Creating safety backup", force=True, status="saving")
        existing = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM files WHERE disk_id = ?)", (disk_id,)
        ).fetchone()[0]
        if existing:
            backup_catalog(prefix=f"catalog_pre_scan_{disk_id}")

        report("Saving completed scan", force=True, status="saving")
        with conn:
            conn.execute("DELETE FROM files WHERE disk_id = ?", (disk_id,))
            conn.execute("DELETE FROM folders WHERE disk_id = ?", (disk_id,))
            conn.execute(
                """
                INSERT INTO files(
                    disk_id, file_name, full_path, extension, size,
                    created_date, modified_date, scanned_at, parent_path
                )
                SELECT disk_id, file_name, full_path, extension, size,
                       created_date, modified_date, scanned_at, parent_path
                FROM scan_files_stage WHERE job_id = ?
                """,
                (job_id,),
            )
            conn.execute(
                """
                INSERT INTO folders(
                    disk_id, folder_name, full_path, created_date, modified_date, scanned_at
                )
                SELECT disk_id, folder_name, full_path, created_date, modified_date, scanned_at
                FROM scan_folders_stage WHERE job_id = ?
                """,
                (job_id,),
            )
            for table in ("catalog_search", "catalog_search_trigram"):
                conn.execute(f"DELETE FROM {table} WHERE disk_id = ?", (disk_id,))
                conn.execute(
                    f"INSERT INTO {table}(item_type, disk_id, name, full_path) "
                    "SELECT 'file', disk_id, file_name, full_path FROM files WHERE disk_id = ?",
                    (disk_id,),
                )
                conn.execute(
                    f"INSERT INTO {table}(item_type, disk_id, name, full_path) "
                    "SELECT 'folder', disk_id, folder_name, full_path FROM folders WHERE disk_id = ?",
                    (disk_id,),
                )
            conn.execute("DELETE FROM scan_files_stage WHERE job_id = ?", (job_id,))
            conn.execute("DELETE FROM scan_folders_stage WHERE job_id = ?", (job_id,))

    return {
        "file_count": file_count,
        "folder_count": folder_count,
        "error_count": error_count,
        "excluded_count": excluded_count,
        "errors": errors,
    }


def term_match_quality(term: str, words: list[str]) -> int:
    if any(word == term for word in words):
        return 4
    if any(word.startswith(term) for word in words):
        return 3
    if any(term in word for word in words):
        return 2
    if len(term) >= 4:
        similarity = max(
            (SequenceMatcher(None, term, word).ratio() for word in words),
            default=0.0,
        )
        if similarity >= 0.72:
            return 1
    return 0


def rank_search_candidate(
    query: str,
    name: str,
    full_path: str,
    scope: str = "name",
) -> tuple[float, str, int]:
    query_terms = normalize_search_text(query).split()
    if not query_terms:
        return 0.0, "No match", 0
    if scope == "path":
        target_normalized = normalize_search_text(parent_path(full_path))
        target_words = target_normalized.split()
    else:
        target_normalized = normalize_search_text(PureWindowsPath(name).stem)
        target_words = normalize_search_text(name).split()
    qualities = [term_match_quality(term, target_words) for term in query_terms]
    if not all(qualities):
        return 0.0, "No match", 0

    quality_total = sum(qualities)
    query_normalized = normalize_search_text(query)
    if scope == "path":
        return 100.0 + quality_total, "Path", quality_total
    if target_normalized == query_normalized:
        score, match_type = 1_000.0, "Exact name"
    elif target_normalized.startswith(query_normalized):
        score, match_type = 900.0, "Prefix"
    elif any(quality == 1 for quality in qualities):
        score, match_type = 600.0, "Similar spelling"
    elif len(query_terms) > 1:
        score, match_type = 750.0, "All keywords"
    else:
        score, match_type = 800.0, "Partial name"
    return float(score), match_type, quality_total


def search_catalog(
    params: dict[str, list[str]],
) -> tuple[list[dict[str, object]], int, str]:
    keyword = params.get("q", [""])[0].strip()
    disk_id = normalize_disk_id(params.get("disk_id", [""])[0])
    if not keyword:
        if disk_id:
            with get_conn() as conn:
                total = conn.execute(
                    "SELECT (SELECT COUNT(*) FROM files WHERE disk_id = ?) + "
                    "(SELECT COUNT(*) FROM folders WHERE disk_id = ?)",
                    (disk_id, disk_id),
                ).fetchone()[0]
                candidates = [
                    {"item_type": "folder", **dict(row), "name": row["folder_name"]}
                    for row in conn.execute(
                        "SELECT disk_id, folder_name, full_path FROM folders WHERE disk_id = ? ORDER BY full_path LIMIT ?",
                        (disk_id, SEARCH_RESULT_LIMIT),
                    )
                ]
                remaining = max(0, SEARCH_RESULT_LIMIT - len(candidates))
                candidates.extend(
                    {"item_type": "file", **dict(row), "name": row["file_name"]}
                    for row in conn.execute(
                        "SELECT disk_id, file_name, full_path FROM files WHERE disk_id = ? ORDER BY full_path LIMIT ?",
                        (disk_id, remaining),
                    )
                )
                return hydrate_search_results(conn, candidates), total, "disk"
        return [], 0, "name"

    terms = normalize_search_text(keyword).split()
    if not terms:
        return [], 0, "name"
    primary_term = terms[0]
    token_query = f'"{primary_term}"*'
    trigram_values = sorted(
        {
            primary_term[index : index + 3]
            for index in range(max(0, len(primary_term) - 2))
            if len(primary_term[index : index + 3]) == 3
        }
    )
    trigram_query = " OR ".join(f'"{value}"' for value in trigram_values)
    candidates: dict[tuple[str, str, str], dict[str, object]] = {}

    with get_conn() as conn:
        disk_clause = " AND disk_id = ?" if disk_id else ""
        disk_values: list[object] = [disk_id] if disk_id else []
        token_rows = conn.execute(
            f"""
            SELECT item_type, disk_id, name, full_path
            FROM catalog_search
            WHERE catalog_search MATCH ?{disk_clause}
            ORDER BY bm25(catalog_search)
            LIMIT 800
            """,
            [token_query, *disk_values],
        ).fetchall()
        for row in token_rows:
            candidates[(row["item_type"], row["disk_id"], row["full_path"])] = dict(row)

        if trigram_query:
            trigram_rows = conn.execute(
                f"""
                SELECT item_type, disk_id, name, full_path
                FROM catalog_search_trigram
                WHERE catalog_search_trigram MATCH ?{disk_clause}
                ORDER BY bm25(catalog_search_trigram)
                LIMIT 1_200
                """,
                [trigram_query, *disk_values],
            ).fetchall()
            for row in trigram_rows:
                candidates.setdefault(
                    (row["item_type"], row["disk_id"], row["full_path"]), dict(row)
                )

        name_ranked: list[dict[str, object]] = []
        for candidate in candidates.values():
            score, match_type, quality = rank_search_candidate(
                keyword,
                str(candidate["name"]),
                str(candidate["full_path"]),
                scope="name",
            )
            if score:
                ranked_item = dict(candidate)
                ranked_item.update(score=score, match_type=match_type, quality=quality)
                name_ranked.append(ranked_item)
        scope = "name"
        ranked = name_ranked
        if not ranked:
            scope = "path"
            for candidate in candidates.values():
                score, match_type, quality = rank_search_candidate(
                    keyword,
                    str(candidate["name"]),
                    str(candidate["full_path"]),
                    scope="path",
                )
                if score:
                    ranked_item = dict(candidate)
                    ranked_item.update(score=score, match_type=match_type, quality=quality)
                    ranked.append(ranked_item)
        ranked.sort(
            key=lambda item: (
                -float(item["score"]),
                -int(item["quality"]),
                normalize_search_text(str(item["name"])),
                str(item["disk_id"]),
                str(item["full_path"]),
            )
        )

        visible = hydrate_search_results(conn, ranked[:SEARCH_RESULT_LIMIT])
    return visible, len(ranked), scope


def hydrate_search_results(
    conn: sqlite3.Connection,
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for item in candidates:
        if item["item_type"] == "file":
            metadata = conn.execute(
                """
                SELECT extension, size, created_date, modified_date, parent_path
                FROM files WHERE disk_id = ? AND full_path = ?
                """,
                (item["disk_id"], item["full_path"]),
            ).fetchone()
            if not metadata:
                continue
            item.update(dict(metadata))
        else:
            metadata = conn.execute(
                """
                SELECT created_date, modified_date
                FROM folders WHERE disk_id = ? AND full_path = ?
                """,
                (item["disk_id"], item["full_path"]),
            ).fetchone()
            if not metadata:
                continue
            item.update(dict(metadata))
            item["extension"] = ""
            item["size"] = 0
            item["parent_path"] = parent_path(str(item["full_path"]))
        parent = str(item["parent_path"])
        item["parent_folder"] = PureWindowsPath(parent).name if parent else "(disk root)"
        item["display_path"] = parent or "(disk root)"
        results.append(item)
    return results


def related_files(
    conn: sqlite3.Connection,
    disk_id: str,
    parent: str,
    exclude_path: str,
    limit: int = 12,
) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT file_name, full_path, extension, size, modified_date
        FROM files
        WHERE disk_id = ? AND parent_path = ? AND full_path <> ?
        ORDER BY modified_date DESC, file_name
        LIMIT ?
        """,
        (disk_id, parent, exclude_path, limit),
    ).fetchall()


@lru_cache(maxsize=1)
def dashboard_stats() -> dict[str, object]:
    with get_conn() as conn:
        cached = conn.execute("SELECT * FROM dashboard_cache WHERE id = 1").fetchone()
        top_types = conn.execute(
            """
            SELECT extension, count
            FROM dashboard_top_types_cache
            ORDER BY count DESC
            LIMIT 8
            """
        ).fetchall()
    if cached:
        latest_scan = None
        if cached["latest_disk_id"]:
            latest_scan = {
                "disk_id": cached["latest_disk_id"],
                "file_count": cached["latest_file_count"],
                "scanned_at": cached["latest_scanned_at"],
            }
        return {
            "total_files": cached["total_files"],
            "total_disks": cached["total_disks"],
            "total_size": cached["total_size"],
            "latest_scan": latest_scan,
            "top_types": top_types,
        }
    return {
        "total_files": 0,
        "total_disks": 0,
        "total_size": 0,
        "latest_scan": None,
        "top_types": top_types,
    }


@lru_cache(maxsize=1)
def disk_rows() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT
                disk_id,
                file_count,
                total_size,
                last_scanned,
                total_capacity,
                used_space,
                available_space,
                usage_percent
            FROM disk_summary_cache
            ORDER BY disk_id
            """
        ).fetchall()


def invalidate_summary_cache() -> None:
    dashboard_stats.cache_clear()
    disk_rows.cache_clear()


def history_rows() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT disk_id, root_path, file_count, folder_count, error_count,
                   excluded_count, status, current_folder, scanned_at,
                   COALESCE(started_at, scanned_at) AS started_at,
                   COALESCE(finished_at, CASE WHEN status = 'completed' THEN scanned_at END) AS finished_at,
                   error_message
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()


def duplicate_rows() -> list[sqlite3.Row]:
    with get_conn() as conn:
        return conn.execute(
            """
            SELECT file_name, extension, COUNT(*) AS copies, GROUP_CONCAT(DISTINCT disk_id) AS disks
            FROM files
            GROUP BY lower(file_name), extension
            HAVING COUNT(*) > 1
            ORDER BY copies DESC, file_name
            LIMIT 200
            """
        ).fetchall()


def export_csv() -> Path:
    ensure_dirs()
    output = EXPORT_DIR / f"catalog_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with get_conn() as conn, output.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "disk_id",
                "file_name",
                "full_path",
                "extension",
                "size",
                "created_date",
                "modified_date",
            ]
        )
        for row in conn.execute(
            """
            SELECT f.disk_id, f.file_name, f.full_path, f.extension, f.size,
                   f.created_date, f.modified_date
            FROM files f
            ORDER BY f.disk_id, f.full_path
            """
        ):
            writer.writerow(row)
    return output


def backup_catalog(prefix: str = "catalog_backup") -> Path:
    ensure_dirs()
    safe_prefix = "".join(character if character.isalnum() or character in "-_" else "_" for character in prefix)
    output = BACKUP_DIR / f"{safe_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.db"
    if not DB_PATH.exists():
        get_conn().close()
    source = sqlite3.connect(DB_PATH)
    target = sqlite3.connect(output)
    try:
        source.backup(target, pages=1_000)
        check = target.execute("PRAGMA quick_check").fetchone()[0]
        if check != "ok":
            raise RuntimeError(f"Backup integrity check failed: {check}")
    except Exception:
        target.close()
        source.close()
        output.unlink(missing_ok=True)
        raise
    target.close()
    source.close()
    return output


def layout(
    title: str,
    content: str,
    notice: str = "",
    authed: bool = True,
    head_extra: str = "",
) -> bytes:
    notice_html = f'<div class="notice">{esc(notice)}</div>' if notice else ""
    nav = ""
    if authed:
        nav = """
  <nav>
    <a href="/scan">Scan Disk</a>
    <a href="/search">Search</a>
    <a href="/disks">Disks</a>
    <a href="/logout">Logout</a>
  </nav>
"""
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  {head_extra}
  <title>{esc(title)} - Disk Catalog</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7f9;
      --panel: #ffffff;
      --line: #d8dee6;
      --text: #1f2933;
      --muted: #627180;
      --accent: #176b87;
      --accent-dark: #0f5268;
      --danger: #8a1f11;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      background: #12343b;
      color: white;
      padding: 18px 28px;
    }}
    header h1 {{ margin: 0; font-size: 22px; }}
    header p {{ margin: 6px 0 0; color: #d7e3e7; }}
    nav {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      padding: 14px 28px;
      background: #e8eef2;
      border-bottom: 1px solid var(--line);
    }}
    nav a, button, .button {{
      border: 0;
      border-radius: 6px;
      background: var(--accent);
      color: white;
      cursor: pointer;
      display: inline-block;
      font-size: 14px;
      line-height: 1;
      padding: 11px 14px;
      text-decoration: none;
    }}
    nav a:hover, button:hover, .button:hover {{ background: var(--accent-dark); }}
    button.danger, .button.danger {{ background: var(--danger); }}
    button.danger:hover, .button.danger:hover {{ background: #64170d; }}
    main {{ padding: 24px 28px 42px; }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-bottom: 18px;
      padding: 18px;
    }}
    h2 {{ margin: 0 0 14px; font-size: 20px; }}
    label {{ display: block; font-weight: 700; margin-bottom: 6px; }}
    input, select {{
      border: 1px solid #bcc7d2;
      border-radius: 6px;
      font-size: 15px;
      max-width: 520px;
      padding: 10px 11px;
      width: 100%;
    }}
    .grid {{
      display: grid;
      gap: 14px;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      margin-bottom: 14px;
    }}
    .stat {{
      background: #f7fafc;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .stat strong {{ display: block; font-size: 24px; margin-top: 4px; }}
    .notice {{
      background: #e6f4ea;
      border: 1px solid #a8d5b5;
      border-radius: 6px;
      margin-bottom: 16px;
      padding: 12px;
    }}
    .warning {{
      background: #fff7e6;
      border: 1px solid #f1c76d;
      border-radius: 6px;
      color: #5f4200;
      padding: 12px;
    }}
    .muted {{ color: var(--muted); }}
    table {{
      border-collapse: collapse;
      font-size: 14px;
      width: 100%;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{ background: #f0f3f6; }}
    .results-table .disk-cell {{ width: 90px; white-space: nowrap; }}
    .results-table .name-cell {{ width: 260px; }}
    .results-table .path-cell {{ overflow-wrap: anywhere; word-break: normal; }}
    details.related {{ margin: 8px 0; }}
    details.related summary {{ color: var(--accent-dark); cursor: pointer; font-weight: 700; }}
    .related-list {{ columns: 2; margin: 10px 0 0; padding-left: 20px; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .scan-progress {{
      background: #dfe7ec;
      border-radius: 4px;
      height: 12px;
      margin: 18px 0;
      overflow: hidden;
    }}
    .scan-progress span {{
      animation: scan 1.4s linear infinite;
      background: var(--accent);
      display: block;
      height: 100%;
      width: 32%;
    }}
    @keyframes scan {{ from {{ transform: translateX(-100%); }} to {{ transform: translateX(320%); }} }}
  </style>
</head>
<body>
  <header>
    <h1>Disk Catalog</h1>
    <p>Read-only local file catalog. Stores file names and paths, not file contents.</p>
  </header>
  {nav}
  <main>
    {notice_html}
    {content}
  </main>
</body>
</html>"""
    return page.encode("utf-8")


def login_page(notice: str = "") -> bytes:
    content = """
<section>
  <h2>Login</h2>
  <form method="post" action="/login">
    <div class="grid">
      <div>
        <label for="password">Password</label>
        <input id="password" name="password" type="password" required>
      </div>
    </div>
    <button type="submit">Login</button>
  </form>
</section>
"""
    return layout("Login", content, notice, authed=False)


def setup_page(notice: str = "") -> bytes:
    content = """
<section>
  <h2>Create Admin Password</h2>
  <p class="muted">This protects the local catalog screens. Use at least 8 characters.</p>
  <form method="post" action="/setup">
    <div class="grid">
      <div>
        <label for="password">New password</label>
        <input id="password" name="password" type="password" required>
      </div>
      <div>
        <label for="confirm">Confirm password</label>
        <input id="confirm" name="confirm" type="password" required>
      </div>
    </div>
    <button type="submit">Save Password</button>
  </form>
</section>
"""
    return layout("Setup", content, notice, authed=False)


def dashboard_page(notice: str = "") -> bytes:
    stats = dashboard_stats()
    latest = stats["latest_scan"]
    latest_text = "No scans yet"
    if latest:
        latest_text = f"{esc(latest['disk_id'])} - {esc(latest['file_count'])} files at {esc(latest['scanned_at'])}"
    types_rows = "".join(
        f"<tr><td>{esc(row['extension'])}</td><td>{esc(row['count'])}</td></tr>"
        for row in stats["top_types"]
    )
    content = f"""
<section>
  <h2>Dashboard</h2>
  <div class="grid">
    <div class="stat">Disks cataloged<strong>{esc(stats['total_disks'])}</strong></div>
    <div class="stat">Files cataloged<strong>{esc(stats['total_files'])}</strong></div>
    <div class="stat">Cataloged size<strong>{esc(fmt_size(int(stats['total_size'])))}</strong></div>
    <div class="stat">Latest scan<strong style="font-size:16px">{latest_text}</strong></div>
  </div>
</section>
<section>
  <h2>Top File Types</h2>
  <table>
    <thead><tr><th>Type</th><th>Files</th></tr></thead>
    <tbody>{types_rows or '<tr><td colspan="2">No files scanned yet.</td></tr>'}</tbody>
  </table>
</section>
<section>
  <h2>Stage 2 Safety</h2>
  <p class="warning">This app still does not delete, move, rename, format, or auto-organize files. It reads metadata only.</p>
</section>
"""
    return layout("Dashboard", content, notice)


def scan_page(notice: str = "") -> bytes:
    active = active_scan_job()
    active_html = ""
    if active:
        active_html = f"""
<section>
  <h2>Active Scan</h2>
  <p>{esc(active[1]['disk_id'])} is currently {esc(active[1]['status'])}.</p>
  <a class="button" href="/scan/status?{urlencode({'id': active[0]})}">View Scan Status</a>
</section>
"""
    content = f"""
{active_html}
<section>
  <h2>Scan Disk</h2>
  <p class="muted">Enter the physical label from your sticker, then enter the drive path. Example: HD01 and E:\\</p>
  <form method="post" action="/scan">
    <div class="grid">
      <div>
        <label for="disk_id">Disk ID</label>
        <input id="disk_id" name="disk_id" placeholder="HD01" required>
      </div>
      <div>
        <label for="root_path">Disk path</label>
        <input id="root_path" name="root_path" placeholder="E:\\" required>
      </div>
    </div>
    <button type="submit">Scan Disk</button>
  </form>
</section>
<section>
  <h2>Safety</h2>
  <p>This scanner reads file list metadata only. It does not copy, delete, move, rename, or modify files.</p>
</section>
"""
    return layout("Scan Disk", content, notice)


def scan_status_page(job_id: str, notice: str = "") -> bytes:
    job = scan_job(job_id)
    if not job:
        return layout(
            "Scan Status",
            '<section><h2>Scan not found</h2><a class="button" href="/scan">Return to Scan Disk</a></section>',
            notice,
        )

    status = str(job["status"])
    elapsed_end = float(job["finished_at"] or time.time())
    elapsed = max(0, int(elapsed_end - float(job["started_at"])))
    minutes, seconds = divmod(elapsed, 60)
    stalled_seconds = max(0, int(time.time() - float(job["last_progress_at"])))
    stalled = status == "scanning" and stalled_seconds >= STALL_WARNING_SECONDS
    scan_rate = float(job["scan_rate"])
    insert_rate = float(job["insert_rate"])
    expected_files = int(job["expected_files"])
    if expected_files > int(job["file_count"]) and scan_rate > 0:
        eta_seconds = int((expected_files - int(job["file_count"])) / scan_rate)
        eta_minutes, eta_remainder = divmod(eta_seconds, 60)
        eta_text = f"{eta_minutes}m {eta_remainder}s"
    else:
        eta_text = "Unknown on first scan"
    refresh = '<meta http-equiv="refresh" content="2">' if status in {"scanning", "saving", "cancelling"} else ""
    progress = '<div class="scan-progress"><span></span></div>' if status in {"scanning", "saving", "cancelling"} else ""
    cancel = ""
    if status == "scanning":
        cancel = f"""
        <form method="post" action="/scan/cancel">
          <input type="hidden" name="job_id" value="{esc(job_id)}">
          <button type="submit">Cancel Scan</button>
        </form>
        """
    message = {
        "scanning": "Scanning file and folder names",
        "saving": "Saving the completed catalog",
        "cancelling": "Stopping the scan safely",
        "cancelled": "Scan cancelled. The previous catalog was kept.",
        "completed": "Scan complete.",
        "failed": f"Scan failed: {esc(job.get('error', 'Unknown error'))}",
    }.get(status, status)
    warning = ""
    if stalled:
        warning = f'<p class="warning">No progress for {stalled_seconds} seconds. The current folder or disk may be slow or unreadable. You can cancel safely; the previous catalog is preserved.</p>'
    if job["network_path"]:
        warning += '<p class="warning">This is a network path. Network scans can pause because of connection delays.</p>'
    error_details = ""
    if job["errors"]:
        items = "".join(f"<li>{esc(item)}</li>" for item in job["errors"])
        error_details = f"<details><summary>Skipped item details</summary><ul>{items}</ul></details>"
    content = f"""
<section>
  <h2>Scan Status: {esc(job['disk_id'])}</h2>
  <p><strong>{message}</strong></p>
  {warning}
  {progress}
  <div class="grid">
    <div class="stat">Files found<strong>{esc(job['file_count'])}</strong></div>
    <div class="stat">Folders found<strong>{esc(job['folder_count'])}</strong></div>
    <div class="stat">Skipped<strong>{esc(job['error_count'])}</strong></div>
    <div class="stat">Excluded caches<strong>{esc(job['excluded_count'])}</strong></div>
    <div class="stat">Elapsed time<strong>{minutes}m {seconds}s</strong></div>
    <div class="stat">Scan speed<strong>{scan_rate:,.0f}/sec</strong></div>
    <div class="stat">Database speed<strong>{insert_rate:,.0f}/sec</strong></div>
    <div class="stat">Estimated remaining<strong style="font-size:16px">{eta_text}</strong></div>
  </div>
  <p><strong>Current folder:</strong> {esc(job['current_folder'])}</p>
  <p><strong>Slow directories detected:</strong> {esc(job['long_directory_count'])}</p>
  {error_details}
  {cancel}
  <a class="button" href="/scan">Return to Scan Disk</a>
</section>
"""
    return layout("Scan Status", content, notice, head_extra=refresh)


def search_page(
    params: dict[str, list[str]] | None = None,
    notice: str = "",
    disk_id: str = "",
) -> bytes:
    params = dict(params or {})
    disk_id = normalize_disk_id(disk_id)
    if disk_id:
        params["disk_id"] = [disk_id]
    query_entered = bool(params.get("q", [""])[0].strip())
    rows: list[dict[str, object]] = []
    total = 0
    scope = "name"
    if query_entered:
        rows, total, scope = search_catalog(params)

    result_parts: list[str] = []
    related_cache: dict[tuple[str, str], list[sqlite3.Row]] = {}
    with get_conn() as related_conn:
        for row in rows:
            is_file = row["item_type"] == "file"
            preview_path = str(row["parent_path"]) if is_file else str(row["full_path"])
            cache_key = (str(row["disk_id"]), preview_path)
            if cache_key not in related_cache:
                related_cache[cache_key] = related_files(
                    related_conn,
                    cache_key[0],
                    cache_key[1],
                    "",
                    limit=20,
                )
            siblings = [
                sibling
                for sibling in related_cache[cache_key]
                if not is_file or sibling["full_path"] != row["full_path"]
            ][:12]
            related_items = "".join(
                f"<li>{esc(sibling['file_name'])} <span class=\"muted\">({esc(sibling['extension'] or 'file')}, {esc(fmt_size(sibling['size']))})</span></li>"
                for sibling in siblings
            )
            preview_title = "Related files" if is_file else "Folder preview"
            related_preview = (
                f'<h3>{preview_title}</h3><ul class="related-list">{related_items}</ul>'
                if siblings
                else '<p class="muted">No files to preview.</p>'
            )
            display_path = (
                ' → '.join(PureWindowsPath(str(row["display_path"])).parts)
                if row["display_path"] != "(disk root)"
                else "(disk root)"
            )
            icon = chr(0x1F4C4) if is_file else chr(0x1F4C1)
            advanced = ""
            if is_file:
                advanced = (
                    f'<p><strong>Type:</strong> {esc(row["extension"] or "None")} &nbsp; '
                    f'<strong>Size:</strong> {esc(fmt_size(int(row["size"])))}</p>'
                )
            result_parts.append(
                f"""
        <tr>
          <td class="disk-cell"><strong>{esc(row['disk_id'])}</strong></td>
          <td class="name-cell">{icon} {esc(row['name'])}</td>
          <td>{esc(row['parent_folder'])}</td>
          <td class="path-cell">{esc(display_path)}</td>
          <td>{esc(fmt_date(row['created_date']))}</td>
          <td>{esc(fmt_date(row['modified_date']))}</td>
        </tr>
        <tr><td></td><td colspan="5">
          <details class="related">
            <summary>Details</summary>
            {advanced}
            {related_preview}
          </details>
        </td></tr>
        """
            )
    result_rows = "".join(result_parts)
    scope_text = "name matches" if scope != "path" else "path matches"

    results = (
        f"""
<section>
  <h2>Results</h2>
  <p class="muted">{total} {scope_text}.</p>
  <table class="results-table">
    <thead><tr><th>Disk</th><th>Match</th><th>Parent Folder</th><th>Path</th><th>Created</th><th>Modified</th></tr></thead>
    <tbody>{result_rows or '<tr><td colspan="6">No matching files or folders.</td></tr>'}</tbody>
  </table>
</section>
"""
        if query_entered
        else ""
    )
    form_action = "/disks/search" if disk_id else "/search"
    hidden_disk = f'<input type="hidden" name="disk_id" value="{esc(disk_id)}">' if disk_id else ""
    heading = f"Search {disk_id}" if disk_id else "Search"
    content = f"""
<section>
  <h2>{esc(heading)}</h2>
  <form method="get" action="{form_action}">
    {hidden_disk}
    <div style="margin-bottom:14px; max-width:620px">
      <label for="q">File or folder name</label>
      <input id="q" name="q" value="{esc(params.get('q', [''])[0])}" required autofocus>
    </div>
    <button type="submit">Search</button>
  </form>
</section>
{results}
"""
    return layout(heading, content, notice)


def disks_page(notice: str = "") -> bytes:
    def storage_value(value: object) -> str:
        return "Not recorded" if value is None else fmt_size(int(value))

    rows = "".join(
        f"""
        <tr>
          <td>{esc(row['disk_id'])}</td>
          <td>{esc(row['file_count'])}</td>
          <td>{esc(fmt_size(row['total_size']))}</td>
          <td>{esc(storage_value(row['total_capacity']))}</td>
          <td>{esc(storage_value(row['used_space']))}</td>
          <td>{esc(storage_value(row['available_space']))}</td>
          <td>{esc('Not recorded' if row['usage_percent'] is None else f"{row['usage_percent']:.1f}%")}</td>
          <td>{esc(fmt_date(row['last_scanned']))}</td>
          <td><div class="actions">
            <a class="button" href="/disks/search?{urlencode({'disk_id': row['disk_id']})}">Search Disk</a>
          </div></td>
        </tr>
        """
        for row in disk_rows()
    )
    content = f"""
<section>
  <h2>Disks</h2>
  <div class="actions" style="margin-bottom:14px">
    <a class="button danger" href="/disks/remove">Delete Catalog Data</a>
  </div>
  <table>
    <thead><tr><th>Disk ID</th><th>Files</th><th>Cataloged size</th><th>Total capacity</th><th>Used space</th><th>Available space</th><th>Usage</th><th>Last scanned</th><th>Action</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="9">No disks scanned yet.</td></tr>'}</tbody>
  </table>
</section>
"""
    return layout("Disks", content, notice)


def disk_remove_page(session_token: str, notice: str = "", selected_disk_id: str = "") -> bytes:
    disks = disk_rows()
    if not disks:
        return layout(
            "Remove Disk",
            '<section><h2>No disks in catalog</h2><a class="button" href="/disks">Return to Disks</a></section>',
            notice,
        )
    selected_disk_id = normalize_disk_id(selected_disk_id)
    options = "".join(
        f'<option value="{esc(row["disk_id"])}"'
        f'{" selected" if row["disk_id"] == selected_disk_id else ""}>'
        f'{esc(row["disk_id"])}</option>'
        for row in disks
    )
    confirm_token = disk_delete_token(session_token, "")
    content = f"""
<section>
  <h2>Delete Disk from Catalog</h2>
  <p class="warning"><strong>This removes catalog information only.</strong> Files on the physical disk will not be opened, changed, or deleted.</p>
  <form method="post" action="/disks/remove">
    <input type="hidden" name="confirm_token" value="{esc(confirm_token)}">
    <div class="grid">
      <div>
        <label for="disk_id">Disk ID</label>
        <select id="disk_id" name="disk_id" required>{options}</select>
      </div>
      <div>
        <label for="password">Catalog password</label>
        <input id="password" name="password" type="password" required>
      </div>
    </div>
    <div class="actions">
      <button class="danger" type="submit">Delete Catalog Data</button>
      <a class="button" href="/disks">Cancel</a>
    </div>
  </form>
</section>
"""
    return layout("Remove Disk", content, notice)


def history_page(notice: str = "") -> bytes:
    rows = "".join(
        f"""
        <tr>
          <td>{esc(row['disk_id'])}</td>
          <td><strong>{esc(str(row['status']).title())}</strong></td>
          <td>{esc(row['root_path'])}</td>
          <td>{esc(row['file_count'])} files<br>{esc(row['folder_count'])} folders<br>{esc(row['error_count'])} skipped<br>{esc(row['excluded_count'])} excluded</td>
          <td>{esc(row['current_folder'] or '-')}</td>
          <td>{esc(row['started_at'])}</td>
          <td>{esc(row['finished_at'] or '-')}</td>
          <td>{esc(row['error_message'] or '-')}</td>
        </tr>
        """
        for row in history_rows()
    )
    content = f"""
<section>
  <h2>Scan History</h2>
  <table>
    <thead><tr><th>Disk</th><th>Status</th><th>Scanned path</th><th>Progress</th><th>Last folder</th><th>Started</th><th>Finished</th><th>Problem</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="8">No scan history yet.</td></tr>'}</tbody>
  </table>
</section>
"""
    return layout("Scan History", content, notice)


def duplicates_page(notice: str = "") -> bytes:
    rows = "".join(
        f"""
        <tr>
          <td>{esc(row['file_name'])}</td>
          <td>{esc(row['extension'])}</td>
          <td>{esc(row['copies'])}</td>
          <td>{esc(row['disks'])}</td>
          <td><a class="button" href="/search?{urlencode({'q': row['file_name']})}">View</a></td>
        </tr>
        """
        for row in duplicate_rows()
    )
    content = f"""
<section>
  <h2>Duplicate File Names</h2>
  <p class="muted">This checks matching file names only. It does not compare actual file contents.</p>
  <table>
    <thead><tr><th>File</th><th>Type</th><th>Copies</th><th>Disks</th><th>Action</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="5">No duplicate file names found.</td></tr>'}</tbody>
  </table>
</section>
"""
    return layout("Duplicates", content, notice)


class Handler(BaseHTTPRequestHandler):
    def send_html(self, body: bytes, status: int = 200, session_token: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if session_token is not None:
            cookie = cookies.SimpleCookie()
            cookie[SESSION_COOKIE] = session_token
            cookie[SESSION_COOKIE]["httponly"] = True
            cookie[SESSION_COOKIE]["samesite"] = "Strict"
            cookie[SESSION_COOKIE]["path"] = "/"
            if session_token:
                cookie[SESSION_COOKIE]["max-age"] = str(SESSION_TTL_SECONDS)
            else:
                cookie[SESSION_COOKIE]["max-age"] = "0"
            self.send_header("Set-Cookie", cookie.output(header="").strip())
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, path: str, session_token: str | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", path)
        if session_token is not None:
            cookie = cookies.SimpleCookie()
            cookie[SESSION_COOKIE] = session_token
            cookie[SESSION_COOKIE]["httponly"] = True
            cookie[SESSION_COOKIE]["samesite"] = "Strict"
            cookie[SESSION_COOKIE]["path"] = "/"
            cookie[SESSION_COOKIE]["max-age"] = str(SESSION_TTL_SECONDS) if session_token else "0"
            self.send_header("Set-Cookie", cookie.output(header="").strip())
        self.send_header("Content-Length", "0")
        self.end_headers()

    def session_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie(raw)
        return jar.get(SESSION_COOKIE).value if SESSION_COOKIE in jar else ""

    def is_authed(self) -> bool:
        return session_is_valid(self.session_token())

    def require_auth(self, parsed_path: str) -> bool:
        if parsed_path in {"/login", "/setup"}:
            return True
        if not password_is_set():
            self.redirect("/setup")
            return False
        if not self.is_authed():
            self.redirect("/login")
            return False
        return True

    def form_data(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        return parse_qs(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if not self.require_auth(parsed.path):
            return
        if parsed.path == "/setup":
            self.send_html(setup_page())
        elif parsed.path == "/login":
            self.send_html(login_page())
        elif parsed.path == "/logout":
            delete_session(self.session_token())
            self.redirect("/login", session_token="")
        elif parsed.path == "/":
            self.redirect("/disks")
        elif parsed.path == "/scan":
            self.send_html(scan_page())
        elif parsed.path == "/scan/status":
            params = parse_qs(parsed.query)
            self.send_html(scan_status_page(params.get("id", [""])[0]))
        elif parsed.path == "/search":
            params = parse_qs(parsed.query)
            self.send_html(search_page(params) if parsed.query else search_page())
        elif parsed.path == "/disks":
            params = parse_qs(parsed.query)
            removed = params.get("removed", [""])[0]
            if removed:
                notice = f"Removed {removed} from the catalog. Physical disk files were not changed."
            else:
                notice = ""
            self.send_html(disks_page(notice))
        elif parsed.path == "/disks/search":
            params = parse_qs(parsed.query)
            disk_id = normalize_disk_id(params.get("disk_id", [""])[0])
            if not disk_id or not any(row["disk_id"] == disk_id for row in disk_rows()):
                self.send_html(
                    layout(
                        "Search Disk",
                        '<section><h2>Disk not found</h2><a class="button" href="/disks">Return to Disks</a></section>',
                    ),
                    404,
                )
            else:
                self.send_html(search_page(params, disk_id=disk_id))
        elif parsed.path == "/disks/remove":
            self.send_html(disk_remove_page(self.session_token()))
        elif parsed.path == "/history":
            self.send_html(history_page())
        elif parsed.path == "/duplicates":
            self.send_html(duplicates_page())
        elif parsed.path == "/export":
            output = export_csv()
            self.send_html(dashboard_page(f"CSV exported to {output}"))
        elif parsed.path == "/backup":
            output = backup_catalog()
            self.send_html(dashboard_page(f"Catalog backup created at {output}"))
        else:
            self.send_html(layout("Not Found", "<section><h2>Page not found</h2></section>"), 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/setup":
            data = self.form_data()
            password = data.get("password", [""])[0]
            confirm = data.get("confirm", [""])[0]
            if password_is_set():
                self.redirect("/login")
                return
            if password != confirm:
                self.send_html(setup_page("Passwords do not match."), 400)
                return
            try:
                set_password(password)
            except ValueError as exc:
                self.send_html(setup_page(str(exc)), 400)
                return
            token = create_session()
            self.redirect("/", session_token=token)
            return

        if parsed.path == "/login":
            data = self.form_data()
            token = attempt_login(data.get("password", [""])[0])
            if token:
                self.redirect("/", session_token=token)
            else:
                self.send_html(login_page("Incorrect password."), 401)
            return

        if not self.require_auth(parsed.path):
            return

        if parsed.path == "/scan":
            data = self.form_data()
            try:
                job_id = start_scan_job(
                    data.get("disk_id", [""])[0],
                    data.get("root_path", [""])[0],
                )
                self.redirect(f"/scan/status?{urlencode({'id': job_id})}")
            except (ValueError, OSError) as exc:
                self.send_html(scan_page(str(exc)), 400)
        elif parsed.path == "/scan/cancel":
            data = self.form_data()
            job_id = data.get("job_id", [""])[0]
            cancel_scan_job(job_id)
            self.redirect(f"/scan/status?{urlencode({'id': job_id})}")
        elif parsed.path == "/disks/remove":
            data = self.form_data()
            disk_id = normalize_disk_id(data.get("disk_id", [""])[0])
            supplied_token = data.get("confirm_token", [""])[0]
            expected_token = disk_delete_token(self.session_token(), "")
            error = ""
            if not hmac.compare_digest(supplied_token, expected_token):
                error = "Confirmation expired or is invalid."
            elif not password_matches(data.get("password", [""])[0]):
                error = "Incorrect catalog password."
            if error:
                self.send_html(
                    disk_remove_page(self.session_token(), error, disk_id),
                    400,
                )
                return
            try:
                remove_disk_catalog(disk_id)
                self.redirect(f"/disks?{urlencode({'removed': disk_id})}")
            except (ValueError, OSError, sqlite3.Error) as exc:
                self.send_html(
                    disk_remove_page(self.session_token(), str(exc), disk_id),
                    400,
                )
        else:
            self.send_html(layout("Not Found", "<section><h2>Page not found</h2></section>"), 404)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{now_text()}] {self.address_string()} {format % args}")


def main() -> None:
    ensure_dirs()
    get_conn().close()
    recover_interrupted_scans()
    folder_count = ensure_folder_catalog()
    file_count, folder_count = ensure_search_catalog()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Disk Catalog is running at http://{HOST}:{PORT}")
    print(f"Search catalog ready with {file_count:,} files and {folder_count:,} folders.")
    print("Stage 2: login, dashboard, disk list, scan history, duplicates, export, backup.")
    print("Press Ctrl+C to stop.")
    server.serve_forever()


if __name__ == "__main__":
    main()
