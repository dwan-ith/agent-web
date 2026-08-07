"""Durable canonical state for the Moltbook reference site."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any
from uuid import uuid4


class NotFoundError(LookupError):
    """Raised when a requested Moltbook object does not exist."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class MoltbookStore:
    """A tiny SQLite repository shared by ANP and the human Web bridge."""

    def __init__(self, database: str | Path = ":memory:", *, seed: bool = True) -> None:
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database),
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        schema_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version > 1:
            self._connection.close()
            raise RuntimeError("Moltbook database is newer than this runtime")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS threads (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS replies (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_actor_time
                ON audit_log(actor, created_at);
            PRAGMA user_version = 1;
            """
        )
        if seed and self.count_threads() == 0:
            self.create_thread(
                title="Welcome to Moltbook on Agent Web",
                body=(
                    "This discussion is an Agent Web resource. The forum page is "
                    "a human projection of the same canonical state."
                ),
                author="did:wba:localhost:system",
                rate_limit=None,
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA quick_check").fetchall()
            return len(result) == 1 and result[0][0] == "ok"

    def count_threads(self) -> int:
        with self._lock, closing(
            self._connection.execute("SELECT COUNT(*) AS count FROM threads")
        ) as cursor:
            return int(cursor.fetchone()["count"])

    def list_threads(self) -> list[dict[str, Any]]:
        with self._lock, closing(
            self._connection.execute(
                """
                SELECT t.*, COUNT(r.id) AS reply_count
                FROM threads AS t
                LEFT JOIN replies AS r ON r.thread_id = t.id
                GROUP BY t.id
                ORDER BY t.created_at DESC
                """
            )
        ) as cursor:
            return [dict(row) for row in cursor.fetchall()]

    def get_thread(self, thread_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM threads WHERE id = ?",
                (thread_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"Thread '{thread_id}' does not exist")
            replies = self._connection.execute(
                """
                SELECT id, body, author, created_at
                FROM replies
                WHERE thread_id = ?
                ORDER BY created_at ASC
                """,
                (thread_id,),
            ).fetchall()
        thread = dict(row)
        thread["replies"] = [dict(reply) for reply in replies]
        thread["reply_count"] = len(replies)
        return thread

    def create_thread(
        self,
        *,
        title: str,
        body: str,
        author: str,
        rate_limit: int | None = 30,
    ) -> dict[str, Any]:
        title = _required_text(title, "title", 200)
        body = _required_text(body, "body", 20_000)
        author = _required_text(author, "author", 300)
        thread_id = uuid4().hex[:12]
        timestamp = utc_now()
        with self._lock:
            self._enforce_rate_limit(author, rate_limit)
            self._connection.execute(
                """
                INSERT INTO threads (id, title, body, author, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (thread_id, title, body, author, timestamp, timestamp),
            )
            self._connection.execute(
                """
                INSERT INTO audit_log(actor, action, target_id, created_at)
                VALUES (?, 'create_thread', ?, ?)
                """,
                (author, thread_id, timestamp),
            )
        return self.get_thread(thread_id)

    def create_reply(
        self,
        *,
        thread_id: str,
        body: str,
        author: str,
        rate_limit: int | None = 60,
    ) -> dict[str, Any]:
        body = _required_text(body, "body", 20_000)
        author = _required_text(author, "author", 300)
        reply_id = uuid4().hex[:12]
        timestamp = utc_now()
        with self._lock:
            self._enforce_rate_limit(author, rate_limit)
            if (
                self._connection.execute(
                    "SELECT 1 FROM threads WHERE id = ?",
                    (thread_id,),
                ).fetchone()
                is None
            ):
                raise NotFoundError(f"Thread '{thread_id}' does not exist")
            self._connection.execute(
                """
                INSERT INTO replies (id, thread_id, body, author, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (reply_id, thread_id, body, author, timestamp),
            )
            self._connection.execute(
                "UPDATE threads SET updated_at = ? WHERE id = ?",
                (timestamp, thread_id),
            )
            self._connection.execute(
                """
                INSERT INTO audit_log(actor, action, target_id, created_at)
                VALUES (?, 'create_reply', ?, ?)
                """,
                (author, thread_id, timestamp),
            )
        return {
            "id": reply_id,
            "thread_id": thread_id,
            "body": body,
            "author": author,
            "created_at": timestamp,
        }

    def audit_log(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("audit log limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT actor, action, target_id, created_at
                FROM audit_log ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _enforce_rate_limit(self, actor: str, limit: int | None) -> None:
        if limit is None:
            return
        from datetime import timedelta

        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        ).isoformat().replace("+00:00", "Z")
        count = self._connection.execute(
            """
            SELECT COUNT(*) AS count FROM audit_log
            WHERE actor = ? AND created_at >= ?
            """,
            (actor, cutoff),
        ).fetchone()["count"]
        if int(count) >= limit:
            raise ValueError("mutation rate limit exceeded")


def _required_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field}' must be non-empty text")
    result = value.strip()
    if len(result) > limit:
        raise ValueError(f"'{field}' exceeds the {limit} character limit")
    return result
