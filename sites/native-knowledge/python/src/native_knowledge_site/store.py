"""Durable state for the native knowledge site."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Iterable, Mapping
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class KnowledgeStore:
    """Small SQLite system of record; resources are generated from this state."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database), check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS knowledge_topics (
                slug TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                body TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS knowledge_annotations (
                annotation_id TEXT PRIMARY KEY,
                topic_slug TEXT NOT NULL REFERENCES knowledge_topics(slug),
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS knowledge_annotations_topic_time
                ON knowledge_annotations(topic_slug, created_at);
            """
        )

    def seed(self, topics: Iterable[Mapping[str, str]]) -> int:
        """Insert initial operator-supplied content without replacing existing state."""

        prepared = []
        for topic in topics:
            slug = str(topic.get("slug", "")).strip()
            title = str(topic.get("title", "")).strip()
            summary = str(topic.get("summary", "")).strip()
            body = str(topic.get("body", "")).strip()
            if not slug or not title or not summary or not body:
                raise ValueError("topics require slug, title, summary, and body")
            if not all(character.islower() or character.isdigit() or character == "-" for character in slug):
                raise ValueError("topic slug must use lower-case letters, digits, and hyphens")
            prepared.append((slug, title, summary, body, _now()))
        with self._lock:
            before = self._connection.total_changes
            self._connection.executemany(
                """
                INSERT OR IGNORE INTO knowledge_topics
                    (slug, title, summary, body, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                prepared,
            )
            return self._connection.total_changes - before

    def topics(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM knowledge_topics ORDER BY slug"
            ).fetchall()
        return [dict(row) for row in rows]

    def topic(self, slug: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM knowledge_topics WHERE slug = ?", (slug,)
            ).fetchone()
        return dict(row) if row is not None else None

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        value = query.strip()
        if not value or len(value) > 200:
            raise ValueError("query must contain 1 to 200 characters")
        if isinstance(limit, bool) or limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        escaped = value.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM knowledge_topics
                WHERE lower(title) LIKE ? ESCAPE '\\'
                   OR lower(summary) LIKE ? ESCAPE '\\'
                   OR lower(body) LIKE ? ESCAPE '\\'
                ORDER BY slug LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_annotation(
        self, *, topic_slug: str, author: str, text: str
    ) -> dict[str, Any]:
        """Persist an authenticated caller annotation and return its record."""

        value = text.strip()
        if not value or len(value) > 4000:
            raise ValueError("annotation text must contain 1 to 4000 characters")
        if not author.startswith("https://") or len(author) > 2048:
            raise ValueError("annotation author must be an HTTPS controller")
        annotation_id = uuid4().hex
        created_at = _now()
        with self._lock:
            try:
                self._connection.execute(
                    """INSERT INTO knowledge_annotations
                       (annotation_id, topic_slug, author, text, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (annotation_id, topic_slug, author, value, created_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("annotation topic does not exist") from exc
        return {
            "annotation_id": annotation_id,
            "topic_slug": topic_slug,
            "author": author,
            "text": value,
            "created_at": created_at,
        }

    def annotation(self, annotation_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM knowledge_annotations WHERE annotation_id = ?",
                (annotation_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def annotations(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        with self._lock:
            rows = self._connection.execute(
                """SELECT * FROM knowledge_annotations
                   ORDER BY created_at DESC, annotation_id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA quick_check").fetchall()
        return len(result) == 1 and result[0][0] == "ok"

    def close(self) -> None:
        with self._lock:
            self._connection.close()
