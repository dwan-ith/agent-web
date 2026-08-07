"""Durable, provenance-preserving storage for verified Agent Web resources."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Mapping

import jcs
from libagentweb import validate_resource


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class RegistryStore:
    """SQLite index populated only from fully verified site snapshots."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database),
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        schema_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version > 1:
            self._connection.close()
            raise RuntimeError("registry database is newer than this runtime")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS registry_sites (
                agent_description_url TEXT PRIMARY KEY,
                publisher_did TEXT NOT NULL,
                name TEXT NOT NULL,
                description_json TEXT NOT NULL,
                verified_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS registry_site_publisher
                ON registry_sites(publisher_did);

            CREATE TABLE IF NOT EXISTS registry_resources (
                resource_url TEXT PRIMARY KEY,
                agent_description_url TEXT NOT NULL
                    REFERENCES registry_sites(agent_description_url)
                    ON DELETE CASCADE,
                publisher_did TEXT NOT NULL,
                name TEXT NOT NULL,
                summary TEXT NOT NULL,
                types_json TEXT NOT NULL,
                source_document_json TEXT NOT NULL,
                source_digest TEXT NOT NULL,
                source_updated_at TEXT NOT NULL,
                source_expires_at TEXT,
                verified_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS registry_resource_site
                ON registry_resources(agent_description_url);
            CREATE INDEX IF NOT EXISTS registry_resource_publisher
                ON registry_resources(publisher_did);
            PRAGMA user_version = 1;
            """
        )

    def replace_verified_site(
        self,
        *,
        agent_description_url: str,
        description: Mapping[str, Any],
        resources: list[Mapping[str, Any]],
        verified_at: str | None = None,
    ) -> int:
        """Atomically replace one publisher snapshot after proof verification."""

        publisher = description.get("identifier")
        if not isinstance(publisher, str) or not publisher.startswith("did:wba:"):
            raise ValueError("verified Agent Description has no did:wba identifier")
        name = description.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("verified Agent Description has no name")
        if not resources:
            raise ValueError("a verified site snapshot must contain resources")
        timestamp = verified_at or utc_now()
        prepared: list[tuple[Any, ...]] = []
        seen: set[str] = set()
        for value in resources:
            resource = validate_resource(value)
            if resource["provenance"]["publisher"] != publisher:
                raise ValueError(
                    "site snapshot contains a resource from another publisher"
                )
            resource_url = resource["@id"]
            if resource_url in seen:
                raise ValueError("site snapshot contains a duplicate resource URL")
            seen.add(resource_url)
            source_json = json.dumps(
                resource,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            prepared.append(
                (
                    resource_url,
                    agent_description_url,
                    publisher,
                    resource["name"],
                    resource["description"],
                    json.dumps(resource["@type"], separators=(",", ":")),
                    source_json,
                    sha256(jcs.canonicalize(resource)).hexdigest(),
                    resource["provenance"]["updatedAt"],
                    resource["provenance"].get("expiresAt"),
                    timestamp,
                )
            )

        description_json = json.dumps(
            dict(description),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    """
                    INSERT INTO registry_sites (
                        agent_description_url, publisher_did, name,
                        description_json, verified_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(agent_description_url) DO UPDATE SET
                        publisher_did = excluded.publisher_did,
                        name = excluded.name,
                        description_json = excluded.description_json,
                        verified_at = excluded.verified_at
                    """,
                    (
                        agent_description_url,
                        publisher,
                        name,
                        description_json,
                        timestamp,
                    ),
                )
                self._connection.execute(
                    """
                    DELETE FROM registry_resources
                    WHERE agent_description_url = ?
                    """,
                    (agent_description_url,),
                )
                self._connection.executemany(
                    """
                    INSERT INTO registry_resources (
                        resource_url, agent_description_url, publisher_did,
                        name, summary, types_json, source_document_json,
                        source_digest, source_updated_at, source_expires_at,
                        verified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    prepared,
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return len(prepared)

    def sites(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT s.agent_description_url, s.publisher_did, s.name,
                       s.verified_at, COUNT(r.resource_url) AS resource_count
                FROM registry_sites AS s
                LEFT JOIN registry_resources AS r
                    ON r.agent_description_url = s.agent_description_url
                GROUP BY s.agent_description_url
                ORDER BY lower(s.name), s.agent_description_url
                """
            ).fetchall()
        return [
            {
                "agentDescription": row["agent_description_url"],
                "publisher": row["publisher_did"],
                "name": row["name"],
                "verifiedAt": row["verified_at"],
                "resourceCount": row["resource_count"],
            }
            for row in rows
        ]

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        query = query.strip()
        if not query or len(query) > 200:
            raise ValueError("search query must contain 1 to 200 characters")
        if isinstance(limit, bool) or limit < 1 or limit > 100:
            raise ValueError("search limit must be between 1 and 100")
        escaped = (
            query.casefold()
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"
        now = utc_now()
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM registry_resources
                WHERE (
                    lower(name) LIKE ? ESCAPE '\\'
                    OR lower(summary) LIKE ? ESCAPE '\\'
                    OR lower(types_json) LIKE ? ESCAPE '\\'
                )
                AND (source_expires_at IS NULL OR source_expires_at > ?)
                LIMIT 500
                """,
                (pattern, pattern, pattern, now),
            ).fetchall()
        lowered = query.casefold()

        def score(row: sqlite3.Row) -> tuple[int, str]:
            name = str(row["name"]).casefold()
            summary = str(row["summary"]).casefold()
            points = (
                4 if name == lowered else
                3 if name.startswith(lowered) else
                2 if lowered in name else
                1 if lowered in summary else
                0
            )
            return (-points, str(row["resource_url"]))

        ordered = sorted(rows, key=score)[:limit]
        return [self._result(row) for row in ordered]

    def _result(self, row: sqlite3.Row) -> dict[str, Any]:
        source = json.loads(row["source_document_json"])
        return {
            "name": row["name"],
            "description": row["summary"],
            "types": json.loads(row["types_json"]),
            "source": {
                "resource": row["resource_url"],
                "agentDescription": row["agent_description_url"],
                "publisher": row["publisher_did"],
                "updatedAt": row["source_updated_at"],
                "expiresAt": row["source_expires_at"],
                "proof": source["proof"],
                "digest": {
                    "algorithm": "sha-256",
                    "canonicalization": "RFC8785-JCS",
                    "value": row["source_digest"],
                },
                "verifiedAt": row["verified_at"],
            },
        }

    def counts(self) -> dict[str, int]:
        with self._lock:
            sites = self._connection.execute(
                "SELECT COUNT(*) FROM registry_sites"
            ).fetchone()[0]
            resources = self._connection.execute(
                "SELECT COUNT(*) FROM registry_resources"
            ).fetchone()[0]
        return {"sites": int(sites), "resources": int(resources)}

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA quick_check").fetchall()
            return len(result) == 1 and result[0][0] == "ok"
