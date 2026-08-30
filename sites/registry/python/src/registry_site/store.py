"""Durable, provenance-preserving storage for verified Agent Web resources."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any, Mapping

import jcs
from libagentweb import validate_resource


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _query_terms(query: str) -> list[str]:
    """Split a query into lower-case alphanumeric terms for scoring."""

    return [
        term
        for term in query.casefold().replace("-", " ").split()
        if term
    ][:16]


def _type_words(values: list[Any]) -> set[str]:
    """Extract comparable words from semantic type identifiers.

    ``WeatherForecast`` yields ``{weatherforecast, weather, forecast}`` so a
    query term can match a single word of a compound type without matching
    arbitrary substrings of unrelated names.
    """

    words: set[str] = set()
    for value in values:
        text = str(value)
        words.add(text.casefold())
        for part in re.split(r"[-_\s]+", text):
            if not part:
                continue
            words.add(part.casefold())
            # Split camelCase boundaries before folding: Weather -> weather.
            words.update(
                match.group(0).casefold()
                for match in re.finditer(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z0-9])", part)
            )
    return words


def _freshness_tiebreak(row: sqlite3.Row) -> int:
    """Prefer fresher sources on equal relevance, deterministically."""

    try:
        updated = datetime.fromisoformat(
            str(row["source_updated_at"]).replace("Z", "+00:00")
        )
        stamp = int(updated.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S"))
    except ValueError:
        stamp = 0
    # Negated so newer (larger) stamps sort first in ascending key order.
    return -stamp


class RegistryStore:
    """SQLite index populated only from fully verified site snapshots."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database),
            check_same_thread=False,
            isolation_level=None,
            timeout=30.0,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA busy_timeout = 30000")
        schema_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version > 3:
            self._connection.close()
            raise RuntimeError("registry database is newer than this runtime")
        if schema_version < 2:
            # Version 1 databases only lacked the generation counter; the
            # table set is otherwise identical, so upgrade in place.
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

                CREATE TABLE IF NOT EXISTS registry_feed_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    feed_generation INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO registry_feed_state (id, feed_generation)
                    VALUES (1, 0);
                PRAGMA user_version = 2;
                """
            )
        if schema_version < 3:
            # Version 3 adds the per-site snapshot digest so an unchanged
            # re-verified snapshot no longer churns the federation feed
            # generation. Existing rows digest as NULL, which forces exactly
            # one more generation advance on their next accepted snapshot.
            columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(registry_sites)"
                ).fetchall()
            }
            if "content_digest" not in columns:
                self._connection.execute(
                    "ALTER TABLE registry_sites ADD COLUMN content_digest TEXT"
                )
            self._connection.execute("PRAGMA user_version = 3")

    def replace_verified_site(
        self,
        *,
        agent_description_url: str | None = None,
        discovery_url: str | None = None,
        description: Mapping[str, Any],
        resources: list[Mapping[str, Any]],
        verified_at: str | None = None,
    ) -> int:
        """Atomically replace one publisher snapshot after proof verification."""

        endpoint = discovery_url or agent_description_url
        if endpoint is None or (discovery_url and agent_description_url):
            raise ValueError("provide exactly one verified discovery endpoint")

        publisher = description.get("publisher", description.get("identifier"))
        if not isinstance(publisher, str) or not (
            publisher.startswith("https://")
            or publisher.startswith("did:web:")
            or publisher.startswith("did:wba:")
        ):
            raise ValueError("verified publisher descriptor has no supported identifier")
        name = description.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("verified publisher descriptor has no name")
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
                    endpoint,
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
        # Content-address the snapshot so re-verifying an unchanged site
        # refreshes verified_at without churning the federation generation.
        snapshot_digest = sha256(
            (
                description_json
                + "\n"
                + "\n".join(sorted(row[6] for row in prepared))
            ).encode("utf-8")
        ).hexdigest()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    """
                    SELECT publisher_did, content_digest
                    FROM registry_sites
                    WHERE agent_description_url = ?
                    """,
                    (endpoint,),
                ).fetchone()
                snapshot_changed = (
                    existing is None
                    or existing["publisher_did"] != publisher
                    or existing["content_digest"] != snapshot_digest
                )
                self._connection.execute(
                    """
                    INSERT INTO registry_sites (
                        agent_description_url, publisher_did, name,
                        description_json, verified_at, content_digest
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(agent_description_url) DO UPDATE SET
                        publisher_did = excluded.publisher_did,
                        name = excluded.name,
                        description_json = excluded.description_json,
                        verified_at = excluded.verified_at,
                        content_digest = excluded.content_digest
                    """,
                    (
                        endpoint,
                        publisher,
                        name,
                        description_json,
                        timestamp,
                        snapshot_digest,
                    ),
                )
                self._connection.execute(
                    """
                    DELETE FROM registry_resources
                    WHERE agent_description_url = ?
                    """,
                    (endpoint,),
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
                if snapshot_changed:
                    # Only a real content or publisher change advances the
                    # advertised feed generation, inside the same transaction.
                    self._connection.execute(
                        """
                        UPDATE registry_feed_state
                        SET feed_generation = feed_generation + 1
                        WHERE id = 1
                        """
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return len(prepared)

    def feed_generation(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT feed_generation FROM registry_feed_state WHERE id = 1"
            ).fetchone()
        return int(row[0])

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
        result: list[dict[str, Any]] = []
        for row in rows:
            site = {
                "agentDescription": row["agent_description_url"],
                "discoveryUrl": row["agent_description_url"],
                "publisher": row["publisher_did"],
                "name": row["name"],
                "verifiedAt": row["verified_at"],
                "resourceCount": row["resource_count"],
            }
            if str(row["agent_description_url"]).endswith(
                "/.well-known/agent-web"
            ):
                site.pop("agentDescription")
            result.append(site)
        return result

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Rank matching resources by relevance over a bounded candidate set.

        Candidates are scanned in deterministic ``resource_url`` order and
        capped at 2000 rows so latency stays bounded; every candidate is
        scored before truncation to the requested limit.
        """

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
                ORDER BY resource_url
                LIMIT 2000
                """,
                (pattern, pattern, pattern, now),
            ).fetchall()
        terms = _query_terms(query)

        def score(row: sqlite3.Row) -> tuple[int, str]:
            name = str(row["name"]).casefold()
            summary = str(row["summary"]).casefold()
            type_words = _type_words(json.loads(row["types_json"]))
            total = 0
            for term in terms:
                if name == term:
                    total += 8
                elif name.startswith(term):
                    total += 6
                elif term in name:
                    total += 4
                elif term in summary:
                    total += 1
                if term and term in type_words:
                    # A resource whose semantic type contains the concept is
                    # worth more than one that merely mentions the term.
                    total += 2
            return (-total, _freshness_tiebreak(row), str(row["resource_url"]))

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
                "discoveryUrl": row["agent_description_url"],
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

    def prune_expired(self, *, now: str | None = None) -> int:
        """Delete resources past their advertised expiry and emptied sites.

        Expired entries were previously only hidden at query time; without a
        sweep they accumulated forever. Removing expired content changes the
        advertised feed, so the generation advances inside the transaction.
        """

        current = now or utc_now()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self._connection.execute(
                    """
                    DELETE FROM registry_resources
                    WHERE source_expires_at IS NOT NULL
                      AND source_expires_at <= ?
                    """,
                    (current,),
                )
                deleted = int(cursor.rowcount)
                if deleted:
                    self._connection.execute(
                        """
                        DELETE FROM registry_sites
                        WHERE agent_description_url NOT IN (
                            SELECT DISTINCT agent_description_url
                            FROM registry_resources
                        )
                        """
                    )
                    self._connection.execute(
                        """
                        UPDATE registry_feed_state
                        SET feed_generation = feed_generation + 1
                        WHERE id = 1
                        """
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return deleted

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
