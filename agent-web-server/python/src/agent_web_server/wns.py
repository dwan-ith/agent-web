"""Durable WNS handle publication for Agent Web operators."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from anp.wns import (
    HandleResolutionDocument,
    HandleStatus,
    build_resolution_url,
    normalize_handle,
    validate_handle,
    validate_local_part,
)
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse


WNS_SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def did_wba_hostname(did: str) -> str:
    """Extract the DNS hostname from a DID-WBA identifier, ignoring its port."""

    if not isinstance(did, str) or not did.startswith("did:wba:"):
        raise ValueError("WNS bindings require a did:wba DID")
    parts = did.split(":", 3)
    if len(parts) < 4 or not parts[2]:
        raise ValueError("DID-WBA identifier has no authority")
    authority = unquote(parts[2])
    parsed = urlsplit(f"//{authority}")
    if parsed.hostname is None:
        raise ValueError("DID-WBA identifier has no hostname")
    return parsed.hostname.lower()


class HandleStore:
    """A transactional WNS mapping store with append-only history."""

    def __init__(self, database: str | Path, *, provider_domain: str) -> None:
        _, normalized_domain = validate_handle(f"probe.{provider_domain}")
        self.provider_domain = normalized_domain
        self.database = str(database)
        self._lock = RLock()
        self._connection = sqlite3.connect(
            self.database,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        if self.database != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version > WNS_SCHEMA_VERSION:
                raise RuntimeError(
                    f"WNS database schema {version} is newer than this runtime"
                )
            if version == 0:
                self._connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE IF NOT EXISTS handle_bindings (
                        handle TEXT PRIMARY KEY,
                        local_part TEXT NOT NULL UNIQUE,
                        did TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('active', 'suspended', 'revoked')
                        ),
                        binding_generation TEXT NOT NULL,
                        updated TEXT NOT NULL,
                        version_id TEXT NOT NULL UNIQUE
                    );
                    CREATE TABLE IF NOT EXISTS handle_history (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        handle TEXT NOT NULL,
                        did TEXT NOT NULL,
                        status TEXT NOT NULL,
                        binding_generation TEXT NOT NULL,
                        updated TEXT NOT NULL,
                        version_id TEXT NOT NULL UNIQUE,
                        event TEXT NOT NULL
                    );
                    PRAGMA user_version = 1;
                    COMMIT;
                    """
                )

    def bind(
        self,
        handle: str,
        did: str,
        *,
        expected_did: str | None = None,
    ) -> HandleResolutionDocument:
        """Create or rotate a binding with optimistic concurrency protection."""

        normalized = normalize_handle(handle)
        local_part, domain = validate_handle(normalized)
        if domain != self.provider_domain:
            raise ValueError("handle domain does not match this WNS provider")
        if did_wba_hostname(did) != domain:
            raise ValueError("handle domain does not match DID-WBA hostname")

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM handle_bindings WHERE handle = ?",
                    (normalized,),
                ).fetchone()
                if row is None:
                    if expected_did is not None:
                        raise ValueError("cannot rotate a handle that is not registered")
                    generation = "1"
                    event = "registered"
                else:
                    if row["status"] == HandleStatus.REVOKED.value:
                        raise ValueError("revoked handles cannot be rebound")
                    if row["did"] == did and row["status"] == HandleStatus.ACTIVE.value:
                        self._connection.execute("COMMIT")
                        return self._document(row)
                    if expected_did is None or row["did"] != expected_did:
                        raise ValueError(
                            "current DID must be supplied exactly when rotating a handle"
                        )
                    generation = str(int(row["binding_generation"]) + 1)
                    event = "rotated"

                updated = utc_now()
                version_id = uuid4().hex
                values = (
                    normalized,
                    local_part,
                    did,
                    HandleStatus.ACTIVE.value,
                    generation,
                    updated,
                    version_id,
                )
                self._connection.execute(
                    """
                    INSERT INTO handle_bindings (
                        handle, local_part, did, status, binding_generation,
                        updated, version_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(handle) DO UPDATE SET
                        did = excluded.did,
                        status = excluded.status,
                        binding_generation = excluded.binding_generation,
                        updated = excluded.updated,
                        version_id = excluded.version_id
                    """,
                    values,
                )
                self._append_history(values, event)
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        document = self.resolve(local_part)
        assert document is not None
        return document

    def set_status(
        self,
        handle: str,
        status: HandleStatus | str,
        *,
        expected_generation: str,
    ) -> HandleResolutionDocument:
        """Suspend, reactivate, or irrevocably revoke a binding."""

        normalized = normalize_handle(handle)
        requested = HandleStatus(status)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM handle_bindings WHERE handle = ?",
                    (normalized,),
                ).fetchone()
                if row is None:
                    raise KeyError(normalized)
                if row["binding_generation"] != expected_generation:
                    raise ValueError("binding generation changed")
                if row["status"] == HandleStatus.REVOKED.value:
                    raise ValueError("revoked handles cannot change status")
                if row["status"] == requested.value:
                    self._connection.execute("COMMIT")
                    return self._document(row)
                generation = str(int(row["binding_generation"]) + 1)
                updated = utc_now()
                version_id = uuid4().hex
                values = (
                    row["handle"],
                    row["local_part"],
                    row["did"],
                    requested.value,
                    generation,
                    updated,
                    version_id,
                )
                self._connection.execute(
                    """
                    UPDATE handle_bindings
                    SET status = ?, binding_generation = ?, updated = ?, version_id = ?
                    WHERE handle = ?
                    """,
                    (requested.value, generation, updated, version_id, normalized),
                )
                self._append_history(values, f"status:{requested.value}")
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        document = self.resolve(row["local_part"])
        assert document is not None
        return document

    def resolve(self, local_part: str) -> HandleResolutionDocument | None:
        if not validate_local_part(local_part) or local_part != local_part.lower():
            return None
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM handle_bindings WHERE local_part = ?",
                (local_part,),
            ).fetchone()
        return None if row is None else self._document(row)

    def history(self, handle: str) -> list[dict[str, Any]]:
        normalized = normalize_handle(handle)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT handle, did, status, binding_generation, updated,
                       version_id, event
                FROM handle_history WHERE handle = ? ORDER BY sequence
                """,
                (normalized,),
            ).fetchall()
        return [dict(row) for row in rows]

    def integrity_check(self) -> bool:
        with self._lock:
            return self._connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _append_history(self, values: tuple[Any, ...], event: str) -> None:
        handle, _local_part, did, status, generation, updated, version_id = values
        self._connection.execute(
            """
            INSERT INTO handle_history (
                handle, did, status, binding_generation, updated, version_id, event
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (handle, did, status, generation, updated, version_id, event),
        )

    @staticmethod
    def _document(row: Mapping[str, Any]) -> HandleResolutionDocument:
        return HandleResolutionDocument.model_validate(
            {
                "handle": row["handle"],
                "did": row["did"],
                "status": row["status"],
                "binding_generation": row["binding_generation"],
                "updated": row["updated"],
                "versionId": row["version_id"],
                "ttl": 300,
            }
        )


def mount_handle_provider(app: FastAPI, store: HandleStore) -> None:
    """Mount the WNS 1.1 well-known Handle Resolution Endpoint."""

    @app.get("/.well-known/handle/{local_part}", include_in_schema=False)
    async def resolve_handle(local_part: str) -> JSONResponse:
        document = store.resolve(local_part)
        if document is None:
            raise HTTPException(status_code=404, detail="handle not found")
        if document.status == HandleStatus.REVOKED:
            return JSONResponse(
                document.model_dump(mode="json", exclude_none=True),
                status_code=410,
                headers={"Cache-Control": "public, max-age=300"},
            )
        return JSONResponse(
            document.model_dump(mode="json", exclude_none=True),
            headers={"Cache-Control": f"public, max-age={document.ttl or 300}"},
        )


def mount_identity_handle(
    app: FastAPI,
    identity: Any,
    database: str | Path,
) -> HandleStore:
    """Mount the exact handle declared by an identity, failing on stale state."""

    handle = identity.handle
    if handle is None:
        raise ValueError("publisher identity does not declare an exact WNS handle")
    local_part, domain = validate_handle(handle)
    store = HandleStore(database, provider_domain=domain)
    try:
        existing = store.resolve(local_part)
        if existing is None:
            store.bind(handle, identity.did)
        elif existing.did != identity.did or existing.status != HandleStatus.ACTIVE:
            raise ValueError(
                "WNS database is not actively bound to this identity; "
                "perform an explicit operator rotation or status change"
            )
        mount_handle_provider(app, store)
        return store
    except Exception:
        store.close()
        raise
