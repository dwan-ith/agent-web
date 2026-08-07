"""Operator-managed, deny-by-default authorization for Agent Web RPC actions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


ScopeType = Literal["exact", "prefix"]
ResourceResolver = Callable[[Mapping[str, Any]], str]
_ACTION_PATTERN = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("authorization timestamps must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("authorization timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _validate_subject(subject_did: str) -> str:
    if not isinstance(subject_did, str) or not subject_did.startswith("did:wba:"):
        raise ValueError("authorization subject must be an exact did:wba identifier")
    if len(subject_did) > 2048:
        raise ValueError("authorization subject is too long")
    return subject_did


def _validate_action(action: str) -> str:
    if not isinstance(action, str) or not _ACTION_PATTERN.fullmatch(action):
        raise ValueError("authorization action has an invalid name")
    return action


def _validate_resource(resource: str, scope_type: ScopeType) -> str:
    if not isinstance(resource, str) or len(resource) > 4096:
        raise ValueError("authorization resource must be a bounded HTTPS URL")
    parsed = urlsplit(resource)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        raise ValueError("authorization resource must be an absolute HTTPS URL")
    if parsed.fragment:
        raise ValueError("authorization resource must not contain a fragment")
    if scope_type == "prefix" and not resource.endswith("/"):
        raise ValueError("prefix authorization resources must end with '/'")
    return resource


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """The recorded result of one authorization check."""

    allowed: bool
    reason: str
    grant_id: str | None = None


@dataclass(frozen=True, slots=True)
class RpcAuthorizationRule:
    """Map one protected JSON-RPC method to an action and resource scope."""

    action: str
    resource: ResourceResolver
    consume: bool = True

    def __post_init__(self) -> None:
        _validate_action(self.action)


class AuthorizationStore:
    """Durable grants and audit records shared safely by server workers.

    No wildcard subjects or actions are supported. An operator must issue a
    grant for the exact authenticated DID and action. Resource scopes are
    either exact URLs or explicit URL-directory prefixes.
    """

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
            raise RuntimeError("authorization database is newer than this runtime")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS authorization_grants (
                grant_id TEXT PRIMARY KEY,
                subject_did TEXT NOT NULL,
                action TEXT NOT NULL,
                scope_type TEXT NOT NULL CHECK (scope_type IN ('exact', 'prefix')),
                resource TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                max_uses INTEGER CHECK (max_uses IS NULL OR max_uses > 0),
                uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
                revoked_at TEXT,
                note TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS authorization_grant_lookup
                ON authorization_grants(subject_did, action, revoked_at);

            CREATE TABLE IF NOT EXISTS authorization_audit (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_did TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
                reason TEXT NOT NULL,
                grant_id TEXT,
                decided_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS authorization_audit_subject_time
                ON authorization_audit(subject_did, decided_at);
            PRAGMA user_version = 1;
            """
        )

    def grant(
        self,
        *,
        subject_did: str,
        action: str,
        resource: str,
        scope_type: ScopeType = "exact",
        expires_at: datetime | None = None,
        max_uses: int | None = None,
        note: str = "",
    ) -> str:
        """Issue a new grant and return its opaque identifier."""

        subject_did = _validate_subject(subject_did)
        action = _validate_action(action)
        if scope_type not in {"exact", "prefix"}:
            raise ValueError("scope_type must be 'exact' or 'prefix'")
        resource = _validate_resource(resource, scope_type)
        if max_uses is not None and (
            isinstance(max_uses, bool)
            or not isinstance(max_uses, int)
            or max_uses < 1
        ):
            raise ValueError("max_uses must be a positive integer")
        if len(note) > 1000:
            raise ValueError("authorization grant note is too long")
        grant_id = uuid4().hex
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO authorization_grants (
                    grant_id, subject_did, action, scope_type, resource,
                    issued_at, expires_at, max_uses, note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant_id,
                    subject_did,
                    action,
                    scope_type,
                    resource,
                    _timestamp(_utc_now()),
                    _timestamp(expires_at) if expires_at else None,
                    max_uses,
                    note,
                ),
            )
        return grant_id

    def revoke(self, grant_id: str) -> bool:
        """Revoke a grant once. Return false when it is absent/already revoked."""

        if not isinstance(grant_id, str) or not grant_id:
            raise ValueError("grant_id is required")
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE authorization_grants
                SET revoked_at = ?
                WHERE grant_id = ? AND revoked_at IS NULL
                """,
                (_timestamp(_utc_now()), grant_id),
            )
            return cursor.rowcount == 1

    def authorize(
        self,
        *,
        subject_did: str,
        action: str,
        resource: str,
        consume: bool = True,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Atomically choose and optionally consume a matching active grant."""

        subject_did = _validate_subject(subject_did)
        action = _validate_action(action)
        resource = _validate_resource(resource, "exact")
        decision_time = now or _utc_now()
        decided_at = _timestamp(decision_time)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                rows = self._connection.execute(
                    """
                    SELECT * FROM authorization_grants
                    WHERE subject_did = ? AND action = ? AND revoked_at IS NULL
                    ORDER BY
                        CASE scope_type WHEN 'exact' THEN 0 ELSE 1 END,
                        LENGTH(resource) DESC,
                        issued_at ASC
                    """,
                    (subject_did, action),
                ).fetchall()
                matching_scope = False
                expired = False
                exhausted = False
                selected: sqlite3.Row | None = None
                for row in rows:
                    matches = (
                        resource == row["resource"]
                        if row["scope_type"] == "exact"
                        else resource.startswith(row["resource"])
                    )
                    if not matches:
                        continue
                    matching_scope = True
                    if row["expires_at"] and decision_time >= _parse_timestamp(
                        row["expires_at"]
                    ):
                        expired = True
                        continue
                    if (
                        row["max_uses"] is not None
                        and row["uses"] >= row["max_uses"]
                    ):
                        exhausted = True
                        continue
                    selected = row
                    break

                if selected is not None:
                    if consume:
                        self._connection.execute(
                            """
                            UPDATE authorization_grants
                            SET uses = uses + 1
                            WHERE grant_id = ?
                            """,
                            (selected["grant_id"],),
                        )
                    decision = AuthorizationDecision(
                        True,
                        "grant allowed",
                        selected["grant_id"],
                    )
                elif exhausted:
                    decision = AuthorizationDecision(False, "grant exhausted")
                elif expired:
                    decision = AuthorizationDecision(False, "grant expired")
                elif matching_scope:
                    decision = AuthorizationDecision(False, "no active grant")
                else:
                    decision = AuthorizationDecision(False, "no matching grant")

                self._connection.execute(
                    """
                    INSERT INTO authorization_audit (
                        subject_did, action, resource, allowed, reason,
                        grant_id, decided_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        subject_did,
                        action,
                        resource,
                        int(decision.allowed),
                        decision.reason,
                        decision.grant_id,
                        decided_at,
                    ),
                )
                self._connection.execute("COMMIT")
                return decision
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def list_grants(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT grant_id, subject_did, action, scope_type, resource,
                       issued_at, expires_at, max_uses, uses, revoked_at, note
                FROM authorization_grants
                ORDER BY issued_at, grant_id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def audit_log(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("authorization audit limit must be between 1 and 1000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, subject_did, action, resource, allowed,
                       reason, grant_id, decided_at
                FROM authorization_audit
                ORDER BY sequence DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {**dict(row), "allowed": bool(row["allowed"])}
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def integrity_check(self) -> bool:
        with self._lock:
            result = self._connection.execute("PRAGMA quick_check").fetchall()
            return len(result) == 1 and result[0][0] == "ok"


def install_rpc_authorization(
    app: FastAPI,
    store: AuthorizationStore,
    *,
    rpc_path: str,
    rules: Mapping[str, RpcAuthorizationRule],
) -> None:
    """Protect selected JSON-RPC methods with operator-issued grants.

    Install this middleware before the authentication middleware. Starlette
    runs the last-added middleware first, allowing authentication to attach the
    verified DID before this policy executes.
    """

    if not rpc_path.startswith("/"):
        raise ValueError("rpc_path must be an absolute path")
    protected = dict(rules)

    @app.middleware("http")
    async def authorize_rpc(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method != "POST" or request.url.path != rpc_path:
            return await call_next(request)
        try:
            payload = json.loads((await request.body()).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return await call_next(request)
        if isinstance(payload, list):
            if any(
                isinstance(item, dict) and item.get("method") in protected
                for item in payload
            ):
                return _rpc_error(
                    None,
                    -32600,
                    "Protected actions do not support batch requests",
                )
            return await call_next(request)
        if not isinstance(payload, dict):
            return await call_next(request)
        rule = protected.get(payload.get("method"))
        if rule is None:
            return await call_next(request)
        subject_did = getattr(request.state, "did", None)
        if not isinstance(subject_did, str):
            return _rpc_error(
                payload.get("id"),
                -32002,
                "Authorization denied",
                {"reason": "authenticated DID required"},
            )
        params = payload.get("params", {})
        if not isinstance(params, dict):
            return _rpc_error(
                payload.get("id"),
                -32602,
                "Invalid params",
            )
        try:
            resource = rule.resource(params)
            decision = store.authorize(
                subject_did=subject_did,
                action=rule.action,
                resource=resource,
                consume=rule.consume,
            )
        except (KeyError, TypeError, ValueError):
            return _rpc_error(
                payload.get("id"),
                -32602,
                "Invalid params",
            )
        request.state.authorization_decision = decision
        if not decision.allowed:
            return _rpc_error(
                payload.get("id"),
                -32002,
                "Authorization denied",
                {"reason": decision.reason},
            )
        return await call_next(request)


def _rpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        status_code=200,
        content={"jsonrpc": "2.0", "error": error, "id": request_id},
        headers={"Cache-Control": "no-store"},
    )
