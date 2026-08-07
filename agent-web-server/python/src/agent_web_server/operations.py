"""Verified online backup and restore operations for SQLite operator state."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import ssl
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


BACKUP_MANIFEST_SCHEMA = "agent-web-sqlite-backup/1"
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_backup_bundle(
    databases: Mapping[str, str | Path],
    destination: str | Path,
) -> dict[str, Any]:
    """Create verified online SQLite snapshots without overwriting a bundle."""

    if not databases:
        raise ValueError("at least one SQLite database is required")
    destination_path = Path(destination).resolve()
    if destination_path.exists():
        raise FileExistsError(f"refusing to overwrite backup: {destination_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    staging = destination_path.with_name(
        f".{destination_path.name}.{uuid4().hex}.staging"
    )
    staging.mkdir()
    records: dict[str, dict[str, Any]] = {}
    try:
        seen: set[Path] = set()
        for name, raw_source in sorted(databases.items()):
            if not _NAME.fullmatch(name):
                raise ValueError(f"invalid database name: {name!r}")
            source = Path(raw_source).resolve(strict=True)
            if source in seen:
                raise ValueError("the same SQLite database was supplied more than once")
            seen.add(source)
            if not source.is_file():
                raise ValueError(f"SQLite source is not a file: {source}")
            snapshot_name = f"{name}.sqlite3"
            snapshot = staging / snapshot_name
            _online_backup(source, snapshot)
            metadata = inspect_sqlite(snapshot)
            records[name] = {
                "sourceName": source.name,
                "backupFile": snapshot_name,
                "sha256": _sha256_file(snapshot),
                "bytes": snapshot.stat().st_size,
                "userVersion": metadata["userVersion"],
                "pageCount": metadata["pageCount"],
            }
        manifest = {
            "schema": BACKUP_MANIFEST_SCHEMA,
            "createdAt": _utc_now(),
            "databases": records,
        }
        _exclusive_write_json(staging / "manifest.json", manifest)
        verify_backup_bundle(staging)
        os.replace(staging, destination_path)
        return manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def create_coordinated_backup_bundle(
    databases: Mapping[str, str | Path],
    destination: str | Path,
    *,
    maintenance_url: str | Sequence[str],
    operator_token: str,
    ca_file: str | Path | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Drain HTTP mutations, snapshot all databases, and always release writes."""

    raw_urls = [maintenance_url] if isinstance(maintenance_url, str) else list(
        maintenance_url
    )
    if not raw_urls:
        raise ValueError("at least one maintenance URL is required")
    origins = list(dict.fromkeys(_maintenance_origin(value) for value in raw_urls))
    if len(operator_token.encode("utf-8")) < 32:
        raise ValueError("operator token must contain at least 32 bytes")
    context = ssl.create_default_context(
        cafile=str(ca_file) if ca_file is not None else None
    )
    entered: list[str] = []
    try:
        for origin in origins:
            entered.append(origin)
            _maintenance_call(origin, "enter", operator_token, context, timeout)
    except BaseException as original:
        release_errors = _release_maintenance(
            entered, operator_token, context, timeout
        )
        if release_errors:
            original.add_note(
                "maintenance release also failed; operator intervention required: "
                + "; ".join(release_errors)
            )
        raise
    try:
        manifest = create_backup_bundle(databases, destination)
    except BaseException as original:
        release_errors = _release_maintenance(
            entered, operator_token, context, timeout
        )
        if release_errors:
            original.add_note(
                "maintenance release also failed; operator intervention required: "
                + "; ".join(release_errors)
            )
        raise
    release_errors = _release_maintenance(entered, operator_token, context, timeout)
    if release_errors:
        raise RuntimeError(
            "backup succeeded but one or more replicas remain in maintenance: "
            + "; ".join(release_errors)
        )
    return {
        "schema": "agent-web-coordinated-backup/1",
        "maintenanceOrigins": origins,
        "writesReleased": True,
        "backup": manifest,
    }


def verify_backup_bundle(bundle: str | Path) -> dict[str, Any]:
    """Verify manifest containment, digests, and SQLite integrity."""

    root = Path(bundle).resolve(strict=True)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != (
        BACKUP_MANIFEST_SCHEMA
    ):
        raise ValueError("unsupported backup manifest")
    databases = manifest.get("databases")
    if not isinstance(databases, dict) or not databases:
        raise ValueError("backup manifest contains no databases")
    expected_files = {"manifest.json"}
    for name, record in databases.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("backup manifest contains an invalid database name")
        if not isinstance(record, dict):
            raise ValueError("backup manifest database record must be an object")
        filename = record.get("backupFile")
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise ValueError("backup database filename is unsafe")
        expected_files.add(filename)
        snapshot = (root / filename).resolve(strict=True)
        if not snapshot.is_relative_to(root) or not snapshot.is_file():
            raise ValueError("backup database escapes its bundle")
        if _sha256_file(snapshot) != record.get("sha256"):
            raise ValueError(f"backup digest mismatch: {name}")
        if snapshot.stat().st_size != record.get("bytes"):
            raise ValueError(f"backup size mismatch: {name}")
        metadata = inspect_sqlite(snapshot)
        if metadata["userVersion"] != record.get("userVersion"):
            raise ValueError(f"backup schema version mismatch: {name}")
    actual_files = {
        path.name for path in root.iterdir() if path.is_file()
    }
    if actual_files != expected_files:
        raise ValueError("backup bundle contains untracked or missing files")
    return manifest


def restore_backup_bundle(
    bundle: str | Path,
    destination: str | Path,
) -> dict[str, Path]:
    """Restore a verified bundle into a new directory, never over existing data."""

    manifest = verify_backup_bundle(bundle)
    bundle_path = Path(bundle).resolve(strict=True)
    destination_path = Path(destination).resolve()
    if destination_path.exists():
        raise FileExistsError(f"refusing to overwrite restore target: {destination_path}")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    staging = destination_path.with_name(
        f".{destination_path.name}.{uuid4().hex}.staging"
    )
    staging.mkdir()
    restored: dict[str, Path] = {}
    try:
        for name, record in manifest["databases"].items():
            source = bundle_path / record["backupFile"]
            target = staging / record["backupFile"]
            shutil.copyfile(source, target)
            _fsync_file(target)
            if _sha256_file(target) != record["sha256"]:
                raise ValueError(f"restored database digest mismatch: {name}")
            inspect_sqlite(target)
            restored[name] = destination_path / target.name
        _exclusive_write_json(staging / "manifest.json", manifest)
        _fsync_directory(staging)
        os.replace(staging, destination_path)
        return restored
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def inspect_sqlite(database: str | Path) -> dict[str, int]:
    """Fail unless a SQLite file passes quick and full integrity checks."""

    path = Path(database).resolve(strict=True)
    uri = f"{path.as_uri()}?mode=ro&immutable=1"
    connection = sqlite3.connect(uri, uri=True)
    try:
        quick = connection.execute("PRAGMA quick_check").fetchall()
        full = connection.execute("PRAGMA integrity_check").fetchall()
        if quick != [("ok",)] or full != [("ok",)]:
            raise ValueError(f"SQLite integrity check failed: {path}")
        return {
            "userVersion": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "pageCount": int(connection.execute("PRAGMA page_count").fetchone()[0]),
        }
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"invalid SQLite database: {path}") from exc
    finally:
        connection.close()


def _online_backup(source: Path, destination: Path) -> None:
    source_connection = sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    _fsync_file(destination)


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exclusive_write_json(path: Path, value: Mapping[str, Any]) -> None:
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _maintenance_origin(value: str) -> str:
    parsed = urlsplit(value.rstrip("/"))
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("maintenance URL must be an HTTPS origin")
    return f"https://{parsed.netloc}"


def _maintenance_call(
    origin: str,
    action: str,
    token: str,
    context: ssl.SSLContext,
    timeout: float,
) -> dict[str, Any]:
    if action not in {"enter", "exit"}:
        raise ValueError("invalid maintenance action")
    request = Request(
        f"{origin}/ops/maintenance/{action}",
        data=b"",
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Length": "0",
        },
    )
    with urlopen(request, context=context, timeout=timeout) as response:
        body = response.read(64 * 1024 + 1)
        if len(body) > 64 * 1024:
            raise ValueError("maintenance response is too large")
        if response.status != 200:
            raise RuntimeError(
                f"maintenance {action} returned HTTP {response.status}"
            )
    document = json.loads(body)
    if not isinstance(document, dict):
        raise ValueError("maintenance response must be a JSON object")
    expected = action == "enter"
    if document.get("maintenance") is not expected:
        raise RuntimeError(f"maintenance {action} did not reach expected state")
    return document


def _release_maintenance(
    origins: Sequence[str],
    token: str,
    context: ssl.SSLContext,
    timeout: float,
) -> list[str]:
    errors: list[str] = []
    for origin in reversed(origins):
        try:
            _maintenance_call(origin, "exit", token, context, timeout)
        except Exception as exc:
            errors.append(f"{origin}: {exc}")
    return errors
