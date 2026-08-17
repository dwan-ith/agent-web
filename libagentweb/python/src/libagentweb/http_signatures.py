"""Strict Agent Web profile of RFC 9421 HTTP Message Signatures.

The implementation intentionally supports one deterministic profile instead of
claiming to be a general Structured Fields or HTTP Message Signatures library.
That keeps independent implementations small while covering every security-
relevant part of a JSON action request.
"""

from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import re
import secrets
import sqlite3
from threading import RLock
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives.asymmetric import ed25519

from .signing import Ed25519Signer


HTTP_SIGNATURE_SECURITY = "http-message-signature"
CALLER_HEADER = "Agent-Web-Caller"
_LABEL = "agentweb"
_COMPONENTS = (
    "@method",
    "@target-uri",
    "content-digest",
    "content-type",
    "agent-web-caller",
)
_COMPONENT_LIST = " ".join(f'"{item}"' for item in _COMPONENTS)
_SIGNATURE_INPUT = re.compile(
    rf'^{_LABEL}=\({_COMPONENT_LIST}\);created=([0-9]{{1,15}});'
    r'expires=([0-9]{1,15});keyid="([^"\\]{1,2048})";'
    r'nonce="([A-Za-z0-9_-]{22,128})";alg="ed25519"$'
)
_SIGNATURE = re.compile(rf'^{_LABEL}=:([A-Za-z0-9+/]{{86}}==):$')
_CONTENT_DIGEST = re.compile(r"^sha-256=:([A-Za-z0-9+/]{43}=):$")


class HttpMessageSignatureError(ValueError):
    """An authenticated Agent Web HTTP request is missing or invalid."""


@dataclass(frozen=True, slots=True)
class AuthenticatedWebCaller:
    """Verified caller context safe for a publisher authorization decision."""

    controller: str
    key_id: str
    created: int
    expires: int
    nonce: str


class HttpSignatureReplayStore:
    """Atomic persistent nonce claims shared by publisher workers."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database), check_same_thread=False, isolation_level=None
        )
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_web_http_nonces (
                controller TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (controller, nonce)
            )
            """
        )

    def claim(
        self, controller: str, nonce: str, expires: int, *, now: int | None = None
    ) -> bool:
        current = now if now is not None else int(datetime.now(timezone.utc).timestamp())
        with self._lock:
            self._connection.execute(
                "DELETE FROM agent_web_http_nonces WHERE expires_at < ?", (current,)
            )
            try:
                self._connection.execute(
                    """INSERT INTO agent_web_http_nonces
                       (controller, nonce, expires_at) VALUES (?, ?, ?)""",
                    (controller, nonce, expires),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def integrity_check(self) -> bool:
        with self._lock:
            rows = self._connection.execute("PRAGMA quick_check").fetchall()
        return rows == [("ok",)]

    def close(self) -> None:
        with self._lock:
            self._connection.close()


def sign_agent_web_request(
    *,
    method: str,
    target_uri: str,
    body: bytes,
    content_type: str,
    caller: str,
    signer: Ed25519Signer,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Create RFC 9421 and RFC 9530 fields for one JSON action request."""

    normalized_method = _validate_method(method)
    normalized_uri = _validate_https_uri(target_uri)
    normalized_type = _validate_content_type(content_type)
    controller = _validate_controller(caller)
    _validate_key_id(signer.key_id, controller)
    issued = created if created is not None else int(datetime.now(timezone.utc).timestamp())
    expiration = expires if expires is not None else issued + 120
    if expiration <= issued or expiration - issued > 300:
        raise ValueError("HTTP signature lifetime must be between 1 and 300 seconds")
    nonce_value = nonce or secrets.token_urlsafe(24)
    if not re.fullmatch(r"[A-Za-z0-9_-]{22,128}", nonce_value):
        raise ValueError("HTTP signature nonce is invalid")
    content_digest = _content_digest(body)
    parameters = _signature_parameters(
        created=issued,
        expires=expiration,
        key_id=signer.key_id,
        nonce=nonce_value,
    )
    signature_base = _signature_base(
        method=normalized_method,
        target_uri=normalized_uri,
        content_digest=content_digest,
        content_type=normalized_type,
        caller=controller,
        parameters=parameters,
    )
    signature = signer.sign(signature_base.encode("ascii"))
    if len(signature) != 64:
        raise ValueError("Ed25519 signer returned a non-64-byte signature")
    return {
        "Content-Digest": content_digest,
        "Content-Type": normalized_type,
        CALLER_HEADER: controller,
        "Signature-Input": f"{_LABEL}={parameters}",
        "Signature": f"{_LABEL}=:{b64encode(signature).decode('ascii')}:",
    }


def verify_agent_web_request(
    *,
    method: str,
    target_uri: str,
    body: bytes,
    headers: Mapping[str, str],
    raw_headers: Sequence[tuple[bytes, bytes]] | None = None,
    controller_document: Mapping[str, object],
    replay_store: HttpSignatureReplayStore | None = None,
    now: int | None = None,
    clock_skew_seconds: int = 30,
) -> AuthenticatedWebCaller:
    """Verify the strict Agent Web request-signature profile and claim its nonce."""

    if raw_headers is not None:
        _reject_duplicate_security_headers(raw_headers)
    lowered = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    required = (
        "content-digest",
        "content-type",
        "agent-web-caller",
        "signature-input",
        "signature",
    )
    missing = [name for name in required if not lowered.get(name)]
    if missing:
        raise HttpMessageSignatureError(
            f"authenticated request is missing {', '.join(missing)}"
        )
    match = _SIGNATURE_INPUT.fullmatch(lowered["signature-input"])
    if match is None:
        raise HttpMessageSignatureError("Signature-Input is outside the Agent Web profile")
    created, expires = int(match.group(1)), int(match.group(2))
    key_id, nonce = match.group(3), match.group(4)
    current = now if now is not None else int(datetime.now(timezone.utc).timestamp())
    if expires <= created or expires - created > 300:
        raise HttpMessageSignatureError("signature lifetime is invalid")
    if created > current + clock_skew_seconds:
        raise HttpMessageSignatureError("signature was created in the future")
    if expires < current - clock_skew_seconds:
        raise HttpMessageSignatureError("signature has expired")

    caller = _validate_controller(lowered["agent-web-caller"])
    if controller_document.get("id") != caller:
        raise HttpMessageSignatureError("caller does not match its controller document")
    try:
        _validate_key_id(key_id, caller)
    except ValueError as exc:
        raise HttpMessageSignatureError(str(exc)) from exc
    authentication = controller_document.get("authentication")
    if not isinstance(authentication, list) or key_id not in {
        item if isinstance(item, str) else item.get("id")
        for item in authentication
        if isinstance(item, (str, Mapping))
    }:
        raise HttpMessageSignatureError("signature key is not authorized for authentication")
    methods = controller_document.get("verificationMethod")
    method_document = next(
        (
            item
            for item in methods if isinstance(item, Mapping) and item.get("id") == key_id
        ),
        None,
    ) if isinstance(methods, list) else None
    if method_document is None:
        raise HttpMessageSignatureError("signature key is not published")
    if method_document.get("controller") != caller:
        raise HttpMessageSignatureError("signature key controller does not match caller")
    if method_document.get("type") != "Multikey":
        raise HttpMessageSignatureError("signature key must use Multikey")

    digest_match = _CONTENT_DIGEST.fullmatch(lowered["content-digest"])
    if digest_match is None:
        raise HttpMessageSignatureError("Content-Digest must use RFC 9530 sha-256")
    try:
        advertised_digest = b64decode(digest_match.group(1), validate=True)
    except ValueError as exc:
        raise HttpMessageSignatureError("Content-Digest is invalid base64") from exc
    if advertised_digest != sha256(body).digest():
        raise HttpMessageSignatureError("Content-Digest does not match the request body")

    signature_match = _SIGNATURE.fullmatch(lowered["signature"])
    if signature_match is None:
        raise HttpMessageSignatureError("Signature is outside the Agent Web profile")
    try:
        signature = b64decode(signature_match.group(1), validate=True)
        public_key = _authentication_public_key(method_document)
        parameters = lowered["signature-input"].split("=", 1)[1]
        signature_base = _signature_base(
            method=_validate_method(method),
            target_uri=_validate_https_uri(target_uri),
            content_digest=lowered["content-digest"],
            content_type=_validate_content_type(lowered["content-type"]),
            caller=caller,
            parameters=parameters,
        )
        public_key.verify(signature, signature_base.encode("ascii"))
    except HttpMessageSignatureError:
        raise
    except Exception as exc:
        raise HttpMessageSignatureError("HTTP message signature is invalid") from exc
    if replay_store is not None and not replay_store.claim(
        caller, nonce, expires, now=current
    ):
        raise HttpMessageSignatureError("HTTP message signature nonce was replayed")
    return AuthenticatedWebCaller(caller, key_id, created, expires, nonce)


def build_caller_controller(
    *, caller: str, signer: Ed25519Signer
) -> dict[str, object]:
    """Build the minimal HTTPS controller document used for action authentication."""

    controller = _validate_controller(caller)
    _validate_key_id(signer.key_id, controller)
    encoded = b"\xed\x01" + signer.public_key_bytes()
    if len(encoded) != 34:
        raise ValueError("caller authentication key must be Ed25519")
    import base58

    return {
        "id": controller,
        "verificationMethod": [
            {
                "id": signer.key_id,
                "type": "Multikey",
                "controller": controller,
                "publicKeyMultibase": "z" + base58.b58encode(encoded).decode("ascii"),
            }
        ],
        "authentication": [signer.key_id],
    }


def _signature_parameters(*, created: int, expires: int, key_id: str, nonce: str) -> str:
    if '"' in key_id or "\\" in key_id:
        raise ValueError("signing key identifier cannot be serialized safely")
    return (
        f"({_COMPONENT_LIST});created={created};expires={expires};"
        f'keyid="{key_id}";nonce="{nonce}";alg="ed25519"'
    )


def _signature_base(
    *, method: str, target_uri: str, content_digest: str,
    content_type: str, caller: str, parameters: str,
) -> str:
    values = (method, target_uri, content_digest, content_type, caller)
    lines = [f'"{name}": {value}' for name, value in zip(_COMPONENTS, values)]
    lines.append(f'"@signature-params": {parameters}')
    return "\n".join(lines)


def _content_digest(body: bytes) -> str:
    return f"sha-256=:{b64encode(sha256(body).digest()).decode('ascii')}:"


def _validate_method(method: str) -> str:
    value = str(method)
    if value != value.upper():
        raise ValueError("signed HTTP method must use its canonical upper-case form")
    if value not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("unsupported signed HTTP method")
    return value


def _validate_content_type(content_type: str) -> str:
    value = str(content_type).strip().lower()
    if value != "application/json":
        raise ValueError("authenticated Agent Web actions require application/json")
    return value


def _validate_controller(controller: str) -> str:
    value = _validate_https_uri(controller)
    parsed = urlsplit(value)
    if parsed.query:
        raise ValueError("caller controller must not contain a query")
    return value


def _validate_key_id(key_id: str, controller: str) -> str:
    prefix = f"{controller}#"
    if not isinstance(key_id, str) or not key_id.startswith(prefix):
        raise ValueError("signature key does not belong to caller")
    fragment = key_id[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9._~-]{1,128}", fragment):
        raise ValueError("signature key fragment is invalid")
    return key_id


def _validate_https_uri(uri: str) -> str:
    value = str(uri)
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ValueError("HTTP signature URLs must use printable ASCII wire form")
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https" or not parsed.hostname
        or parsed.username or parsed.password or parsed.fragment
    ):
        raise ValueError("HTTP signature identifiers require absolute HTTPS URLs")
    hostname = parsed.hostname.lower()
    port = parsed.port
    authority = hostname if port in {None, 443} else f"{hostname}:{port}"
    path = parsed.path or "/"
    return urlunsplit(("https", authority, path, parsed.query, ""))


def _reject_duplicate_security_headers(
    raw_headers: Sequence[tuple[bytes, bytes]],
) -> None:
    protected = {
        b"content-digest",
        b"content-type",
        b"agent-web-caller",
        b"signature-input",
        b"signature",
    }
    counts: dict[bytes, int] = {}
    for name, _value in raw_headers:
        normalized = bytes(name).lower()
        if normalized in protected:
            counts[normalized] = counts.get(normalized, 0) + 1
    duplicates = sorted(name.decode("ascii") for name, count in counts.items() if count != 1)
    if duplicates:
        raise HttpMessageSignatureError(
            f"authenticated request has duplicate or missing protected fields: {', '.join(duplicates)}"
        )


def _authentication_public_key(method: Mapping[str, object]) -> ed25519.Ed25519PublicKey:
    multibase = method.get("publicKeyMultibase")
    if not isinstance(multibase, str) or not multibase.startswith("z"):
        raise HttpMessageSignatureError("authentication key must be an Ed25519 Multikey")
    import base58

    try:
        encoded = base58.b58decode(multibase[1:])
    except ValueError as exc:
        raise HttpMessageSignatureError("authentication Multikey is invalid") from exc
    if len(encoded) != 34 or encoded[:2] != b"\xed\x01":
        raise HttpMessageSignatureError("authentication Multikey is not Ed25519")
    return ed25519.Ed25519PublicKey.from_public_bytes(encoded[2:])
