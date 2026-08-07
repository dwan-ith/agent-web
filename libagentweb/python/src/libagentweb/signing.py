"""Ed25519 signing abstractions for keys that need not enter the process."""

from __future__ import annotations

from base64 import b64decode, b64encode
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any, Callable, Mapping, Protocol, runtime_checkable
from urllib.parse import quote, urlsplit

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import httpx
import jcs


@runtime_checkable
class Ed25519Signer(Protocol):
    """Minimal synchronous boundary implemented by local, KMS, or HSM keys."""

    @property
    def key_id(self) -> str: ...

    def public_key_bytes(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...


class LocalEd25519Signer:
    """Compatibility signer for tests, development, and migrations."""

    def __init__(self, key: ed25519.Ed25519PrivateKey, *, key_id: str) -> None:
        self._key = key
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class VaultTransitEd25519Signer:
    """PureEdDSA signer backed by a non-derived Vault Transit Ed25519 key."""

    _SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

    def __init__(
        self,
        *,
        base_url: str,
        mount: str,
        key_name: str,
        token_provider: Callable[[], str],
        namespace: str | None = None,
        ca_file: str | None = None,
        timeout: float = 8.0,
        client: httpx.Client | None = None,
    ) -> None:
        parsed = urlsplit(base_url.rstrip("/"))
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Vault base URL must be an HTTPS origin")
        if not self._SLUG.fullmatch(mount) or not self._SLUG.fullmatch(key_name):
            raise ValueError("Vault mount and key name must be bounded path slugs")
        if namespace is not None and (
            not namespace or len(namespace) > 256 or "\n" in namespace
        ):
            raise ValueError("Vault namespace is invalid")
        if timeout <= 0 or timeout > 60:
            raise ValueError("Vault timeout must be in (0, 60]")
        self._base_url = f"https://{parsed.netloc}"
        self._mount = mount
        self._key_name = key_name
        self._token_provider = token_provider
        self._namespace = namespace
        self._owns_client = client is None
        self._client = client or httpx.Client(
            verify=ca_file or True,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )
        self._public_key: bytes | None = None

    @property
    def key_id(self) -> str:
        return f"vault-transit:{self._mount}/{self._key_name}"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def public_key_bytes(self) -> bytes:
        if self._public_key is None:
            document = self._request("GET", f"keys/{self._key_name}")
            data = document.get("data")
            if not isinstance(data, Mapping):
                raise ValueError("Vault key response has no data object")
            if (
                data.get("type") != "ed25519"
                or data.get("supports_signing") is not True
                or data.get("derived") is True
            ):
                raise ValueError(
                    "Vault key must be a non-derived signing-capable Ed25519 key"
                )
            keys = data.get("keys")
            if not isinstance(keys, Mapping) or not keys:
                raise ValueError("Vault key response has no key versions")
            latest = data.get("latest_version")
            if not isinstance(latest, int):
                try:
                    latest = max(int(version) for version in keys)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Vault key versions are invalid") from exc
            record = keys.get(str(latest), keys.get(latest))
            pem = record.get("public_key") if isinstance(record, Mapping) else None
            if not isinstance(pem, str):
                raise ValueError("Vault latest Ed25519 key has no public key")
            public = serialization.load_pem_public_key(pem.encode("ascii"))
            if not isinstance(public, ed25519.Ed25519PublicKey):
                raise ValueError("Vault returned a non-Ed25519 public key")
            self._public_key = public.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        return self._public_key

    def sign(self, data: bytes) -> bytes:
        document = self._request(
            "POST",
            f"sign/{self._key_name}",
            payload={"input": b64encode(data).decode("ascii")},
        )
        response_data = document.get("data")
        value = (
            response_data.get("signature")
            if isinstance(response_data, Mapping) else None
        )
        if not isinstance(value, str) or not re.fullmatch(
            r"vault:v[1-9][0-9]*:[A-Za-z0-9+/]+={0,2}", value
        ):
            raise ValueError("Vault returned an invalid signature envelope")
        try:
            signature = b64decode(value.rsplit(":", 1)[1], validate=True)
        except ValueError as exc:
            raise ValueError("Vault returned invalid signature base64") from exc
        if len(signature) != 64:
            raise ValueError("Vault Ed25519 signature must contain 64 bytes")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(
                self.public_key_bytes()
            ).verify(signature, data)
        except Exception as exc:
            raise ValueError("Vault signature does not match its published key") from exc
        return signature

    def _request(
        self,
        method: str,
        operation: str,
        *,
        payload: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        token = self._token_provider()
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 4096
            or "\n" in token
            or "\r" in token
        ):
            raise ValueError("Vault token provider returned an invalid token")
        headers = {"X-Vault-Token": token, "Accept": "application/json"}
        if self._namespace is not None:
            headers["X-Vault-Namespace"] = self._namespace
        url = (
            f"{self._base_url}/v1/{quote(self._mount, safe='')}/"
            f"{operation}"
        )
        response = self._client.request(
            method,
            url,
            headers=headers,
            json=dict(payload) if payload is not None else None,
        )
        response.raise_for_status()
        if len(response.content) > 1024 * 1024:
            raise ValueError("Vault response exceeds 1 MiB")
        try:
            document = response.json()
        except json.JSONDecodeError as exc:
            raise ValueError("Vault response is not JSON") from exc
        if not isinstance(document, dict):
            raise ValueError("Vault response must be a JSON object")
        return document


def sign_object_proof(
    document: Mapping[str, Any],
    *,
    signer: Ed25519Signer,
    issuer_did: str,
    verification_method: str,
    created: str | None = None,
) -> dict[str, Any]:
    """Generate an ANP Appendix-B eddsa-jcs-2022 proof via any signer."""

    if not verification_method.startswith(f"{issuer_did}#"):
        raise ValueError("verification method does not belong to issuer DID")
    unsigned = deepcopy(dict(document))
    unsigned.pop("proof", None)
    created_value = created or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    try:
        parsed = datetime.fromisoformat(created_value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("created timestamp must include a timezone")
    options = {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": verification_method,
        "proofPurpose": "assertionMethod",
        "created": created_value,
    }
    signing_input = sha256(jcs.canonicalize(options)).digest() + sha256(
        jcs.canonicalize(unsigned)
    ).digest()
    signature = signer.sign(signing_input)
    if len(signature) != 64:
        raise ValueError("Ed25519 signer returned a non-64-byte signature")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(
            signer.public_key_bytes()
        ).verify(signature, signing_input)
    except Exception as exc:
        raise ValueError("signer returned a signature from a different key") from exc
    result = deepcopy(unsigned)
    result["proof"] = {
        **options,
        "proofValue": "z" + base58.b58encode(signature).decode("ascii"),
    }
    return result
