"""Publisher identity, DID hosting, and signed-document helpers."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from anp.authentication.did_resolver import build_did_resolution_url
from anp.authentication.did_wba import (
    create_did_wba_document,
    validate_did_document_binding,
)
from anp.proof.object_proof import generate_object_proof
from anp.wns import build_resolution_url, validate_handle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from libagentweb import (
    Ed25519Signer,
    VaultTransitEd25519Signer,
    sign_object_proof,
    sign_resource as sign_local_resource,
    validate_resource,
)

from .secrets import read_secret_file


IDENTITY_MANIFEST_VERSION = "agent-web-identity-lifecycle/1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class PublisherIdentity:
    """A validated DID-WBA document and its operator-controlled signing key."""

    did_document: dict[str, Any]
    private_key: ed25519.Ed25519PrivateKey

    def __post_init__(self) -> None:
        if not validate_did_document_binding(
            self.did_document,
            verify_proof=True,
        ):
            raise ValueError("publisher DID document has an invalid key binding")
        did = self.did_document.get("id")
        if not isinstance(did, str) or not did.startswith("did:wba:"):
            raise ValueError("publisher identity must use did:wba")
        expected_public = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        method = self.did_document["verificationMethod"][0]
        from anp.authentication.verification_methods import create_verification_method

        verifier = create_verification_method(method)
        actual_public = verifier.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if actual_public != expected_public:
            raise ValueError("private key does not match publisher DID document")

    @property
    def did(self) -> str:
        return str(self.did_document["id"])

    @property
    def verification_method(self) -> str:
        return f"{self.did}#key-1"

    @property
    def private_key_pem(self) -> str:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    @property
    def public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def handle(self) -> str | None:
        """Return the exact WNS handle declared by this DID, if present."""

        candidates: set[str] = set()
        for service in self.did_document.get("service", []):
            if not isinstance(service, Mapping) or service.get("type") != (
                "ANPHandleService"
            ):
                continue
            endpoint = service.get("serviceEndpoint")
            if not isinstance(endpoint, str):
                raise ValueError("ANPHandleService endpoint must be a string")
            parsed = urlsplit(endpoint)
            prefix = "/.well-known/handle/"
            if parsed.scheme != "https" or not parsed.hostname or not parsed.path.startswith(prefix):
                raise ValueError("ANPHandleService must use the standard HTTPS endpoint")
            local_part = unquote(parsed.path[len(prefix):])
            candidate = f"{local_part}.{parsed.hostname.lower()}"
            local_part, domain = validate_handle(candidate)
            if endpoint != build_resolution_url(local_part, domain):
                raise ValueError("ANPHandleService endpoint is not canonical")
            from .wns import did_wba_hostname

            if did_wba_hostname(self.did) != domain:
                raise ValueError("WNS handle domain does not match the publisher DID")
            candidates.add(candidate)
        if len(candidates) > 1:
            raise ValueError("publisher DID declares multiple exact WNS handles")
        return next(iter(candidates), None)

    def sign_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        """Return a detached copy carrying an ANP Appendix-B object proof."""

        unsigned = deepcopy(dict(document))
        unsigned.pop("proof", None)
        return generate_object_proof(
            unsigned,
            self.private_key,
            self.verification_method,
            issuer_did=self.did,
        )

    def sign_resource(self, document: Mapping[str, Any]) -> dict[str, Any]:
        return sign_local_resource(
            document,
            private_key=self.private_key,
            publisher_did=self.did,
            verification_method=self.verification_method,
        )

    @classmethod
    def from_files(
        cls,
        did_document_path: str | Path,
        private_key_path: str | Path,
    ) -> "PublisherIdentity":
        document = json.loads(
            Path(did_document_path).read_text(encoding="utf-8")
        )
        key = serialization.load_pem_private_key(
            Path(private_key_path).read_bytes(),
            password=None,
        )
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TypeError("publisher key must be Ed25519")
        return cls(document, key)

    @classmethod
    def from_lifecycle(cls, directory: str | Path) -> "PublisherIdentity":
        """Load the validated active generation from an identity lifecycle."""

        root = Path(directory).resolve()
        manifest = load_identity_manifest(root)
        active = _active_generation(manifest)
        did_path = _contained_path(root, active["didDocument"])
        key_path = _contained_path(root, active["privateKey"])
        identity = cls.from_files(did_path, key_path)
        if identity.did != manifest["activeDid"] or identity.did != active["did"]:
            raise ValueError("identity manifest active DID does not match its files")
        return identity


class ManagedPublisherIdentity:
    """Publisher identity whose DID assertion key is held by a remote signer.

    A separate process-local Ed25519 key signs short-lived access tokens because
    the current ANP verifier accepts PEM JWT keys. It is not advertised by the
    DID and cannot create publisher object proofs.
    """

    def __init__(
        self,
        did_document: Mapping[str, Any],
        signer: Ed25519Signer,
        access_token_private_key: ed25519.Ed25519PrivateKey,
    ) -> None:
        self.did_document = deepcopy(dict(did_document))
        self.signer = signer
        self._access_token_private_key = access_token_private_key
        if not validate_did_document_binding(self.did_document, verify_proof=True):
            raise ValueError("publisher DID document has an invalid key binding")
        did = self.did_document.get("id")
        if not isinstance(did, str) or not did.startswith("did:wba:"):
            raise ValueError("publisher identity must use did:wba")
        matches = 0
        expected = signer.public_key_bytes()
        if len(expected) != 32:
            raise ValueError("managed Ed25519 public key must contain 32 bytes")
        from anp.authentication.verification_methods import create_verification_method

        for method in self.did_document.get("verificationMethod", []):
            if not isinstance(method, Mapping):
                continue
            verifier = create_verification_method(dict(method))
            public = getattr(verifier, "public_key", None)
            if not isinstance(public, ed25519.Ed25519PublicKey):
                continue
            actual = public.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if actual == expected and method.get("id") == self.verification_method:
                matches += 1
        if matches != 1:
            raise ValueError(
                "managed signer does not match the DID assertion verification method"
            )

    @property
    def did(self) -> str:
        return str(self.did_document["id"])

    @property
    def verification_method(self) -> str:
        return f"{self.did}#key-1"

    @property
    def private_key_pem(self) -> str:
        return self._access_token_private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii")

    @property
    def public_key_pem(self) -> str:
        return self._access_token_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @property
    def handle(self) -> str | None:
        getter = PublisherIdentity.handle.fget
        if getter is None:
            raise RuntimeError("publisher handle property is unavailable")
        return getter(self)  # type: ignore[arg-type]

    def sign_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        return sign_object_proof(
            document,
            signer=self.signer,
            issuer_did=self.did,
            verification_method=self.verification_method,
        )

    def sign_resource(self, document: Mapping[str, Any]) -> dict[str, Any]:
        unsigned = deepcopy(dict(document))
        unsigned.pop("proof", None)
        provenance = unsigned.get("provenance")
        if not isinstance(provenance, Mapping) or provenance.get("publisher") != self.did:
            raise ValueError("resource publisher does not match the signing DID")
        return validate_resource(self.sign_document(unsigned))

    def close(self) -> None:
        close = getattr(self.signer, "close", None)
        if callable(close):
            close()

    @classmethod
    def from_vault_transit(
        cls,
        *,
        did_document_path: str | Path,
        access_token_private_key_path: str | Path,
        vault_url: str,
        vault_mount: str,
        vault_key: str,
        vault_token_file: str | Path,
        vault_namespace: str | None = None,
        vault_ca_file: str | None = None,
    ) -> "ManagedPublisherIdentity":
        document = json.loads(Path(did_document_path).read_text(encoding="utf-8"))
        token_path = Path(vault_token_file)
        signer = VaultTransitEd25519Signer(
            base_url=vault_url,
            mount=vault_mount,
            key_name=vault_key,
            token_provider=lambda: read_secret_file(token_path),
            namespace=vault_namespace,
            ca_file=vault_ca_file,
        )
        key = serialization.load_pem_private_key(
            Path(access_token_private_key_path).read_bytes(),
            password=None,
        )
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            signer.close()
            raise TypeError("access-token key must be Ed25519")
        try:
            return cls(document, signer, key)
        except Exception:
            signer.close()
            raise


def generate_publisher_identity(
    *,
    base_url: str,
    agent_name: str,
    agent_description_path: str,
    handle: str | None = None,
) -> PublisherIdentity:
    """Generate a development/test identity bound to an exact HTTPS origin."""

    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("publisher identities require an absolute HTTPS base URL")
    services: list[dict[str, str]] | None = None
    if handle is not None:
        local_part, domain = validate_handle(handle)
        if domain != parsed.hostname.lower():
            raise ValueError("WNS handle domain must match the publisher hostname")
        services = [
            {
                "id": "#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": build_resolution_url(local_part, domain),
            }
        ]
    document, keys = create_did_wba_document(
        hostname=parsed.hostname,
        port=parsed.port,
        path_segments=["agents", agent_name],
        agent_description_url=(
            f"{base_url.rstrip('/')}/{agent_description_path.lstrip('/')}"
        ),
        enable_e2ee=False,
        did_profile="e1",
        services=services,
    )
    key = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("ANP generated a non-Ed25519 e1 key")
    return PublisherIdentity(document, key)


def load_runtime_identity(
    *,
    identity_directory: str | None,
    did_document: str | None,
    private_key: str | None,
    vault_url: str | None,
    vault_mount: str,
    vault_key: str | None,
    vault_token_file: str | None,
    access_token_private_key: str | None,
    vault_namespace: str | None = None,
    vault_ca_file: str | None = None,
) -> PublisherIdentity | ManagedPublisherIdentity:
    """Load exactly one local-lifecycle or Vault-backed runtime identity."""

    managed_values = (
        vault_url,
        vault_key,
        vault_token_file,
        access_token_private_key,
        vault_namespace,
        vault_ca_file,
    )
    managed = any(value is not None for value in managed_values)
    if identity_directory:
        if did_document or private_key or managed:
            raise ValueError(
                "identity directory cannot be combined with identity files or Vault"
            )
        return PublisherIdentity.from_lifecycle(identity_directory)
    if managed:
        if private_key is not None:
            raise ValueError("Vault identity cannot use a local publisher private key")
        required = {
            "did document": did_document,
            "Vault URL": vault_url,
            "Vault key": vault_key,
            "Vault token file": vault_token_file,
            "access-token private key": access_token_private_key,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise ValueError(
                "Vault identity is missing: " + ", ".join(missing)
            )
        return ManagedPublisherIdentity.from_vault_transit(
            did_document_path=did_document,
            access_token_private_key_path=access_token_private_key,
            vault_url=vault_url,
            vault_mount=vault_mount,
            vault_key=vault_key,
            vault_token_file=vault_token_file,
            vault_namespace=vault_namespace,
            vault_ca_file=vault_ca_file,
        )
    if not did_document or not private_key:
        raise ValueError(
            "provide an identity directory, local DID/key files, or Vault identity"
        )
    return PublisherIdentity.from_files(did_document, private_key)


def did_document_path(identity: PublisherIdentity) -> str:
    """Return the HTTPS path at which this DID-WBA document must be hosted."""

    resolution_url = build_did_resolution_url(identity.did)
    parsed = urlsplit(resolution_url)
    return unquote(parsed.path)


def mount_identity(
    app: FastAPI,
    identity: PublisherIdentity,
    *,
    agent_description_url: str,
) -> None:
    """Host a publisher DID and ANP 1.1 discovery index."""

    path = did_document_path(identity)

    @app.get(path, include_in_schema=False)
    async def did_document() -> JSONResponse:
        return JSONResponse(
            deepcopy(identity.did_document),
            headers={"Cache-Control": "public, max-age=300"},
        )

    @app.get("/.well-known/agent-descriptions", include_in_schema=False)
    async def agent_descriptions() -> dict[str, Any]:
        return {
            "@context": "https://agent-network-protocol.com/contexts/agent-discovery/v1",
            "agentDescriptions": [agent_description_url],
        }


def write_identity(
    identity: PublisherIdentity,
    *,
    directory: str | Path,
) -> tuple[Path, Path]:
    """Persist an identity without overwriting existing operator keys."""

    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    did_path = target / "did.json"
    key_path = target / "private-key.pem"
    for path in (did_path, key_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite identity file: {path}")
    created: list[Path] = []
    try:
        _exclusive_write(key_path, identity.private_key_pem.encode("ascii"), 0o600)
        created.append(key_path)
        _exclusive_write(
            did_path,
            (json.dumps(identity.did_document, indent=2) + "\n").encode("utf-8"),
            0o644,
        )
        created.append(did_path)
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return did_path, key_path


def provision_identity_lifecycle(
    *,
    directory: str | Path,
    base_url: str,
    agent_name: str,
    agent_description_path: str,
    handle: str | None = None,
) -> PublisherIdentity:
    """Provision generation one without replacing any existing lifecycle."""

    root = Path(directory)
    manifest_path = root / "manifest.json"
    if manifest_path.exists():
        raise FileExistsError(
            f"refusing to replace identity lifecycle: {manifest_path}"
        )
    identity = generate_publisher_identity(
        base_url=base_url,
        agent_name=agent_name,
        agent_description_path=agent_description_path,
        handle=handle,
    )
    generation_path = root / "generations" / "000001"
    did_path, key_path = write_identity(identity, directory=generation_path)
    created_at = _utc_now()
    manifest = {
        "schema": IDENTITY_MANIFEST_VERSION,
        "baseUrl": base_url.rstrip("/"),
        "agentName": agent_name,
        "agentDescriptionPath": agent_description_path,
        "handle": identity.handle,
        "activeDid": identity.did,
        "activeGeneration": 1,
        "generations": [
            {
                "generation": 1,
                "did": identity.did,
                "didDocument": did_path.relative_to(root).as_posix(),
                "privateKey": key_path.relative_to(root).as_posix(),
                "createdAt": created_at,
                "status": "active",
            }
        ],
    }
    root.mkdir(parents=True, exist_ok=True)
    try:
        _exclusive_write(
            manifest_path,
            (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
            0o600,
        )
    except Exception:
        # Generation files are intentionally retained for manual recovery.
        raise
    return identity


def rotate_identity_lifecycle(
    directory: str | Path,
    *,
    expected_active_did: str,
) -> dict[str, Any]:
    """Create a new key-bound DID generation and atomically activate it.

    The transition is an Agent Web operator record, not an ANP/WNS continuity
    claim. Both old and new keys attest the same payload so an operator can
    retain evidence while separately updating discovery and stable naming.
    """

    root = Path(directory).resolve()
    manifest = load_identity_manifest(root)
    previous_entry = _active_generation(manifest)
    if manifest["activeDid"] != expected_active_did:
        raise ValueError("active DID changed; refusing an unconfirmed rotation")
    previous = PublisherIdentity.from_lifecycle(root)
    generation = int(manifest["activeGeneration"]) + 1
    generation_path = root / "generations" / f"{generation:06d}"
    successor = generate_publisher_identity(
        base_url=manifest["baseUrl"],
        agent_name=manifest["agentName"],
        agent_description_path=manifest["agentDescriptionPath"],
        handle=manifest.get("handle"),
    )
    did_path, key_path = write_identity(successor, directory=generation_path)
    effective_at = _utc_now()
    payload = {
        "schema": "agent-web-operator-identity-transition/1",
        "previousDid": previous.did,
        "successorDid": successor.did,
        "generation": generation,
        "effectiveAt": effective_at,
    }
    previous_proof = previous.sign_document(payload)["proof"]
    successor_proof = successor.sign_document(payload)["proof"]
    transition = {
        **payload,
        "previousProof": previous_proof,
        "successorProof": successor_proof,
        "notice": (
            "Operator lifecycle evidence only; verify current ANP/WNS "
            "resolution independently."
        ),
    }
    transition_path = generation_path / "transition.json"
    _exclusive_write(
        transition_path,
        (json.dumps(transition, indent=2) + "\n").encode("utf-8"),
        0o644,
    )

    previous_entry["status"] = "retired"
    previous_entry["retiredAt"] = effective_at
    manifest["activeDid"] = successor.did
    manifest["activeGeneration"] = generation
    manifest["generations"].append(
        {
            "generation": generation,
            "did": successor.did,
            "didDocument": did_path.relative_to(root).as_posix(),
            "privateKey": key_path.relative_to(root).as_posix(),
            "transition": transition_path.relative_to(root).as_posix(),
            "createdAt": effective_at,
            "status": "active",
            "previousDid": previous.did,
        }
    )
    _atomic_replace_json(root / "manifest.json", manifest)
    return transition


def load_identity_manifest(directory: str | Path) -> dict[str, Any]:
    """Load and structurally validate a lifecycle manifest."""

    root = Path(directory).resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != (
        IDENTITY_MANIFEST_VERSION
    ):
        raise ValueError("unsupported identity lifecycle manifest")
    required = {
        "baseUrl": str,
        "agentName": str,
        "agentDescriptionPath": str,
        "activeDid": str,
        "activeGeneration": int,
        "generations": list,
    }
    for name, expected_type in required.items():
        if not isinstance(manifest.get(name), expected_type):
            raise ValueError(f"identity manifest field '{name}' is invalid")
    parsed = urlsplit(manifest["baseUrl"])
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("identity manifest baseUrl must use HTTPS")
    active = _active_generation(manifest)
    if sum(
        1
        for entry in manifest["generations"]
        if isinstance(entry, dict) and entry.get("status") == "active"
    ) != 1:
        raise ValueError("identity manifest must have one active status")
    for entry in manifest["generations"]:
        if not isinstance(entry, dict):
            raise ValueError("identity generation must be an object")
        _contained_path(root, entry.get("didDocument"))
        _contained_path(root, entry.get("privateKey"))
    if active.get("did") != manifest["activeDid"]:
        raise ValueError("identity manifest active DID is inconsistent")
    return manifest


def active_identity_paths(
    directory: str | Path,
) -> tuple[Path, Path]:
    """Return contained DID/key paths for the active lifecycle generation."""

    root = Path(directory).resolve()
    manifest = load_identity_manifest(root)
    active = _active_generation(manifest)
    return (
        _contained_path(root, active["didDocument"]),
        _contained_path(root, active["privateKey"]),
    )


def _active_generation(manifest: Mapping[str, Any]) -> dict[str, Any]:
    entries = [
        entry
        for entry in manifest.get("generations", [])
        if isinstance(entry, dict)
        and entry.get("generation") == manifest.get("activeGeneration")
        and entry.get("status") == "active"
    ]
    if len(entries) != 1:
        raise ValueError("identity manifest must have exactly one active generation")
    return entries[0]


def _contained_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("identity manifest contains an invalid file path")
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("identity manifest file escapes its lifecycle directory")
    return candidate


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise


def _atomic_replace_json(path: Path, document: Mapping[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        _exclusive_write(
            temporary,
            (json.dumps(document, indent=2) + "\n").encode("utf-8"),
            0o600,
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
