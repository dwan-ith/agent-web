"""Language-neutral Agent Web contracts, implemented in Python."""

from .browser import ActionConfirmationRequired, AgentBrowser, RemoteANPError
from .managed_auth import ManagedDIDWbaAuthHeader
from .identity import (
    ResourceTrustError,
    load_ed25519_private_key,
    resolve_and_verify_resource,
    sign_resource,
    verify_resource,
)
from .resource import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    ResourceValidationError,
    anp_action,
    empty_affordances,
    is_resource_expired,
    links_by_rel,
    load_context,
    load_resource_schema,
    validate_resource,
    walk_linked_resources,
)
from .wns import HandleTrustError, ResolvedHandle, resolve_exact_handle
from .signing import (
    Ed25519Signer,
    LocalEd25519Signer,
    VaultTransitEd25519Signer,
    sign_object_proof,
)

__all__ = [
    "AGENT_WEB_VERSION",
    "ActionConfirmationRequired",
    "AgentBrowser",
    "HandleTrustError",
    "Ed25519Signer",
    "LocalEd25519Signer",
    "ManagedDIDWbaAuthHeader",
    "RESOURCE_MEDIA_TYPE",
    "RemoteANPError",
    "ResolvedHandle",
    "ResourceTrustError",
    "ResourceValidationError",
    "VaultTransitEd25519Signer",
    "anp_action",
    "empty_affordances",
    "is_resource_expired",
    "links_by_rel",
    "load_context",
    "load_ed25519_private_key",
    "load_resource_schema",
    "resolve_and_verify_resource",
    "resolve_exact_handle",
    "sign_resource",
    "sign_object_proof",
    "validate_resource",
    "verify_resource",
    "walk_linked_resources",
]

__version__ = "0.2.0"
