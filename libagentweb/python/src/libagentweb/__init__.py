"""Language-neutral Agent Web contracts, implemented in Python.

The default import surface is Web-native. ANP compatibility objects are loaded
only when explicitly requested and require the optional ``libagentweb[anp]``
extra.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .discovery import (
    DISCOVERY_MEDIA_TYPE,
    DISCOVERY_PATH,
    DiscoveryValidationError,
    build_discovery_document,
    validate_discovery_document,
)
from .identity import (
    ResourceTrustError,
    load_ed25519_private_key,
    resolve_and_verify_resource,
    sign_resource,
    verify_resource,
)
from .http_signatures import (
    AuthenticatedWebCaller,
    HTTP_SIGNATURE_SECURITY,
    HttpMessageSignatureError,
    HttpSignatureReplayStore,
    build_caller_controller,
    sign_agent_web_request,
    verify_agent_web_request,
)
from .resource import (
    AGENT_WEB_VERSION,
    RESOURCE_MEDIA_TYPE,
    ResourceValidationError,
    anp_action,
    empty_affordances,
    http_action,
    is_resource_expired,
    links_by_rel,
    load_context,
    load_resource_schema,
    validate_resource,
    walk_linked_resources,
)
from .signing import (
    Ed25519Signer,
    LocalEd25519Signer,
    VaultTransitEd25519Signer,
    sign_object_proof,
    verify_object_proof,
)
from .web_browser import WebActionConfirmationRequired, WebAgentBrowser


_OPTIONAL_ANP_EXPORTS = {
    "ActionConfirmationRequired": ("libagentweb.browser", "ActionConfirmationRequired"),
    "AgentBrowser": ("libagentweb.browser", "AgentBrowser"),
    "RemoteANPError": ("libagentweb.browser", "RemoteANPError"),
    "ManagedDIDWbaAuthHeader": ("libagentweb.managed_auth", "ManagedDIDWbaAuthHeader"),
    "HandleTrustError": ("libagentweb.wns", "HandleTrustError"),
    "ResolvedHandle": ("libagentweb.wns", "ResolvedHandle"),
    "resolve_exact_handle": ("libagentweb.wns", "resolve_exact_handle"),
}


def __getattr__(name: str) -> Any:
    target = _OPTIONAL_ANP_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    try:
        value = getattr(import_module(module_name), attribute)
    except ModuleNotFoundError as exc:
        if exc.name == "anp" or (exc.name or "").startswith("anp."):
            raise ModuleNotFoundError(
                f"{name} requires the optional libagentweb[anp] adapter"
            ) from exc
        raise
    globals()[name] = value
    return value


__all__ = [
    "AGENT_WEB_VERSION",
    "AuthenticatedWebCaller",
    "DISCOVERY_MEDIA_TYPE",
    "DISCOVERY_PATH",
    "DiscoveryValidationError",
    "Ed25519Signer",
    "HTTP_SIGNATURE_SECURITY",
    "HttpMessageSignatureError",
    "HttpSignatureReplayStore",
    "LocalEd25519Signer",
    "RESOURCE_MEDIA_TYPE",
    "ResourceTrustError",
    "ResourceValidationError",
    "VaultTransitEd25519Signer",
    "WebAgentBrowser",
    "WebActionConfirmationRequired",
    "anp_action",
    "build_discovery_document",
    "build_caller_controller",
    "empty_affordances",
    "http_action",
    "is_resource_expired",
    "links_by_rel",
    "load_context",
    "load_ed25519_private_key",
    "load_resource_schema",
    "resolve_and_verify_resource",
    "sign_object_proof",
    "sign_agent_web_request",
    "sign_resource",
    "validate_discovery_document",
    "validate_resource",
    "verify_object_proof",
    "verify_agent_web_request",
    "verify_resource",
    "walk_linked_resources",
]

__version__ = "0.2.1"
