"""Proof-verifying Agent Web registry and search publisher.

The indexing and storage surface is Agent Web-native. The legacy server and
runtime are loaded lazily because they still expose optional ANP endpoints.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from .indexer import RegistryIndexer
from .federation import FederationStateFile, FederationSyncResult, RegistryFederator
from .store import RegistryStore


_OPTIONAL_SERVER_EXPORTS = {
    "create_app": ("registry_site.app", "create_app"),
    "start_registry": ("registry_site.runtime", "start_registry"),
}


def __getattr__(name: str) -> Any:
    target = _OPTIONAL_SERVER_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    module_name, attribute = target
    value = getattr(import_module(module_name), attribute)
    globals()[name] = value
    return value

__all__ = [
    "RegistryIndexer",
    "FederationStateFile",
    "FederationSyncResult",
    "RegistryFederator",
    "RegistryStore",
    "create_app",
    "start_registry",
]
