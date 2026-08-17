"""A native Agent Web site with no World Wide Web projection."""

from .app import create_app
from .store import KnowledgeStore

__all__ = ["KnowledgeStore", "create_app"]
