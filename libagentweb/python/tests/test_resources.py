from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
import unittest

from libagentweb.resource import (
    ResourceValidationError,
    links_by_rel,
    load_resource_schema,
    validate_resource,
    walk_linked_resources,
)

from jsonschema import Draft202012Validator

FIXTURES = Path(__file__).resolve().parents[2] / "conformance"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def fixture(folder: str, name: str) -> dict:
    with (FIXTURES / folder / name).open(encoding="utf-8") as handle:
        return json.load(handle)


class ResourceProfileTests(unittest.TestCase):
    def test_valid_conformance_documents(self) -> None:
        for name in ("moltbook-collection.json", "moltbook-thread.json"):
            resource = validate_resource(fixture("valid", name))
            self.assertEqual(resource["agentWeb"]["version"], "0.2")

    def test_invalid_conformance_document(self) -> None:
        with self.assertRaises(ResourceValidationError):
            validate_resource(fixture("invalid", "missing-identity.json"))

    def test_typed_link_traversal_is_application_independent(self) -> None:
        collection = fixture("valid", "moltbook-collection.json")
        thread = fixture("valid", "moltbook-thread.json")
        documents = {
            collection["@id"]: collection,
            thread["@id"]: thread,
        }
        walked = walk_linked_resources(
            collection["@id"],
            documents.__getitem__,
        )
        self.assertEqual(
            [resource["@id"] for resource in walked],
            [collection["@id"], thread["@id"]],
        )
        self.assertEqual(
            links_by_rel(collection, "human-view")[0]["mediaType"],
            "text/html",
        )

    def test_cross_field_identity_and_canonical_bindings_are_enforced(self) -> None:
        resource = fixture("valid", "moltbook-thread.json")
        wrong_canonical = deepcopy(resource)
        wrong_canonical["provenance"]["canonical"] = (
            "https://moltbook.example/agent/resources/threads/other.json"
        )
        with self.assertRaisesRegex(ResourceValidationError, "canonical"):
            validate_resource(wrong_canonical)

        wrong_signer = deepcopy(resource)
        wrong_signer["proof"]["verificationMethod"] = (
            "did:wba:attacker.example:agent:e1_fixture#key-1"
        )
        with self.assertRaisesRegex(ResourceValidationError, "publisher"):
            validate_resource(wrong_signer)


class ResourceSchemaContractTests(unittest.TestCase):
    def test_typescript_schema_copy_matches_the_canonical_schema(self) -> None:
        canonical = (
            REPOSITORY_ROOT
            / "libagentweb/python/src/libagentweb/schemas/agent-web-resource.schema.json"
        )
        typescript_copy = (
            REPOSITORY_ROOT
            / "libagentweb/typescript/src/schemas/agent-web-resource.schema.json"
        )
        self.assertEqual(
            canonical.read_bytes(),
            typescript_copy.read_bytes(),
            "typescript/src/schemas copy has drifted from the canonical schema",
        )

    def test_packaged_schema_is_a_valid_draft_2020_12_schema(self) -> None:
        Draft202012Validator.check_schema(load_resource_schema())


if __name__ == "__main__":
    unittest.main()
