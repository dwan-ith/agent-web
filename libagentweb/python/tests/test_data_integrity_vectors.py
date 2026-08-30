"""Python side of the committed cross-language Data Integrity vectors.

The TypeScript suite consumes the exact same committed file, so any
divergence between the two implementations of ``eddsa-jcs-2022`` fails a
test in at least one language.
"""

from __future__ import annotations

from pathlib import Path
import unittest

import jcs

from libagentweb.signing import verify_object_proof

VECTORS = (
    Path(__file__).resolve().parents[2]
    / "conformance"
    / "data-integrity"
    / "data-integrity.vectors.json"
)


class DataIntegrityVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import json

        cls.vectors = json.loads(
            VECTORS.read_text(encoding="utf-8"), object_pairs_hook=dict
        )

    def test_canonicalization_is_stable(self) -> None:
        unsigned = {
            key: value
            for key, value in self.vectors["resource"].items()
            if key != "proof"
        }
        self.assertEqual(
            jcs.canonicalize(unsigned).decode("utf-8"),
            self.vectors["canonicalUnsignedDocument"],
        )

    def test_positive_vector_verifies(self) -> None:
        verify_object_proof(
            self.vectors["resource"],
            issuer=self.vectors["fixed"]["publisher"],
            controller_document=self.vectors["controllerDocument"],
        )

    def test_negative_vectors_are_rejected(self) -> None:
        publisher = self.vectors["fixed"]["publisher"]
        for negative in self.vectors["negatives"]:
            with self.subTest(negative["name"]):
                with self.assertRaises(ValueError):
                    verify_object_proof(
                        negative.get("resource", self.vectors["resource"]),
                        issuer=negative.get("issuer", publisher),
                        controller_document=negative.get(
                            "controllerDocument",
                            self.vectors["controllerDocument"],
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
