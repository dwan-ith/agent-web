import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ProofVerificationError,
  jcsCanonicalize,
  multikeyToPublicKey,
  verifyObjectProof,
} from "../src/signing.js";
import { SeedSigner } from "../src/http-signatures.js";
import vectors from "../src/vectors/data-integrity.vectors.json" with {
  type: "json",
};

interface VectorDocument {
  fixed: { created: string; origin: string; publisher: string };
  keys: { seedHex: string; publicKeyMultibase: string };
  controllerDocument: Parameters<typeof verifyObjectProof>[1]["controllerDocument"];
  resource: Record<string, unknown>;
  canonicalUnsignedDocument: string;
  negatives: Array<{
    name: string;
    expectedError: string;
    resource?: Record<string, unknown>;
    controllerDocument?: object;
    issuer?: string;
  }>;
}

const document = vectors as unknown as VectorDocument;

test("jcs canonicalization matches the committed RFC 8785 expectation", () => {
  const unsigned: Record<string, unknown> = { ...document.resource };
  delete unsigned.proof;
  assert.equal(jcsCanonicalize(unsigned), document.canonicalUnsignedDocument);
});

test("multikey decoding rejects non-Ed25519 material", () => {
  assert.throws(() => multikeyToPublicKey("z123"), /not valid base58|not Ed25519/);
});

test("verifies the signed conformance resource without ANP", () => {
  verifyObjectProof(document.resource, {
    issuer: document.fixed.publisher,
    controllerDocument: document.controllerDocument,
  });
});

test("the committed key material reproduces the published Multikey", () => {
  const signer = new SeedSigner(
    Buffer.from(document.keys.seedHex, "hex"),
    `${document.fixed.publisher}#key-1`,
  );
  assert.equal(signer.publicKeyMultibase, document.keys.publicKeyMultibase);
});

for (const negative of document.negatives) {
  test(`rejects ${negative.name}`, () => {
    assert.throws(
      () =>
        verifyObjectProof(negative.resource ?? document.resource, {
          issuer:
            negative.issuer ??
            (document.resource["provenance"] as Record<string, unknown>)
              .publisher as string,
          controllerDocument:
            (negative.controllerDocument as never) ??
            document.controllerDocument,
        }),
      (error: unknown) =>
        error instanceof ProofVerificationError &&
        error.message.includes(negative.expectedError),
    );
  });
}
