import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CALLER_HEADER,
  HttpMessageSignatureError,
  InMemoryReplayStore,
  SeedSigner,
  buildCallerController,
  signAgentWebRequest,
  verifyAgentWebRequest,
} from "../src/http-signatures.js";
import vectors from "../src/vectors/http-signatures.vectors.json" with {
  type: "json",
};

interface VectorDocument {
  fixed: { created: number; expires: number; nonce: string; now: number };
  key: { seedHex: string; publicKeyMultibase: string; secondSeedHex: string };
  callerController: Parameters<typeof verifyAgentWebRequest>[0]["controllerDocument"];
  request: {
    method: string;
    targetUri: string;
    bodyBase64: string;
    contentType: string;
    caller: string;
  };
  expectedHeaders: Record<string, string>;
  negatives: Array<{
    name: string;
    expectedError: string;
    method?: string;
    targetUri?: string;
    bodyBase64?: string;
    verifyNow?: number;
    headers?: Record<string, string>;
    controllerDocument?: object;
  }>;
}

const document = vectors as unknown as VectorDocument;

function signer() {
  return new SeedSigner(
    Buffer.from(document.key.seedHex, "hex"),
    document.callerController.authentication[0] as string,
  );
}

function positiveHeaders(): Record<string, string> {
  return signAgentWebRequest({
    method: document.request.method,
    targetUri: document.request.targetUri,
    body: Buffer.from(document.request.bodyBase64, "base64"),
    contentType: document.request.contentType,
    caller: document.request.caller,
    signer: signer(),
    created: document.fixed.created,
    expires: document.fixed.expires,
    nonce: document.fixed.nonce,
  });
}

function lowered(headers: Record<string, string>): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    output[key.toLowerCase()] = value;
  }
  return output;
}

test("seed derivation reproduces the committed Multikey", () => {
  assert.equal(signer().publicKeyMultibase, document.key.publicKeyMultibase);
});

test("signing reproduces every committed header byte-for-byte", () => {
  const produced = lowered(positiveHeaders());
  const expected = lowered(document.expectedHeaders);
  assert.deepEqual(produced, expected);
});

test("committed controller matches the derived signer", () => {
  const controller = buildCallerController(
    document.request.caller,
    signer(),
  );
  assert.deepEqual(controller, document.callerController);
});

test("verification accepts the committed positive vector", () => {
  const caller = verifyAgentWebRequest({
    method: document.request.method,
    targetUri: document.request.targetUri,
    body: Buffer.from(document.request.bodyBase64, "base64"),
    headers: lowered(document.expectedHeaders),
    controllerDocument: document.callerController,
    now: document.fixed.now,
  });
  assert.equal(caller.controller, document.request.caller);
  assert.equal(caller.nonce, document.fixed.nonce);
});

test("replay store rejects the second claim of the same nonce", () => {
  const store = new InMemoryReplayStore();
  const headers = lowered(document.expectedHeaders);
  const input = {
    method: document.request.method,
    targetUri: document.request.targetUri,
    body: Buffer.from(document.request.bodyBase64, "base64"),
    headers,
    controllerDocument: document.callerController,
    replayStore: store,
    now: document.fixed.now,
  } as const;
  verifyAgentWebRequest(input);
  assert.throws(() => verifyAgentWebRequest(input), /replayed/);
});

for (const negative of document.negatives) {
  test(`rejects ${negative.name}`, () => {
    const headers: Record<string, string> = {
      ...lowered(document.expectedHeaders),
      ...lowered(negative.headers ?? {}),
    };
    assert.throws(
      () =>
        verifyAgentWebRequest({
          method: negative.method ?? document.request.method,
          targetUri: negative.targetUri ?? document.request.targetUri,
          body: Buffer.from(
            negative.bodyBase64 ?? document.request.bodyBase64,
            "base64",
          ),
          headers,
          controllerDocument:
            (negative.controllerDocument as typeof document.callerController) ??
            document.callerController,
          now: negative.verifyNow ?? document.fixed.now,
        }),
      (error: unknown) =>
        error instanceof HttpMessageSignatureError &&
        error.message.includes(negative.expectedError),
      `expected failure containing "${negative.expectedError}"`,
    );
  });
}
