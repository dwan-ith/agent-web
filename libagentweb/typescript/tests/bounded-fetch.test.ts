import assert from "node:assert/strict";
import { test } from "node:test";

import { boundedFetch, fetchAgentWebResource } from "../src/index.js";

const ORIGINAL_FETCH = globalThis.fetch;

function withFetch(implementation: typeof fetch): void {
  (globalThis as { fetch: typeof fetch }).fetch = implementation;
}

test.afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
});

test("boundedFetch rejects redirects instead of following them", async () => {
  // Native fetch configured with redirect:"error" rejects a redirect before
  // any response arrives; the mock asserts the option is set and then fails
  // exactly the way undici does.
  withFetch((async (_url: RequestInfo | URL, init?: RequestInit) => {
    assert.equal(init?.redirect, "error");
    throw new TypeError("fetch failed");
  }) as unknown as typeof fetch);
  await assert.rejects(
    () => boundedFetch("https://publisher.example/resource"),
    /before a response arrived/,
  );
});

test("boundedFetch rejects advertised bodies beyond the byte cap", async () => {
  withFetch((async () =>
    new Response("x", {
      status: 200,
      headers: { "Content-Length": String(5 * 1024 * 1024) },
    })) as unknown as typeof fetch);
  await assert.rejects(() => boundedFetch("https://p.example/r"), /byte limit/);
});

test("boundedFetch rejects streamed bodies that grow past the cap", async () => {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(1024 * 1024));
      controller.enqueue(new Uint8Array(1024 * 1024));
      controller.enqueue(new Uint8Array(1024 * 1024));
      controller.close();
    },
  });
  withFetch((async () =>
    new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })) as unknown as typeof fetch);
  await assert.rejects(
    () =>
      boundedFetch("https://p.example/r", {
        maxBytes: 2 * 1024 * 1024,
        timeoutMs: 1_000,
      }),
    /byte limit/,
  );
});

test("fetchAgentWebResource validates through the bounded transport", async () => {
  const resource = {
    "@context": "urn:agent-web:context:0.2",
    "@id": "https://p.example/r",
    "@type": ["AgentWebResource"],
    agentWeb: { version: "0.2", kind: "resource" },
    name: "Bounded",
    links: [],
    affordances: { properties: {}, actions: {}, events: {} },
    provenance: {
      publisher: "https://p.example/.well-known/agent-web",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      canonical: "https://p.example/r",
    },
    data: {},
    proof: {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      verificationMethod:
        "https://p.example/.well-known/agent-web#key-1",
      proofPurpose: "assertionMethod",
      created: "2026-01-01T00:00:00Z",
      proofValue:
        "z3fW12AE8sBbcwHrGDjRDDAqRsLxyN7x9DdYUq7DEEJaJkGmDrwFv2RLcyXbPQh5xCKSjHH6aH4FJmTTA2ZMBbUmz",
    },
  };
  withFetch((async (_url: RequestInfo | URL, init?: RequestInit) => {
    assert.equal(init?.redirect, "error");
    return new Response(JSON.stringify(resource), {
      status: 200,
      headers: { "Content-Type": "application/agent-web+json" },
    });
  }) as unknown as typeof fetch);
  const result = await fetchAgentWebResource("https://p.example/r");
  assert.equal(result.name, "Bounded");
});
