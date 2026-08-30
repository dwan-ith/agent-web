import assert from "node:assert/strict";
import { test } from "node:test";

import { browserApi } from "../src/api.js";

interface CapturedInit {
  headers?: Record<string, string>;
}

function fakeStatusResponse(): Response {
  return new Response(
    JSON.stringify({
      ready: true,
      callerDid: null,
      callerController: null,
      allowedOrigins: [],
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

function injectMetaToken(token: string | null): void {
  (globalThis as Record<string, unknown>).document = token
    ? {
        querySelector: () => ({ getAttribute: () => token }),
      }
    : { querySelector: () => null };
}

function clearDocument(): void {
  delete (globalThis as Record<string, unknown>).document;
}

test("the UI client sends the injected daemon session token", async () => {
  const captured: CapturedInit[] = [];
  injectMetaToken("injected-session-token");
  try {
    await browserApi.status((async (
      _url: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      captured.push({ headers: init?.headers as Record<string, string> });
      return fakeStatusResponse();
    }) as typeof fetch);
  } finally {
    clearDocument();
  }
  assert.equal(captured.length, 1);
  assert.equal(
    captured[0].headers?.["X-Agent-Web-Browser-Token"],
    "injected-session-token",
  );
});

test("without an injected token no session header is sent", async () => {
  const captured: CapturedInit[] = [];
  clearDocument();
  try {
    await browserApi.status((async (
      _url: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      captured.push({ headers: init?.headers as Record<string, string> });
      return fakeStatusResponse();
    }) as typeof fetch);
  } finally {
    clearDocument();
  }
  assert.equal(captured.length, 1);
  assert.equal(captured[0].headers?.["X-Agent-Web-Browser-Token"], undefined);
});

test("mutations carry the token alongside JSON content type", async () => {
  const captured: CapturedInit[] = [];
  injectMetaToken("mutation-token");
  try {
    await browserApi.connect(
      "https://publisher.example/.well-known/agent-web",
      (async (
        _url: RequestInfo | URL,
        init?: RequestInit,
      ) => {
        captured.push({ headers: init?.headers as Record<string, string> });
        return new Response(
          JSON.stringify({
            status: {
              ready: true,
              callerDid: null,
              callerController: null,
              allowedOrigins: [],
            },
            entry: { resource: {}, verified: true },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as typeof fetch,
    );
  } finally {
    clearDocument();
  }
  assert.equal(
    captured[0].headers?.["X-Agent-Web-Browser-Token"],
    "mutation-token",
  );
  assert.equal(captured[0].headers?.["Content-Type"], "application/json");
});
