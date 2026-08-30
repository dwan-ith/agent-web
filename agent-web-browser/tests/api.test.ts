import assert from "node:assert/strict";
import test from "node:test";

import { browserApi } from "../src/api";

test("connect sends a live Agent Description URL to the local daemon", async () => {
  let request: Request | undefined;
  const fetcher: typeof fetch = async (input, init) => {
    request = new Request(new URL(String(input), "http://localhost"), init);
    return Response.json({
      status: {
        ready: true,
        callerDid: "did:wba:browser.test:agents:browser:e1_test",
        callerController: "https://browser.test/.well-known/agent-web-caller",
        allowedOrigins: ["https://moltbook.test"],
      },
      entry: { verified: true, resource: {} },
    });
  };
  await browserApi.connect("https://moltbook.test/ad.json", fetcher);
  assert.equal(request?.url, "http://localhost/api/connect");
  assert.equal(request?.method, "POST");
  assert.deepEqual(await request?.json(), {
    agentDescriptionUrl: "https://moltbook.test/ad.json",
  });
});

test("action execution carries explicit confirmation state", async () => {
  let body: unknown;
  const fetcher: typeof fetch = async (input, init) => {
    body = JSON.parse(String(init?.body));
    return Response.json({ verified: true, resource: {} });
  };
  await browserApi.call(
    "create_thread",
    { title: "Live" },
    true,
    "https://moltbook.test/resources/index.json",
    fetcher,
  );
  assert.deepEqual(body, {
    method: "create_thread",
    params: { title: "Live" },
    confirmed: true,
    resourceUrl: "https://moltbook.test/resources/index.json",
  });
});

test("daemon error details are surfaced", async () => {
  const fetcher: typeof fetch = async () =>
    Response.json({ detail: "object proof is invalid" }, { status: 400 });
  await assert.rejects(
    browserApi.open("https://bad.test/resource.json", fetcher),
    /object proof is invalid/,
  );
});

test("requests carry the injected daemon session token", async () => {
  globalThis.document = {
    querySelector: ((selector: string) =>
      selector === 'meta[name="agent-web-daemon-token"]'
        ? { getAttribute: () => "injected-token" }
        : null) as unknown as Document["querySelector"],
  } as unknown as Document;
  try {
    let headers: Headers | undefined;
    const fetcher: typeof fetch = async (_input, init) => {
      headers = new Request(new URL("http://localhost/api/status"), init)
        .headers;
      return Response.json({ ready: true, allowedOrigins: [] });
    };
    await browserApi.status(fetcher);
    assert.equal(headers?.get("X-Agent-Web-Browser-Token"), "injected-token");
  } finally {
    delete (globalThis as { document?: Document }).document;
  }
});

test("requests omit the token header when no meta tag is present", async () => {
  let headers: Headers | undefined;
  const fetcher: typeof fetch = async (_input, init) => {
    headers = new Request(new URL("http://localhost/api/status"), init).headers;
    return Response.json({ ready: true, allowedOrigins: [] });
  };
  await browserApi.status(fetcher);
  assert.equal(headers?.get("X-Agent-Web-Browser-Token"), null);
});
