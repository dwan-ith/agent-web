import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AgentWebValidationError,
  linksByRel,
  validateResource,
  walkLinkedResources,
  type AgentWebResource,
} from "../src/index.js";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function fixture(folder: "valid" | "invalid", name: string): Promise<unknown> {
  const contents = await readFile(
    resolve(packageDirectory, "..", "conformance", folder, name),
    "utf8",
  );
  return JSON.parse(contents);
}

test("all valid conformance resources pass", async () => {
  for (const name of ["moltbook-collection.json", "moltbook-thread.json"]) {
    const resource = validateResource(await fixture("valid", name));
    assert.equal(resource.agentWeb.version, "0.2");
  }
});

test("invalid conformance resource is rejected", async () => {
  await assert.rejects(
    async () => validateResource(await fixture("invalid", "missing-identity.json")),
    AgentWebValidationError,
  );
});

test("browser follows typed links without Moltbook-specific parsing", async () => {
  const collection = validateResource(
    await fixture("valid", "moltbook-collection.json"),
  );
  const thread = validateResource(await fixture("valid", "moltbook-thread.json"));
  const resources = new Map<string, AgentWebResource>([
    [collection["@id"], collection],
    [thread["@id"], thread],
  ]);

  const walked = await walkLinkedResources(
    collection["@id"],
    async (url) => {
      const resource = resources.get(url);
      if (!resource) throw new Error(`Missing fixture ${url}`);
      return resource;
    },
  );

  assert.deepEqual(
    walked.map((resource) => resource["@id"]),
    [collection["@id"], thread["@id"]],
  );
  assert.equal(linksByRel(collection, "human-view")[0]?.mediaType, "text/html");
});

test("traversal resource limit is enforced", async () => {
  const collection = validateResource(
    await fixture("valid", "moltbook-collection.json"),
  );
  await assert.rejects(
    () => walkLinkedResources(collection["@id"], async () => collection, {
      maxResources: 0,
    }),
    /resource limit/,
  );
});

test("canonical and signing DID cross-field bindings are enforced", async () => {
  const resource = validateResource(
    await fixture("valid", "moltbook-thread.json"),
  );
  assert.throws(
    () =>
      validateResource({
        ...resource,
        provenance: {
          ...resource.provenance,
          canonical: "https://moltbook.example/other.json",
        },
      }),
    /canonical/,
  );
  assert.throws(
    () =>
      validateResource({
        ...resource,
        proof: {
          ...resource.proof,
          verificationMethod:
            "did:wba:attacker.example:agent:e1_fixture#key-1",
        },
      }),
    /publisher/,
  );
});
