import resourceSchema from "../../python/src/libagentweb/schemas/agent-web-resource.schema.json" with {
  type: "json",
};
import {
  Ajv2020,
  type ErrorObject,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";

export const AGENT_WEB_VERSION = "0.2" as const;
export const RESOURCE_MEDIA_TYPE = "application/agent-web+json" as const;

export type AgentWebKind = "resource" | "collection" | "service";
export type AgentWebProtocol = "ANP" | "A2A" | "MCP" | "HTTP";

export interface AgentWebLink {
  rel: string;
  href: string;
  mediaType?: string;
  title?: string;
}

export interface AgentWebInterface {
  protocol: AgentWebProtocol;
  href: string;
  method?: string;
  contentType?: string;
}

export interface AgentWebAction {
  description: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
  safe: boolean;
  idempotent: boolean;
  authorizationLevel: "normal" | "user-presence-required";
  interfaces: AgentWebInterface[];
}

export interface AgentWebResource {
  "@context": string | Record<string, unknown> | Array<string | Record<string, unknown>>;
  "@id": string;
  "@type": string | string[];
  agentWeb: {
    version: typeof AGENT_WEB_VERSION;
    kind: AgentWebKind;
  };
  name: string;
  description?: string;
  links: AgentWebLink[];
  affordances: {
    properties: Record<string, unknown>;
    actions: Record<string, AgentWebAction>;
    events: Record<string, unknown>;
  };
  provenance: {
    publisher: string;
    createdAt: string;
    updatedAt: string;
    expiresAt?: string;
    canonical: string;
    sources?: string[];
  };
  data: unknown;
  proof: {
    type: "DataIntegrityProof";
    cryptosuite: "eddsa-jcs-2022";
    verificationMethod: string;
    proofPurpose: "assertionMethod";
    created: string;
    proofValue: string;
  };
  extensions?: Record<string, unknown>;
}

export class AgentWebValidationError extends Error {
  constructor(public readonly errors: ErrorObject[]) {
    super(
      errors
        .map((error) => `${error.instancePath || "<root>"}: ${error.message}`)
        .join("; "),
    );
    this.name = "AgentWebValidationError";
  }
}

let validator: ValidateFunction | undefined;

function resourceValidator(): ValidateFunction {
  if (validator) return validator;
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    allowUnionTypes: true,
  });
  const addFormats = addFormatsModule as unknown as (instance: Ajv2020) => Ajv2020;
  addFormats(ajv);
  const compiled = ajv.compile(resourceSchema);
  validator = compiled;
  return compiled;
}

export function validateResource(value: unknown): AgentWebResource {
  const validate = resourceValidator();
  if (!validate(value)) {
    throw new AgentWebValidationError(validate.errors ?? []);
  }
  const resource = value as AgentWebResource;
  if (resource.provenance.canonical !== resource["@id"]) {
    throw new AgentWebValidationError([
      {
        instancePath: "/provenance/canonical",
        schemaPath: "#/cross-field",
        keyword: "const",
        params: {},
        message: "must exactly match @id",
      },
    ]);
  }
  if (
    !resource.proof.verificationMethod.startsWith(
      `${resource.provenance.publisher}#`,
    )
  ) {
    throw new AgentWebValidationError([
      {
        instancePath: "/proof/verificationMethod",
        schemaPath: "#/cross-field",
        keyword: "pattern",
        params: {},
        message: "must belong to provenance.publisher",
      },
    ]);
  }
  const created = Date.parse(resource.provenance.createdAt);
  const updated = Date.parse(resource.provenance.updatedAt);
  if (updated < created) {
    throw new AgentWebValidationError([
      {
        instancePath: "/provenance/updatedAt",
        schemaPath: "#/cross-field",
        keyword: "format",
        params: {},
        message: "must not precede createdAt",
      },
    ]);
  }
  if (
    resource.provenance.expiresAt !== undefined &&
    Date.parse(resource.provenance.expiresAt) <= updated
  ) {
    throw new AgentWebValidationError([
      {
        instancePath: "/provenance/expiresAt",
        schemaPath: "#/cross-field",
        keyword: "format",
        params: {},
        message: "must be later than updatedAt",
      },
    ]);
  }
  return structuredClone(resource);
}

export function linksByRel(
  resource: AgentWebResource,
  rel: string,
): AgentWebLink[] {
  return resource.links
    .filter((link) => link.rel === rel)
    .map((link) => structuredClone(link));
}

export async function walkLinkedResources(
  entrypoint: string,
  fetchResource: (url: string) => Promise<unknown>,
  options: {
    rels?: ReadonlySet<string>;
    maxResources?: number;
  } = {},
): Promise<AgentWebResource[]> {
  const rels = options.rels ?? new Set(["item", "next", "related"]);
  const maxResources = options.maxResources ?? 100;
  const queue = [entrypoint];
  const visited = new Set<string>();
  const resources: AgentWebResource[] = [];

  while (queue.length > 0) {
    const target = queue.shift()!;
    if (visited.has(target)) continue;
    if (visited.size >= maxResources) {
      throw new Error("Agent Web traversal exceeded its resource limit");
    }
    visited.add(target);

    const resource = validateResource(await fetchResource(target));
    resources.push(resource);
    for (const link of resource.links) {
      if (rels.has(link.rel) && !visited.has(link.href)) {
        queue.push(link.href);
      }
    }
  }
  return resources;
}

export async function fetchAgentWebResource(
  url: string,
  fetcher: typeof fetch = fetch,
): Promise<AgentWebResource> {
  const response = await fetcher(url, {
    headers: { Accept: RESOURCE_MEDIA_TYPE },
  });
  if (!response.ok) {
    throw new Error(`Agent Web request failed with HTTP ${response.status}`);
  }
  return validateResource(await response.json());
}
