import type { AgentWebResource } from "@agent-web/core";

export interface BrowserStatus {
  ready: boolean;
  callerDid: string | null;
  callerController: string | null;
  connectedAgent?: {
    name: string;
    description: string;
    url: string;
    binding?: string;
    handle?: string;
    bindingGeneration?: string;
  };
  allowedOrigins: string[];
}

export interface OpenResult {
  resource: AgentWebResource;
  verified: true;
}

function daemonToken(): string | null {
  if (typeof document === "undefined") return null;
  const meta = document.querySelector<HTMLMetaElement>(
    'meta[name="agent-web-daemon-token"]',
  );
  return meta?.getAttribute("content") ?? null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  fetcher: typeof fetch = fetch,
): Promise<T> {
  const token = daemonToken();
  const response = await fetcher(path, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { "X-Agent-Web-Browser-Token": token } : {}),
      ...init.headers,
    },
  });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail =
      typeof value.detail === "string" ? value.detail : `HTTP ${response.status}`;
    throw new Error(detail);
  }
  return value as T;
}

export const browserApi = {
  status(fetcher?: typeof fetch): Promise<BrowserStatus> {
    return request("/api/status", {}, fetcher);
  },
  connect(
    agentDescriptionUrl: string,
    fetcher?: typeof fetch,
  ): Promise<{ status: BrowserStatus; entry: OpenResult }> {
    return request(
      "/api/connect",
      {
        method: "POST",
        body: JSON.stringify({ agentDescriptionUrl }),
      },
      fetcher,
    );
  },
  open(resourceUrl: string, fetcher?: typeof fetch): Promise<OpenResult> {
    return request(
      "/api/open",
      {
        method: "POST",
        body: JSON.stringify({ resourceUrl }),
      },
      fetcher,
    );
  },
  allowOrigin(origin: string, fetcher?: typeof fetch): Promise<BrowserStatus> {
    return request(
      "/api/origins",
      {
        method: "POST",
        body: JSON.stringify({ origin }),
      },
      fetcher,
    );
  },
  call(
    method: string,
    params: Record<string, unknown>,
    confirmed: boolean,
    resourceUrl?: string,
    fetcher?: typeof fetch,
  ): Promise<OpenResult> {
    return request(
      "/api/actions",
      {
        method: "POST",
        body: JSON.stringify({ method, params, confirmed, resourceUrl }),
      },
      fetcher,
    );
  },
};
