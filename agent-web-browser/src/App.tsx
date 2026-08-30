import {
  linksByRel,
  validateResource,
  type AgentWebAction,
  type AgentWebResource,
} from "@agent-web/core";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { browserApi, type BrowserStatus } from "./api";

const MAX_HISTORY = 100;

type Pending =
  | { kind: "origin"; origin: string; target: string }
  | { kind: "action"; name: string; action: AgentWebAction }
  | null;

export function App() {
  const [status, setStatus] = useState<BrowserStatus | null>(null);
  const [resource, setResource] = useState<AgentWebResource | null>(null);
  const [descriptionUrl, setDescriptionUrl] = useState("");
  const [address, setAddress] = useState("");
  const [history, setHistory] = useState<AgentWebResource[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [pending, setPending] = useState<Pending>(null);
  const [parameters, setParameters] = useState<Record<string, string>>({});
  const [raw, setRaw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(
    "Connect to /.well-known/agent-web. ANP Agent Descriptions and WNS handles remain optional compatibility inputs.",
  );
  const [error, setError] = useState("");

  useEffect(() => {
    browserApi.status().then(setStatus).catch((reason: Error) => {
      setError(`The local browser daemon is unavailable: ${reason.message}`);
    });
  }, []);

  const actions = useMemo(
    () => Object.entries(resource?.affordances.actions ?? {}),
    [resource],
  );

  function commit(next: AgentWebResource) {
    const validated = validateResource(next);
    // Bound the in-memory session so a long browsing session cannot grow
    // without limit; dropping the oldest entries keeps the newest context.
    const nextHistory = [
      ...history.slice(0, historyIndex + 1).slice(-MAX_HISTORY - 1),
      validated,
    ];
    setHistory(nextHistory);
    setHistoryIndex(nextHistory.length - 1);
    setResource(validated);
    setAddress(validated["@id"]);
    setParameters({});
  }

  async function connect(event: FormEvent) {
    event.preventDefault();
    await perform(async () => {
      const result = await browserApi.connect(descriptionUrl);
      setStatus(result.status);
      commit(result.entry.resource);
      setNotice(
        `Verified ${result.status.connectedAgent?.name ?? "agent"} and its entry resource.`,
      );
    });
  }

  async function open(target: string, originApproved = false) {
    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch {
      setError("Enter an absolute HTTPS resource URL.");
      return;
    }
    if (parsed.protocol !== "https:") {
      setError("Agent Web resources must use HTTPS.");
      return;
    }
    if (!status?.allowedOrigins.includes(parsed.origin) && !originApproved) {
      setPending({ kind: "origin", origin: parsed.origin, target });
      return;
    }
    await perform(async () => {
      const result = await browserApi.open(target);
      commit(result.resource);
      setNotice(
        `Verified signature and DID binding for ${result.resource.provenance.publisher}.`,
      );
    });
  }

  async function approveOrigin() {
    if (pending?.kind !== "origin") return;
    const request = pending;
    await perform(async () => {
      const nextStatus = await browserApi.allowOrigin(request.origin);
      setStatus(nextStatus);
      setPending(null);
      await open(request.target, true);
    });
  }

  async function executeAction(
    name: string,
    action: AgentWebAction,
    confirmed: boolean,
  ) {
    const params: Record<string, unknown> = {};
    const properties = (action.input.properties ?? {}) as Record<
      string,
      Record<string, unknown>
    >;
    const required = Array.isArray(action.input.required)
      ? (action.input.required as string[])
      : [];
    const missing = required.filter(
      (field) => !(parameters[`${name}:${field}`] ?? "").trim(),
    );
    if (missing.length > 0) {
      setError(`Provide values for: ${missing.join(", ")}.`);
      return;
    }
    for (const [field, schema] of Object.entries(properties)) {
      const value = parameters[`${name}:${field}`] ?? "";
      if ("const" in schema) params[field] = schema.const;
      else if (schema.type === "number" || schema.type === "integer") {
        const parsed = Number(value);
        if (!Number.isFinite(parsed)) {
          setError(`${field} must be a finite number.`);
          return;
        }
        params[field] = parsed;
      } else if (schema.type === "boolean") params[field] = value === "true";
      else params[field] = value;
    }
    await perform(async () => {
      const result = await browserApi.call(
        name,
        params,
        confirmed,
        resource?.["@id"],
      );
      commit(result.resource);
      setPending(null);
      setNotice(
        `Executed ${name} through ${status?.connectedAgent?.binding ?? "the advertised interface"}.`,
      );
    });
  }

  function reviewAction(name: string, action: AgentWebAction) {
    if (action.authorizationLevel === "user-presence-required") {
      setPending({ kind: "action", name, action });
    } else {
      void executeAction(name, action, false);
    }
  }

  function moveHistory(index: number) {
    const next = history[index];
    if (!next) return;
    const expiresAt = next.provenance.expiresAt;
    if (expiresAt && Date.parse(expiresAt) <= Date.now()) {
      setError(
        "This historical resource has expired; reopen it to fetch a freshly signed copy.",
      );
      return;
    }
    setHistoryIndex(index);
    setResource(next);
    setAddress(next["@id"]);
    setNotice("Moved through verified local history.");
  }

  async function perform(operation: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await operation();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Operation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell">
      <header className="toolbar">
        <div className="brand">
          <b>AW</b>
          <span>
            <strong>Agent Web Browser</strong>
            <small>HTTPS · signed resources · optional protocol adapters</small>
          </span>
        </div>
        <div className="history-controls">
          <button aria-label="Back" disabled={historyIndex <= 0} onClick={() => moveHistory(historyIndex - 1)}>←</button>
          <button aria-label="Forward" disabled={historyIndex >= history.length - 1} onClick={() => moveHistory(historyIndex + 1)}>→</button>
        </div>
        <form className="address" onSubmit={(event) => { event.preventDefault(); void open(address); }}>
          <span className={resource ? "trust live" : "trust"} />
          <input aria-label="Agent Web resource address" value={address} onChange={(event) => setAddress(event.target.value)} placeholder="https://agent.example/resources/index.json" disabled={!resource} />
          <button disabled={!resource || busy}>Open</button>
        </form>
      </header>

      {!resource ? (
        <section className="connect-view">
          <div className="connect-card">
            <span className="eyebrow">LIVE DISCOVERY</span>
            <h1>Open an agent-native site</h1>
            <p>The browser verifies HTTPS Web discovery, publisher keys, resource proofs, canonical URLs, and every link it opens. ANP discovery is optional.</p>
            <form onSubmit={connect}>
              <label htmlFor="ad-url">Agent Web discovery URL or optional ANP/WNS input</label>
              <input id="ad-url" value={descriptionUrl} onChange={(event) => setDescriptionUrl(event.target.value)} placeholder="moltbook.agent.example or https://agent.example/agent/ad.json" required />
              <button disabled={busy}>{busy ? "Verifying…" : "Discover and open"}</button>
            </form>
            <dl>
              <div><dt>Browser identity</dt><dd>{status?.callerController ?? status?.callerDid ?? "Loading local identity…"}</dd></div>
              <div><dt>Private key</dt><dd>Held by the loopback daemon; never sent to this UI.</dd></div>
              <div><dt>WNS verification</dt><dd>Exact handle-to-DID reverse binding with its continuity generation reported.</dd></div>
              <div><dt>Demo graph</dt><dd>None. Every resource shown is fetched live.</dd></div>
            </dl>
          </div>
        </section>
      ) : (
        <div className="workspace">
          <aside>
            <span className="eyebrow">TRUSTED SESSION</span>
            <div className="identity"><small>CALLER IDENTITY</small><code>{status?.callerController ?? status?.callerDid ?? "none configured"}</code></div>
            <div className="identity"><small>PUBLISHER</small><code>{resource.provenance.publisher}</code></div>
            <div className="metrics">
              <div><b>{history.length}</b><span>verified opens</span></div>
              <div><b>{status?.allowedOrigins.length ?? 0}</b><span>allowed origins</span></div>
              <div><b>{linksByRel(resource, "related").length}</b><span>cross-site links</span></div>
            </div>
            <button className="disconnect" onClick={() => { setResource(null); setHistory([]); setHistoryIndex(-1); }}>Connect elsewhere</button>
          </aside>
          <section className="resource-view">
            <div className="resource-title">
              <div><span className="verified">PROOF VERIFIED</span><h1>{resource.name}</h1><p>{resource.description}</p></div>
              <div className="kind"><small>RESOURCE KIND</small><strong>{resource.agentWeb.kind}</strong><code>{safeUrlPart(resource["@id"], (url) => url.origin)}</code></div>
            </div>
            <div className="notice">{notice}</div>
            {error && <div className="error" role="alert">{error}</div>}
            <div className="columns">
              <section className="panel">
                <header><div><span className="eyebrow">STRUCTURED CONTENT</span><h2>Data</h2></div><button className="text" onClick={() => setRaw(!raw)}>{raw ? "Readable" : "JSON"}</button></header>
                {raw ? <pre>{JSON.stringify(resource, null, 2)}</pre> : <Readable value={resource.data} />}
              </section>
              <section className="panel">
                <header><div><span className="eyebrow">TYPED LINKS</span><h2>Navigate</h2></div><b>{resource.links.length}</b></header>
                <div className="links">
                  {resource.links.filter((link) => link.rel !== "self").map((link) => (
                    <button key={`${link.rel}:${link.href}`} onClick={() => void open(link.href)}>
                      <span>{link.rel}</span><div><strong>{link.title ?? safeUrlPart(link.href, (url) => url.pathname)}</strong><small>{safeUrlPart(link.href, (url) => url.host)}</small></div><b>↗</b>
                    </button>
                  ))}
                </div>
              </section>
            </div>
            <section className="panel actions">
              <header><div><span className="eyebrow">ADVERTISED AFFORDANCES</span><h2>Actions</h2></div><b>{actions.length}</b></header>
              {actions.length === 0 ? <p className="empty">No actions are advertised by this resource.</p> : (
                <div className="action-grid">{actions.map(([name, action]) => (
                  <article key={name}>
                    <span className={action.authorizationLevel === "normal" ? "safe" : "review"}>{action.authorizationLevel}</span>
                    <h3>{name}</h3><p>{action.description}</p>
                    <ActionFields name={name} action={action} values={parameters} setValues={setParameters} />
                    <button onClick={() => reviewAction(name, action)} disabled={busy}>{action.authorizationLevel === "user-presence-required" ? "Review and execute" : "Execute"}</button>
                  </article>
                ))}</div>
              )}
            </section>
          </section>
        </div>
      )}
      {error && !resource && <div className="global-error" role="alert">{error}</div>}
      {pending && (
        <div className="backdrop"><section className="modal" role="dialog" aria-modal="true">
          <span className="eyebrow">{pending.kind === "origin" ? "ORIGIN POLICY" : "USER PRESENCE REQUIRED"}</span>
          <h2>{pending.kind === "origin" ? "Trust this HTTPS origin?" : `Execute ${pending.name}?`}</h2>
          {pending.kind === "origin" ? <><p>The link crosses to a publisher not yet allowed in this browser session.</p><code>{pending.origin}</code></> : <><p>{pending.action.description}</p><dl><div><dt>Safe</dt><dd>{String(pending.action.safe)}</dd></div><div><dt>Idempotent</dt><dd>{String(pending.action.idempotent)}</dd></div></dl></>}
          <footer><button className="secondary" onClick={() => setPending(null)}>Cancel</button><button onClick={() => pending.kind === "origin" ? void approveOrigin() : void executeAction(pending.name, pending.action, true)} disabled={busy}>{pending.kind === "origin" ? "Allow for session" : "Confirm and execute"}</button></footer>
        </section></div>
      )}
    </main>
  );
}

function safeUrlPart(href: string, select: (url: URL) => string): string {
  try {
    return select(new URL(href));
  } catch {
    return href;
  }
}

function ActionFields({
  name,
  action,
  values,
  setValues,
}: {
  name: string;
  action: AgentWebAction;
  values: Record<string, string>;
  setValues: (next: Record<string, string>) => void;
}) {
  const properties = (action.input.properties ?? {}) as Record<string, Record<string, unknown>>;
  return (
    <div className="fields">
      {Object.entries(properties).map(([field, schema]) => {
        if ("const" in schema) {
          return <input key={field} type="hidden" value={String(schema.const)} readOnly />;
        }
        const key = `${name}:${field}`;
        return (
          <label key={field}>
            {field}
            <input
              value={values[key] ?? ""}
              onChange={(event) => setValues({ ...values, [key]: event.target.value })}
              required={Array.isArray(action.input.required) && action.input.required.includes(field)}
            />
          </label>
        );
      })}
    </div>
  );
}

function Readable({ value }: { value: unknown }) {
  if (!value || typeof value !== "object") return <p>{String(value)}</p>;
  return (
    <dl className="data">
      {Object.entries(value as Record<string, unknown>).map(([key, item]) => (
        <div key={key}>
          <dt>{key.replace(/([A-Z])/g, " $1")}</dt>
          <dd>{Array.isArray(item) ? `${item.length} items` : typeof item === "object" ? JSON.stringify(item) : String(item)}</dd>
        </div>
      ))}
    </dl>
  );
}
