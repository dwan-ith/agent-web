/**
 * Strict Agent Web profile of RFC 9421 HTTP Message Signatures.
 *
 * A deliberate cross-language twin of `libagentweb.http_signatures` in
 * Python: same five mandatory components, same fixed parameters, same wire
 * format, same rejection reasons. Byte-level agreement is enforced by the
 * committed conformance vectors consumed by both implementations.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";

export const HTTP_SIGNATURE_SECURITY = "http-message-signature";
export const CALLER_HEADER = "Agent-Web-Caller";
const LABEL = "agentweb";
const COMPONENTS = [
  "@method",
  "@target-uri",
  "content-digest",
  "content-type",
  "agent-web-caller",
] as const;
const COMPONENT_LIST = COMPONENTS.map((name) => `"${name}"`).join(" ");
const SIGNATURE_INPUT = new RegExp(
  '^agentweb=\\("@method" "@target-uri" "content-digest" "content-type" ' +
    '"agent-web-caller"\\);created=([0-9]{1,15});expires=([0-9]{1,15});' +
    'keyid="([^"\\\\]{1,2048})";nonce="([A-Za-z0-9_-]{22,128})";alg="ed25519"$',
);
const SIGNATURE = new RegExp(`^${LABEL}=:([A-Za-z0-9+/]{86}==):$`);
const CONTENT_DIGEST = /^sha-256=:([A-Za-z0-9+/]{43}=):$/;

export type ReplayStore = {
  claim(caller: string, nonce: string, expires: number, now?: number): boolean;
};

export interface Signer {
  readonly keyId: string;
  readonly publicKeyMultibase?: string;
  sign(data: Uint8Array): Uint8Array;
}

export interface ControllerDocument {
  id: string;
  verificationMethod: Array<{
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase: string;
  }>;
  authentication: Array<string | { id: string }>;
}

/** Ed25519 signer over a raw 32-byte seed; mirrors LocalEd25519Signer. */
export class SeedSigner implements Signer {
  readonly keyId: string;
  readonly publicKeyMultibase: string;
  private readonly privateKey;

  constructor(seed: Uint8Array, keyId: string) {
    if (seed.length !== 32) throw new Error("Ed25519 seed must contain 32 bytes");
    this.keyId = keyId;
    const pkcs8 = Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]);
    this.privateKey = createPrivateKey({
      key: pkcs8,
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(this.privateKey).export({
      format: "der",
      type: "spki",
    });
    const raw = spki.subarray(spki.length - 32);
    this.publicKeyMultibase = `z${base58Encode(
      Buffer.concat([Buffer.from([0xed, 0x01]), raw]),
    )}`;
  }

  sign(data: Uint8Array): Uint8Array {
    return nodeSign(null, Buffer.from(data), this.privateKey);
  }
}

export function buildCallerController(
  caller: string,
  signer: Signer,
): ControllerDocument {
  validateController(caller);
  validateKeyId(signer.keyId, caller);
  if (!signer.publicKeyMultibase) {
    throw new Error("signer must publish its Multikey");
  }
  return {
    id: caller,
    verificationMethod: [
      {
        id: signer.keyId,
        type: "Multikey",
        controller: caller,
        publicKeyMultibase: signer.publicKeyMultibase,
      },
    ],
    authentication: [signer.keyId],
  };
}

export function signAgentWebRequest(options: {
  method: string;
  targetUri: string;
  body: Uint8Array;
  contentType: string;
  caller: string;
  signer: Signer;
  created?: number;
  expires?: number;
  nonce?: string;
}): Record<string, string> {
  const method = validateMethod(options.method);
  const targetUri = validateHttpsUri(options.targetUri);
  const contentType = validateContentType(options.contentType);
  const caller = validateController(options.caller);
  validateKeyId(options.signer.keyId, caller);
  const issued = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? issued + 120;
  if (expires <= issued || expires - issued > 300) {
    throw new Error("HTTP signature lifetime must be between 1 and 300 seconds");
  }
  const nonce = options.nonce ?? randomBytes(18).toString("base64url");
  if (!/^[A-Za-z0-9_-]{22,128}$/.test(nonce)) {
    throw new Error("HTTP signature nonce is invalid");
  }
  const contentDigest = contentDigestFor(options.body);
  const parameters = signatureParameters({
    created: issued,
    expires,
    keyId: options.signer.keyId,
    nonce,
  });
  const base = signatureBase({
    method,
    targetUri,
    contentDigest,
    contentType,
    caller,
    parameters,
  });
  const signature = options.signer.sign(Buffer.from(base, "ascii"));
  if (signature.length !== 64) {
    throw new Error("Ed25519 signer returned a non-64-byte signature");
  }
  const encoded = Buffer.from(signature).toString("base64");
  return {
    "Content-Digest": contentDigest,
    "Content-Type": contentType,
    [CALLER_HEADER]: caller,
    "Signature-Input": `${LABEL}=${parameters}`,
    Signature: `${LABEL}=:${encoded}:`,
  };
}

export interface AuthenticatedWebCaller {
  controller: string;
  keyId: string;
  created: number;
  expires: number;
  nonce: string;
}

export class HttpMessageSignatureError extends Error {}

export function verifyAgentWebRequest(options: {
  method: string;
  targetUri: string;
  body: Uint8Array;
  headers: Record<string, string | undefined>;
  controllerDocument: ControllerDocument;
  replayStore?: ReplayStore;
  now?: number;
  clockSkewSeconds?: number;
}): AuthenticatedWebCaller {
  const lowered: Record<string, string> = {};
  for (const [key, value] of Object.entries(options.headers)) {
    if (typeof value === "string") lowered[key.toLowerCase()] = value.trim();
  }
  const required = [
    "content-digest",
    "content-type",
    CALLER_HEADER.toLowerCase(),
    "signature-input",
    "signature",
  ];
  const missing = required.filter((name) => !lowered[name]);
  if (missing.length > 0) {
    throw new HttpMessageSignatureError(
      `authenticated request is missing ${missing.join(", ")}`,
    );
  }
  const match = SIGNATURE_INPUT.exec(lowered["signature-input"]);
  if (!match) {
    throw new HttpMessageSignatureError(
      "Signature-Input is outside the Agent Web profile",
    );
  }
  const created = Number(match[1]);
  const expires = Number(match[2]);
  const keyId = match[3];
  const nonce = match[4];
  const current = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.clockSkewSeconds ?? 30;
  if (expires <= created || expires - created > 300) {
    throw new HttpMessageSignatureError("signature lifetime is invalid");
  }
  if (created > current + skew) {
    throw new HttpMessageSignatureError("signature was created in the future");
  }
  if (expires < current - skew) {
    throw new HttpMessageSignatureError("signature has expired");
  }

  let caller: string;
  try {
    caller = validateController(lowered[CALLER_HEADER.toLowerCase()]);
  } catch (error) {
    throw new HttpMessageSignatureError((error as Error).message);
  }
  if (options.controllerDocument.id !== caller) {
    throw new HttpMessageSignatureError(
      "caller does not match its controller document",
    );
  }
  try {
    validateKeyId(keyId, caller);
  } catch (error) {
    throw new HttpMessageSignatureError((error as Error).message);
  }
  const authentication = options.controllerDocument.authentication;
  const authorized = new Set(
    Array.isArray(authentication)
      ? authentication.map((item) =>
          typeof item === "string" ? item : item?.id,
        )
      : [],
  );
  if (!authorized.has(keyId)) {
    throw new HttpMessageSignatureError(
      "signature key is not authorized for authentication",
    );
  }
  const methods = Array.isArray(options.controllerDocument.verificationMethod)
    ? options.controllerDocument.verificationMethod
    : [];
  const methodDocument = methods.find((item) => item && item.id === keyId);
  if (!methodDocument) {
    throw new HttpMessageSignatureError("signature key is not published");
  }
  if (methodDocument.controller !== caller) {
    throw new HttpMessageSignatureError(
      "signature key controller does not match caller",
    );
  }
  if (methodDocument.type !== "Multikey") {
    throw new HttpMessageSignatureError("signature key must use Multikey");
  }

  const digestMatch = CONTENT_DIGEST.exec(lowered["content-digest"]);
  if (!digestMatch) {
    throw new HttpMessageSignatureError(
      "Content-Digest must use RFC 9530 sha-256",
    );
  }
  const advertised = Buffer.from(digestMatch[1], "base64");
  if (!advertised.equals(digestFor(options.body))) {
    throw new HttpMessageSignatureError(
      "Content-Digest does not match the request body",
    );
  }

  const signatureMatch = SIGNATURE.exec(lowered["signature"]);
  if (!signatureMatch) {
    throw new HttpMessageSignatureError(
      "Signature is outside the Agent Web profile",
    );
  }
  let valid: boolean;
  try {
    const signature = Buffer.from(signatureMatch[1], "base64");
    const publicKey = multikeyToPublicKey(methodDocument.publicKeyMultibase);
    const parameters = lowered["signature-input"]
      .split("=")
      .slice(1)
      .join("=");
    const base = signatureBase({
      method: validateMethod(options.method),
      targetUri: validateHttpsUri(options.targetUri),
      contentDigest: lowered["content-digest"],
      contentType: validateContentType(lowered["content-type"]),
      caller,
      parameters,
    });
    valid = nodeVerify(null, Buffer.from(base, "ascii"), publicKey, signature);
  } catch {
    throw new HttpMessageSignatureError("HTTP message signature is invalid");
  }
  if (!valid) {
    throw new HttpMessageSignatureError("HTTP message signature is invalid");
  }
  if (
    options.replayStore &&
    !options.replayStore.claim(caller, nonce, expires, current)
  ) {
    throw new HttpMessageSignatureError(
      "HTTP message signature nonce was replayed",
    );
  }
  return { controller: caller, keyId, created, expires, nonce };
}

export class InMemoryReplayStore implements ReplayStore {
  private readonly claims = new Map<string, number>();

  claim(caller: string, nonce: string, expires: number, now?: number): boolean {
    const current = now ?? Math.floor(Date.now() / 1000);
    for (const [key, expiry] of this.claims) {
      if (expiry < current) this.claims.delete(key);
    }
    const key = `${caller}\n${nonce}`;
    if (this.claims.has(key)) return false;
    this.claims.set(key, expires);
    return true;
  }
}

function signatureParameters(input: {
  created: number;
  expires: number;
  keyId: string;
  nonce: string;
}): string {
  if (input.keyId.includes('"') || input.keyId.includes("\\")) {
    throw new Error("signing key identifier cannot be serialized safely");
  }
  return (
    `(${COMPONENT_LIST});created=${input.created};expires=${input.expires};` +
    `keyid="${input.keyId}";nonce="${input.nonce}";alg="ed25519"`
  );
}

function signatureBase(input: {
  method: string;
  targetUri: string;
  contentDigest: string;
  contentType: string;
  caller: string;
  parameters: string;
}): string {
  const values = [
    input.method,
    input.targetUri,
    input.contentDigest,
    input.contentType,
    input.caller,
  ];
  const lines = COMPONENTS.map((name, index) => `"${name}": ${values[index]}`);
  lines.push(`"@signature-params": ${input.parameters}`);
  return lines.join("\n");
}

function contentDigestFor(body: Uint8Array): string {
  return `sha-256=:${digestFor(body).toString("base64")}:`;
}

function digestFor(body: Uint8Array): Buffer {
  return createHash("sha256").update(Buffer.from(body)).digest();
}

function validateMethod(method: string): string {
  if (method !== method.toUpperCase()) {
    throw new Error(
      "signed HTTP method must use its canonical upper-case form",
    );
  }
  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    throw new Error("unsupported signed HTTP method");
  }
  return method;
}

function validateContentType(contentType: string): string {
  const value = String(contentType).trim().toLowerCase();
  if (value !== "application/json") {
    throw new Error("authenticated Agent Web actions require application/json");
  }
  return value;
}

function validateController(controller: string): string {
  const value = validateHttpsUri(controller);
  if (value.includes("?")) {
    throw new Error("caller controller must not contain a query");
  }
  return value;
}

function validateKeyId(keyId: string, controller: string): string {
  const prefix = `${controller}#`;
  if (!keyId.startsWith(prefix)) {
    throw new Error("signature key does not belong to caller");
  }
  const fragment = keyId.slice(prefix.length);
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(fragment)) {
    throw new Error("signature key fragment is invalid");
  }
  return keyId;
}

function validateHttpsUri(uri: string): string {
  for (const character of uri) {
    const code = character.charCodeAt(0);
    if (code < 0x21 || code > 0x7e) {
      throw new Error("HTTP signature URLs must use printable ASCII wire form");
    }
  }
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error("HTTP signature identifiers require absolute HTTPS URLs");
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error("HTTP signature identifiers require absolute HTTPS URLs");
  }
  const port =
    parsed.port === "" || parsed.port === "443" ? "" : `:${parsed.port}`;
  return `https://${parsed.hostname}${port}${parsed.pathname}${parsed.search}`;
}

function multikeyToPublicKey(multibase: string) {
  if (!multibase.startsWith("z")) {
    throw new HttpMessageSignatureError(
      "authentication key must be an Ed25519 Multikey",
    );
  }
  let encoded: Buffer;
  try {
    encoded = base58Decode(multibase.slice(1));
  } catch {
    throw new HttpMessageSignatureError("authentication Multikey is invalid");
  }
  if (encoded.length !== 34 || encoded[0] !== 0xed || encoded[1] !== 0x01) {
    throw new HttpMessageSignatureError(
      "authentication Multikey is not Ed25519",
    );
  }
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    encoded.subarray(2),
  ]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes: Uint8Array): string {
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      carry += digits[index] << 8;
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = "";
  for (const byte of bytes) {
    if (byte === 0) output += "1";
    else break;
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58_ALPHABET[digits[index]];
  }
  return output;
}

function base58Decode(value: string): Buffer {
  const bytes: number[] = [];
  for (const character of value) {
    const alphabetIndex = BASE58_ALPHABET.indexOf(character);
    if (alphabetIndex < 0) {
      throw new Error(`invalid base58 character: ${character}`);
    }
    let carry = alphabetIndex;
    for (let index = 0; index < bytes.length; index += 1) {
      carry += bytes[index] * 58;
      bytes[index] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  for (const character of value) {
    if (character === "1") zeros += 1;
    else break;
  }
  bytes.reverse();
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes)]);
}
