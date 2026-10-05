import { createHmac, timingSafeEqual } from "node:crypto";
import type { SharedManifest } from "./types.ts";

/**
 * Persistence integrity protection for shared manifests.
 *
 * The business `contentHash` binds the ORIGINAL request content (canonicalized
 * raw identifiers) for idempotency/conflict comparison, but the persisted
 * document only carries irreversible aliases: the raw content can never be
 * reconstructed on recovery, so contentHash alone cannot vouch for the bytes at
 * rest. A backup bit-flip or stray storage-layer write can therefore replace a
 * protected business value (e.g. measurement `diagnosis: "benign"`) with
 * another perfectly legal scalar (`"malignant"`) while leaving batchId, file
 * name, alias formats, createdAt and the original contentHash untouched. Such
 * an entry passes every format check, becomes queryable, and — because the
 * untouched contentHash still matches a retry of the original request — is even
 * served as an "idempotent replay".
 *
 * The seal closes that gap: every persisted document is tagged with an
 * HMAC-SHA256 over a canonical rendering of the FULL shared manifest, keyed by
 * the stable deployment secret (the same secret that makes aliases stable).
 * The HMAC message is domain-separated from alias derivation so a manifest tag
 * can never be confused with an identifier digest. Recovery recomputes the tag
 * before admitting an entry; any protected-field rewrite invalidates it, and
 * forging a valid tag requires the secret.
 *
 * The seal exists strictly inside the persistence layer. It is never part of
 * {@link SharedManifest}, never leaves the store and never appears in an API
 * response: shared copies keep their existing wire contract exactly.
 */

/** Domain-separation prefix, distinct from the aliaser's "patient|accession|record" labels. */
const SEAL_DOMAIN = "shared-manifest-seal-v1";

export interface ProtectiveMetadata {
  /** HMAC-SHA256 over the canonical sealed document, lowercase hex. */
  seal: string;
  /** Domain label/version of the sealing scheme; only the current value is accepted. */
  sealAlgo: typeof SEAL_DOMAIN;
}

/** On-disk envelope: the shared document plus its persistence-only integrity tag. */
export interface IntegrityEnvelope {
  v: 1;
  manifest: SharedManifest;
  protection: ProtectiveMetadata;
}

function canonicalizeManifest(manifest: SharedManifest): string {
  return stableStringify(manifest);
}

/**
 * Deterministic JSON rendering: object keys sorted, arrays preserved, so the
 * same document always yields the same tagged bytes regardless of on-disk
 * member order.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

/** Compute the integrity tag for a shared manifest under the deployment secret. */
export function computeSeal(manifest: SharedManifest, secret: Buffer): string {
  return createHmac("sha256", secret)
    .update(SEAL_DOMAIN, "utf8")
    .update(Buffer.from([0]))
    .update(canonicalizeManifest(manifest), "utf8")
    .digest("hex");
}

/** Wrap a shared manifest in its sealed persistence envelope. */
export function sealManifest(manifest: SharedManifest, secret: Buffer): IntegrityEnvelope {
  return {
    v: 1,
    manifest,
    protection: { seal: computeSeal(manifest, secret), sealAlgo: SEAL_DOMAIN },
  };
}

/**
 * Verify a sealed envelope: the tag must be a well-formed 64-hex HMAC matching
 * the document under the given secret, and the algorithm label must be the
 * current one. Returns false (never throws) on any malformed or mismatched
 * tag; callers treat that exactly like any other recovery-contract failure.
 */
export function verifyEnvelope(envelope: IntegrityEnvelope, secret: Buffer): boolean {
  const protection = envelope.protection;
  if (protection === null || typeof protection !== "object") return false;
  if (protection.sealAlgo !== SEAL_DOMAIN) return false;
  if (typeof protection.seal !== "string" || !/^[0-9a-f]{64}$/.test(protection.seal)) {
    return false;
  }
  const expected = computeSeal(envelope.manifest, secret);
  const a = Buffer.from(protection.seal, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
