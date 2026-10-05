import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { IntegrityEnvelope, SharedManifest } from "./types.ts";

/**
 * Persistence-time integrity protection for shared manifests.
 *
 * Structural recovery validation (see sharedValidation.ts) only proves a
 * persisted document has the right SHAPE: a backup restored after partial
 * corruption or a stray storage-layer write can flip a protected business
 * field to another perfectly legal value — diagnosis "benign" -> "malignant"
 * is still a string measurement, the aliases stay well formed, the original
 * contentHash keeps its 64-hex shape — and nothing structural would notice.
 *
 * The envelope closes that gap with two deployment-key-bound values:
 *  - contentDigest: SHA-256 over a canonical rendering of EVERY protected
 *    field of the stored document (batchId, createdAt, inbound contentHash,
 *    aliases, related aliases and measurement keys/values). It is derived
 *    from the persisted document itself, so recovery does not need the
 *    original raw identifiers to recompute it.
 *  - signature: HMAC-SHA256 keyed by the same deployment secret that mints
 *    aliases, binding contentDigest to batchId, the persisted file name
 *    (SHA-256(batchId)) and createdAt. Without the key a rewritten file
 *    cannot carry a valid envelope, and without changing the digest a
 *    tampered field cannot be re-signed.
 *
 * Canonical rendering sorts object keys and records, so verification is
 * independent of JSON key/record ordering while remaining sensitive to any
 * value change. The envelope exists solely for recovery: callers never see
 * it (the HTTP layer strips it from responses), and no envelope value is
 * ever derived from raw identifiers.
 */

export const INTEGRITY_ALG = "HS256" as const;
export const INTEGRITY_VERSION = 1 as const;
const HEX_64 = /^[0-9a-f]{64}$/;

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

/**
 * The authenticated payload: exactly the protected business content of a
 * persisted manifest, with the integrity envelope itself excluded (it is
 * verified, not authenticated by itself).
 */
function protectedPayload(manifest: Omit<SharedManifest, "integrity">): unknown {
  return {
    batchId: manifest.batchId,
    createdAt: manifest.createdAt,
    contentHash: manifest.contentHash,
    records: manifest.records.map((record) => ({
      recordAlias: record.recordAlias,
      patientAlias: record.patientAlias,
      accessionAlias: record.accessionAlias,
      relatedAliases: record.relatedAliases,
      measurements: record.measurements,
    })),
  };
}

export function canonicalDigestOf(manifest: Omit<SharedManifest, "integrity">): string {
  return createHash("sha256").update(stableStringify(protectedPayload(manifest)), "utf8").digest("hex");
}

/** Storage file name binding authenticated inside the signature. */
function fileName(batchId: string): string {
  return createHash("sha256").update(batchId, "utf8").digest("hex") + ".json";
}

function sign(secret: Buffer, batchId: string, createdAt: string, contentDigest: string): string {
  const message = [batchId, fileName(batchId), createdAt, contentDigest].join("\n");
  return createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

/** Mint the integrity envelope for a document at write time. */
export function sealManifest(
  manifest: Omit<SharedManifest, "integrity">,
  secret: Buffer,
): IntegrityEnvelope {
  const contentDigest = canonicalDigestOf(manifest);
  return {
    alg: INTEGRITY_ALG,
    version: INTEGRITY_VERSION,
    contentDigest,
    signature: sign(secret, manifest.batchId, manifest.createdAt, contentDigest),
  };
}

export type IntegrityCheck =
  | { ok: true }
  | { ok: false; code: string; path: string; message: string };

function fail(code: string, path: string, message: string): IntegrityCheck {
  return { ok: false, code, path, message };
}

/**
 * Recompute and verify the envelope of a structurally validated manifest.
 * Every returned failure carries a rule code and JSON path only; the
 * authenticated values themselves (which may be attacker-controlled) are
 * never embedded in the diagnostic.
 */
export function verifyManifestIntegrity(
  manifest: SharedManifest,
  secret: Buffer,
): IntegrityCheck {
  const envelope = manifest.integrity;
  if (envelope === null || typeof envelope !== "object" || Array.isArray(envelope)) {
    return fail("invalid_integrity_envelope", "$.integrity", "integrity envelope must be an object");
  }
  if (envelope.alg !== INTEGRITY_ALG) {
    return fail("invalid_integrity_alg", "$.integrity.alg", "unsupported integrity algorithm");
  }
  if (envelope.version !== INTEGRITY_VERSION) {
    return fail("invalid_integrity_version", "$.integrity.version", "unsupported integrity envelope version");
  }
  if (typeof envelope.contentDigest !== "string" || !HEX_64.test(envelope.contentDigest)) {
    return fail(
      "invalid_integrity_digest",
      "$.integrity.contentDigest",
      "contentDigest must be 64 lowercase hex characters",
    );
  }
  if (typeof envelope.signature !== "string" || !HEX_64.test(envelope.signature)) {
    return fail(
      "invalid_integrity_signature",
      "$.integrity.signature",
      "signature must be 64 lowercase hex characters",
    );
  }

  // Timing-safe comparison of the recomputed values (shape was checked above).
  const expectedDigest = canonicalDigestOf(manifest);
  if (!timingSafeEqualHex(envelope.contentDigest, expectedDigest)) {
    return fail(
      "content_digest_mismatch",
      "$.integrity.contentDigest",
      "persisted content does not match the authenticated digest",
    );
  }

  const expectedSignature = sign(
    secret,
    manifest.batchId,
    manifest.createdAt,
    envelope.contentDigest,
  );
  if (!timingSafeEqualHex(envelope.signature, expectedSignature)) {
    return fail(
      "integrity_signature_mismatch",
      "$.integrity.signature",
      "persisted manifest failed integrity signature verification",
    );
  }

  return { ok: true };
}

function timingSafeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "hex");
  const bufB = Buffer.from(b, "hex");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
