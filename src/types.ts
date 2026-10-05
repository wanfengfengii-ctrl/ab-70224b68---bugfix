/**
 * Core domain types for the pathology manifest collaboration service.
 *
 * Privacy boundary: `Input*` types carry institution-local identifiers and must
 * never leave the process in logs, responses or persisted files. `Shared*`
 * types carry only irreversible per-category aliases and are safe to share.
 */

export const ID_CLASSES = ["patient", "accession", "record"] as const;
export type IdClass = (typeof ID_CLASSES)[number];

export type MeasurementValue = string | number | boolean | null;

export interface InputRecord {
  recordId: string;
  patientId: string;
  accessionId: string;
  /** Normalized: de-duplicated, lexicographically sorted. */
  relatedIds: string[];
  measurements: Record<string, MeasurementValue>;
}

export interface InputBatch {
  batchId: string;
  records: InputRecord[];
}

export interface SharedRecord {
  recordAlias: string;
  patientAlias: string;
  accessionAlias: string;
  relatedAliases: string[];
  measurements: Record<string, MeasurementValue>;
}

/**
 * Authenticity envelope embedded in every persisted shared manifest.
 *
 * The write path seals the document with the deployment key: `contentDigest`
 * is the SHA-256 of the canonicalized full business payload (every protected
 * field — aliases, related aliases, measurements, batchId, createdAt and the
 * inbound contentHash), and `signature` is a keyed HMAC binding that digest to
 * the batchId, file name and createdAt. Recovery recomputes both values, so a
 * backup/storage modification that flips a protected field to another legal
 * value (e.g. diagnosis "benign" -> "malignant") is detected even though the
 * resulting JSON is structurally valid.
 *
 * The envelope is recovery metadata: it is verified at load time but never
 * appears in a shared API response. The key never leaves the deployment, so an
 * attacker who can rewrite files cannot forge a matching signature.
 */
export interface IntegrityEnvelope {
  alg: "HS256";
  version: 1;
  /** SHA-256 (64 lowercase hex) of the canonicalized protected payload. */
  contentDigest: string;
  /** HMAC-SHA256 (64 lowercase hex) over the digest/batchId/file binding. */
  signature: string;
}

export interface SharedManifest {
  batchId: string;
  createdAt: string;
  contentHash: string;
  records: SharedRecord[];
  integrity: IntegrityEnvelope;
}

export interface ValidationIssue {
  code: string;
  path: string;
  message: string;
}

/**
 * Machine-readable marker appended when more issues were found than the
 * shared diagnostic cap allows reporting. It never carries field values.
 */
export interface IssueTruncation {
  code: "issues_truncated";
  /** Number of field-level issues retained (the shared deterministic cap). */
  limit: number;
  /** Number of issues actually present in `issues` (always === limit here). */
  reported: number;
  /** Number of additional issues that were found but not expanded. */
  remaining: number;
}

/** Payload failed structural / referential validation -> HTTP 422. */
export class ValidationFailed extends Error {
  readonly issues: ValidationIssue[];
  readonly truncation: IssueTruncation | null;

  constructor(issues: ValidationIssue[], truncation: IssueTruncation | null = null) {
    super("manifest validation failed");
    this.name = "ValidationFailed";
    this.issues = issues;
    this.truncation = truncation;
  }
}

/**
 * A persisted shared manifest failed recovery validation during store load.
 * The service must refuse to start rather than serve or silently overwrite
 * the corrupt entry. Issues carry only rule codes and JSON paths, never the
 * offending values (a corrupt file may contain raw identifiers).
 */
export class CorruptManifestError extends Error {
  readonly issues: ValidationIssue[];
  readonly truncation: IssueTruncation | null;

  constructor(issues: ValidationIssue[], truncation: IssueTruncation | null = null) {
    super("persisted manifest failed recovery validation");
    this.name = "CorruptManifestError";
    this.issues = issues;
    this.truncation = truncation;
  }
}

/** A manifest already exists for the batchId with different content -> HTTP 409. */
export class BatchConflictError extends Error {
  readonly batchId: string;

  constructor(batchId: string) {
    super("a manifest already exists for this batchId with different business content");
    this.name = "BatchConflictError";
    this.batchId = batchId;
  }
}
