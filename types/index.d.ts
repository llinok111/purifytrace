/**
 * Type definitions for purifytrace.
 *
 * The DOMPurify config type is intentionally loose: purifytrace forwards the
 * config unchanged, and DOMPurify's own `Config` type is not re-exported here
 * to avoid a hard dependency on its type layout.
 */

export type Confidence = 'confirmed' | 'inferred';

export type AuditAction = 'remove' | 'strip-attribute' | 'rewrite-attribute';

export interface Reason {
  /** Stable machine-readable reason code. */
  code: string;
  /** The DOMPurify config key responsible, when one can be named. */
  policyKey: string | null;
  /**
   * `confirmed` — the effective allow-list excludes the item, so a config key
   * is directly responsible.
   * `inferred`  — the item was allow-listed and dropped anyway; the named rule
   * is the most plausible explanation, not a proof.
   */
  confidence: Confidence;
  /** Human-readable explanation. */
  detail: string;
}

export interface ElementEvent {
  action: 'remove';
  kind: 'element';
  /** Lower-cased tag name. */
  target: string;
  namespace: 'html' | 'svg' | 'mathml' | string;
  /** Path in the *input* tree, e.g. `body > div > svg > script`. */
  path: string;
  /** Descendants that were pruned before the walker reached them. */
  subtreeRemoved: number;
  reason: Reason;
}

export interface AttributeEvent {
  action: 'strip-attribute' | 'rewrite-attribute';
  kind: 'attribute';
  /** Lower-cased attribute name. */
  target: string;
  /** Tag the attribute was on. */
  on: string;
  path: string;
  /** Value the attribute had before sanitization. */
  value: string;
  /** Present only for `rewrite-attribute`. */
  after?: string;
  reason: Reason;
}

export type AuditEvent = ElementEvent | AttributeEvent;

export interface Finding {
  code: string;
  severity: 'high' | 'medium' | 'low';
  tag?: string;
  attr?: string;
  path?: string;
  evidence: string;
  note: string;
}

export interface FindingSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
}

export interface Bookkeeping {
  /** Number of records in `DOMPurify.removed` for this call. */
  upstreamRecords: number;
  upstreamElements: Array<{ tag: string; count: number }>;
  upstreamAttributes: Array<{ name: string; count: number }>;
  /** Decisions the audit reports and upstream did not. */
  auditOnly: Array<{ tag: string; count: number }>;
  /** Records upstream made that the audit did not. */
  upstreamOnly: Array<{ tag: string; count: number; explained?: string }>;
  auditOnlyAttributes: Array<{ name: string; count: number }>;
  upstreamOnlyAttributes: Array<{ name: string; count: number }>;
}

export interface Prewalk {
  /** Elements the HTML parser moved into <head> and dropped. */
  headIgnored: Array<{ tag: string; text: string }>;
  /** Tags the parser produced more of than the walker saw. */
  bodyUnseen: Array<{ tag: string; parsed: number; seen: number }>;
  /** Visible text differs between input and output. */
  textChanged: boolean;
  inputTextChars: number;
  outputTextChars: number;
}

export interface Trail {
  version: string;
  dompurify: string;
  input: string | null;
  output: unknown;
  events: AuditEvent[];
  stats: {
    elementsSeen: number;
    elementsKept: number;
    elementsRemoved: number;
    attributesSeen: number;
    textNodesSeen: number;
    bytesIn: number | null;
    bytesOut: number | null;
  };
  bookkeeping: Bookkeeping;
  prewalk: Prewalk;
  policy: { allowedTags: number | null; allowedAttributes: number | null };
  findings: Finding[];
  findingSummary: FindingSummary;
  /** True when at least one high-severity finding survived. */
  blocked: boolean;
}

export interface AuditedSanitizer {
  readonly version: string;
  readonly dompurify: string;
  /** Same behaviour as `DOMPurify.sanitize`. */
  sanitize(input: unknown, config?: Record<string, unknown>): unknown;
  /** Sanitize and return the audit trail. */
  audit(input: unknown, config?: Record<string, unknown>): { output: unknown; trail: Trail };
  /** The wrapped DOMPurify instance. */
  readonly instance: Record<string, unknown>;
}

export function createAuditedSanitizer(options: {
  createDOMPurify: (window: unknown) => Record<string, unknown>;
  window: unknown;
}): AuditedSanitizer;

export function normalizeConfig(config?: Record<string, unknown>): Record<string, unknown>;

export function createReasoner(config?: Record<string, unknown>): {
  element(element: { tag: string; ns: string }, session: Record<string, unknown>): Reason;
  attribute(
    attr: { name: string; value: string },
    element: { tag: string } | undefined,
    session: Record<string, unknown>
  ): Reason;
};

export function scanOutput(html: string, window: unknown, preparsed?: unknown): Finding[];
export function summarize(findings: Finding[]): FindingSummary;
export function hasHigh(findings: Finding[]): boolean;

export function installRecorder(DOMPurify: Record<string, unknown>): Record<string, unknown>;

export function renderText(trail: Trail): string;
export function renderJson(trail: Trail): string;
export function renderSarif(trail: Trail, options?: { uri?: string }): string;

export interface TrailDiff {
  outputChanged: boolean;
  beforeOutput: unknown;
  afterOutput: unknown;
  added: AuditEvent[];
  removed: AuditEvent[];
  changed: Array<{ key: string; from: string; to: string; event: AuditEvent }>;
  findings: { before: FindingSummary; after: FindingSummary; deltaHigh: number };
  policy: { before: Trail['policy']; after: Trail['policy'] };
}

export function diffTrails(before: Trail, after: Trail): TrailDiff;
export function renderDiffText(diff: TrailDiff, beforeLabel?: string, afterLabel?: string): string;
