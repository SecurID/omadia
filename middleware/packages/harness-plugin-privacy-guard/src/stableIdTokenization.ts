/**
 * Stable-id tokenization — Privacy-Shield v3.
 *
 * Tool-aware pre-pass that runs BEFORE the NER detectors (Presidio,
 * regex) inside `processToolResult`. Tools that declare `piiFields`
 * annotations (see `@omadia/plugin-api`'s `piiAnnotation.ts`) hand the
 * walker their structured result and a list of (path, idPath, type)
 * tuples; the walker:
 *
 *   1. Resolves each `path` to a list of "leaf positions" — writable
 *      slots (object key OR array index) so the leaf can be overwritten
 *      in place.
 *   2. Resolves the parallel `idPath` to a list of stable identifiers
 *      drawn from the same array spreads.
 *   3. For each (leaf, id) pair: when the leaf is a non-empty string
 *      and the id is non-null/undefined, mints a whole-value token
 *      via `map.tokenFor(leafValue, displayType)` and writes the
 *      token back into the JSON at the leaf position.
 *
 * Path grammar (slice 2 — extended for real Odoo shapes)
 * ------------------------------------------------------
 * A path is a sequence of steps:
 *
 *   - `key`   — descend into an object property (`name`, `partner`).
 *   - `[]`    — spread across every element of an array. May appear at
 *               the head of the path when the tool result is itself a
 *               top-level array (Odoo `search_read` returns `[{…}]`).
 *   - `[N]`   — descend into a fixed array index. The motivating case
 *               is Odoo's many2one wire format `field: [id, label]` —
 *               `field[1]` is the human label, `field[0]` the id.
 *
 * Examples:
 *
 *   - `"name"`                       — top-level object field
 *   - `"user.name"`                  — nested object
 *   - `"employees[].name"`           — array of objects, one per row
 *   - `"[].name"`                    — TOP-LEVEL array of objects
 *   - `"[].employee_id[1]"`          — top-level array, many2one label
 *   - `"[].employee_id[0]"`          — top-level array, many2one id
 *   - `"absences[].partner.name"`    — array of nested objects
 *
 * `path` and `idPath` must contain the SAME number of `[]` spreads in
 * the same nesting order so the two leaf lists zip 1:1. Fixed `[N]`
 * indices do not multiply, so they need not align in count.
 *
 * Dedup semantics (slice 1.5): the walker mints tokens via
 * `TokenizeMap.tokenForStableId`, keyed by the entity id resolved
 * from `idPath` — NOT by the string value. The same entity yields one
 * token across every row of the result; two homonyms that share a
 * value but differ in id (`"Müller" + id=12` vs `"Müller" + id=88`)
 * get DISTINCT tokens, so a ranking table never silently merges them.
 *
 * Failure modes
 * -------------
 *   - Shape mismatch (path / idPath disagree on `[]` spread count, or
 *     the two leaf lists differ in length): the annotation is skipped,
 *     the rest of the result is untouched, `skipped` increments. NER
 *     then runs on the unmodified value as a defense-in-depth net.
 *   - Non-string leaf / null id / missing segment: skipped silently.
 *
 * The walker never throws — every defensive branch returns a no-op so
 * tokenisation failures degrade to "NER does what it always did".
 * Stable-id is strictly additive on the privacy-guard pipeline.
 */

import type { PIIFieldType, ToolPIIField } from '@omadia/plugin-api';

import type { TokenizeMap } from './tokenizeMap.js';

export interface StableIdTokenizationOutcome {
  /** Deep-cloned tool result with annotated leaves rewritten to tokens. */
  readonly value: unknown;
  /** Number of leaf string fields actually replaced with stable tokens. */
  readonly replaced: number;
  /**
   * Number of annotations skipped because the (path, idPath) pair did
   * not align in shape against the raw result. Telemetry signal — when
   * non-zero, the operator should re-check the tool's PII annotations
   * against the live response shape.
   */
  readonly skipped: number;
}

/** One parsed step of a path expression. */
type PathSegment =
  | { readonly kind: 'key'; readonly key: string }
  | { readonly kind: 'spread' }
  | { readonly kind: 'index'; readonly index: number };

/** A writable leaf position — either an object property or an array slot. */
type LeafAddress =
  | { readonly kind: 'objKey'; readonly parent: Record<string, unknown>; readonly key: string }
  | { readonly kind: 'arrIndex'; readonly parent: unknown[]; readonly index: number };

/**
 * Entry point. Walks `raw` once per annotation; never mutates the
 * input. Annotations with malformed paths are skipped defensively.
 *
 * `raw` may be a top-level object (`{absences: [...]}`) OR a top-level
 * array (Odoo `search_read` → `[{…}]`). Primitives pass through
 * untouched.
 */
export function applyStableIdTokenization(
  raw: unknown,
  annotations: readonly ToolPIIField[],
  map: TokenizeMap,
): StableIdTokenizationOutcome {
  if (annotations.length === 0) {
    return { value: raw, replaced: 0, skipped: 0 };
  }
  if (raw === null || typeof raw !== 'object') {
    // Primitive top-level payload — nothing structured to walk.
    return { value: raw, replaced: 0, skipped: 0 };
  }

  // Deep-clone via JSON round-trip. The walker mutates the clone, not
  // the caller's reference. JSON-clone is sufficient because every
  // tool result this walker sees is already JSON-serialisable (it's
  // about to be `JSON.stringify`ed for the LLM). Works for both
  // top-level objects and top-level arrays.
  const work = JSON.parse(JSON.stringify(raw)) as unknown;

  let replaced = 0;
  let skipped = 0;

  for (const ann of annotations) {
    const type: PIIFieldType = ann.type ?? 'PERSON';
    const pathSegs = parsePath(ann.path);
    const idSegs = parsePath(ann.idPath);
    if (pathSegs.length === 0 || idSegs.length === 0) {
      skipped += 1;
      continue;
    }
    if (countSpreads(pathSegs) !== countSpreads(idSegs)) {
      skipped += 1;
      continue;
    }
    const addresses = collectAddresses(work, pathSegs);
    const ids = collectValues(work, idSegs);
    if (addresses.length !== ids.length) {
      skipped += 1;
      continue;
    }
    for (let i = 0; i < addresses.length; i += 1) {
      const addr = addresses[i];
      const id = ids[i];
      if (!addr) continue;
      if (id === null || id === undefined) continue;
      const leaf = readLeaf(addr);
      if (typeof leaf !== 'string' || leaf.length === 0) continue;
      // Stable-id dedup (slice 1.5): the token is keyed by the entity
      // identity at `idPath`, not by the string value. The same
      // employee yields one token across every row; two homonyms
      // ("Thomas Müller" id 12 vs id 88) get distinct tokens so a
      // ranking table never silently merges their rows.
      const token = map.tokenForStableId(
        leaf,
        typeToDetectorHint(type),
        String(id),
      );
      writeLeaf(addr, token);
      replaced += 1;
    }
  }

  return { value: work, replaced, skipped };
}

// ---------------------------------------------------------------------------
// Path parsing.
// ---------------------------------------------------------------------------

/**
 * Parse a path expression into segments. Returns an empty array for any
 * malformed input — the caller treats that as "skip this annotation".
 *
 * Grammar (informal):
 *
 *   path    := step (sep step)*
 *   step    := key | spread | index
 *   sep     := '.'        (required before a `key`, never before `[...]`)
 *   spread  := '[]'
 *   index   := '[' digits ']'
 *   key     := [^.[\]]+
 *
 * A `key` needs a preceding `.` unless it is the very first step.
 * `[]` / `[N]` attach directly (no dot). Leading `.`, trailing `.`,
 * `..`, unclosed `[`, stray `]`, and `[non-digit]` are all rejected.
 */
function parsePath(path: string): readonly PathSegment[] {
  if (path.length === 0) return [];
  const segs: PathSegment[] = [];
  let i = 0;
  let started = false;
  let lastWasDot = false;

  while (i < path.length) {
    const ch = path[i];

    if (ch === '.') {
      if (!started || lastWasDot) return []; // leading or doubled dot
      lastWasDot = true;
      i += 1;
      continue;
    }

    if (ch === '[') {
      const close = path.indexOf(']', i);
      if (close < 0) return []; // unclosed bracket
      const inner = path.slice(i + 1, close);
      if (inner.length === 0) {
        segs.push({ kind: 'spread' });
      } else if (/^\d+$/.test(inner)) {
        segs.push({ kind: 'index', index: Number.parseInt(inner, 10) });
      } else {
        return []; // `[foo]` — only `[]` and `[digits]` are valid
      }
      started = true;
      lastWasDot = false;
      i = close + 1;
      continue;
    }

    if (ch === ']') return []; // stray close bracket

    // Identifier run — a `key` segment. Valid only at the head of the
    // path or directly after a `.` separator.
    if (started && !lastWasDot) return [];
    let j = i;
    while (j < path.length) {
      const c = path[j];
      if (c === '.' || c === '[' || c === ']') break;
      j += 1;
    }
    const key = path.slice(i, j);
    if (key.length === 0) return [];
    segs.push({ kind: 'key', key });
    started = true;
    lastWasDot = false;
    i = j;
  }

  if (lastWasDot) return []; // trailing dot
  return segs;
}

function countSpreads(segs: readonly PathSegment[]): number {
  let n = 0;
  for (const s of segs) if (s.kind === 'spread') n += 1;
  return n;
}

// ---------------------------------------------------------------------------
// Walkers.
// ---------------------------------------------------------------------------

/**
 * Walk `obj` along `segs`, returning the writable leaf positions every
 * path resolves to. Missing intermediate segments yield an empty slice
 * for that branch — never throws.
 */
function collectAddresses(
  obj: unknown,
  segs: readonly PathSegment[],
): readonly LeafAddress[] {
  if (segs.length === 0) return [];
  const head = segs[0];
  if (!head) return [];
  const rest = segs.slice(1);
  const isLast = rest.length === 0;

  if (head.kind === 'spread') {
    if (!Array.isArray(obj)) return [];
    if (isLast) {
      // `…[]` as the final step — every element of the array is itself
      // a leaf (array-of-strings, e.g. `emails[]`).
      return obj.map(
        (_, index): LeafAddress => ({ kind: 'arrIndex', parent: obj, index }),
      );
    }
    const out: LeafAddress[] = [];
    for (const item of obj) {
      out.push(...collectAddresses(item, rest));
    }
    return out;
  }

  if (head.kind === 'index') {
    if (!Array.isArray(obj)) return [];
    if (head.index >= obj.length) return [];
    if (isLast) {
      return [{ kind: 'arrIndex', parent: obj, index: head.index }];
    }
    return collectAddresses(obj[head.index], rest);
  }

  // head.kind === 'key'
  if (!isPlainObject(obj)) return [];
  if (isLast) {
    return [{ kind: 'objKey', parent: obj, key: head.key }];
  }
  return collectAddresses(obj[head.key], rest);
}

/**
 * Walk `obj` along `segs`, returning the leaf VALUES every path
 * resolves to. Read-side mirror of `collectAddresses` — used to pluck
 * stable ids out of `idPath`.
 */
function collectValues(obj: unknown, segs: readonly PathSegment[]): readonly unknown[] {
  if (segs.length === 0) return [];
  const head = segs[0];
  if (!head) return [];
  const rest = segs.slice(1);
  const isLast = rest.length === 0;

  if (head.kind === 'spread') {
    if (!Array.isArray(obj)) return [];
    if (isLast) return obj;
    const out: unknown[] = [];
    for (const item of obj) {
      out.push(...collectValues(item, rest));
    }
    return out;
  }

  if (head.kind === 'index') {
    if (!Array.isArray(obj)) return [];
    if (head.index >= obj.length) return [];
    if (isLast) return [obj[head.index]];
    return collectValues(obj[head.index], rest);
  }

  // head.kind === 'key'
  if (!isPlainObject(obj)) return [];
  if (isLast) return [obj[head.key]];
  return collectValues(obj[head.key], rest);
}

function readLeaf(addr: LeafAddress): unknown {
  return addr.kind === 'objKey'
    ? addr.parent[addr.key]
    : addr.parent[addr.index];
}

function writeLeaf(addr: LeafAddress, value: string): void {
  if (addr.kind === 'objKey') {
    addr.parent[addr.key] = value;
  } else {
    addr.parent[addr.index] = value;
  }
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/**
 * Map the public `PIIFieldType` literal to the detector-hint string
 * the existing `TokenizeMap.tokenFor` knows about (`pii.name`,
 * `pii.email`, …). Keeps the token's display type aligned with the
 * NER detector taxonomy so a stable-id-minted token and an
 * NER-minted token of the same type are visually indistinguishable
 * to the LLM.
 */
function typeToDetectorHint(type: PIIFieldType): string {
  switch (type) {
    case 'PERSON':
      return 'pii.name';
    case 'EMAIL':
      return 'pii.email';
    case 'PHONE':
      return 'pii.phone';
    case 'IBAN':
      return 'pii.iban';
    case 'CARD':
      return 'pii.credit_card';
    case 'ADDRESS':
      return 'pii.address';
    case 'ORG':
      return 'pii.organization';
    case 'APIKEY':
      return 'pii.api_key';
    default:
      // Exhaustiveness guard — TS will catch a new variant at compile
      // time, but at runtime fall back to a generic name hint.
      return 'pii.name';
  }
}
