/**
 * purifytrace — sanitization audit trail for DOMPurify.
 *
 * Upstream keeps exactly one record per dropped item (`DOMPurify.removed`), with
 * no reason, no path and no accounting for nodes the HTML parser discarded
 * before the walk started. This module adds a per-call audit trail without
 * touching DOMPurify's own decision logic: it reads the public hook events and
 * the final DOM, then explains what happened.
 */

import { installRecorder, finalizeSession } from './record.js';
import { createReasoner } from './reasons.js';
import { normalizeConfig } from './policy.js';
import { scanOutput, summarize, hasHigh } from './danger.js';

const VERSION = '0.1.0';

/**
 * Create an audited sanitizer.
 *
 * @param {object} options
 * @param {Function} options.createDOMPurify the `createDOMPurify` factory
 * @param {object} options.window DOM window the sanitizer runs against
 * @returns {object} sanitizer with `sanitize()` and `audit()`
 */
export function createAuditedSanitizer({ createDOMPurify, window } = {}) {
  if (typeof createDOMPurify !== 'function') {
    throw new TypeError('createAuditedSanitizer needs the createDOMPurify factory');
  }
  if (!window || typeof window.DOMParser !== 'function') {
    throw new TypeError('createAuditedSanitizer needs a window with DOMParser');
  }

  // A dedicated instance: DOMPurify hooks are instance-global and cannot be
  // scoped to a single call, so sharing an instance with the caller's hooks
  // would make the recording non-deterministic.
  const purifier = createDOMPurify(window);
  if (!purifier.isSupported) {
    throw new Error('DOMPurify reports isSupported=false for this window; refusing to emit an audit trail that could not exist');
  }
  const recorder = installRecorder(purifier);

  /**
   * Sanitize and return both the output and its audit trail.
   *
   * @param {string|Node} input
   * @param {object} [config] DOMPurify config, unchanged in meaning
   */
  function audit(input, config = {}) {
    const normalized = normalizeConfig(config);
    const reasons = createReasoner(normalized);
    const session = recorder.begin(input);
    let output;
    let failure = null;

    try {
      output = purifier.sanitize(input, config);
    } catch (error) {
      failure = {
        name: error && error.name,
        message: error && error.message,
      };
      throw Object.assign(error instanceof Error ? error : new Error(String(error)), { purifytrace: { failure } });
    } finally {
      recorder.end(session);
    }

    const upstreamRemoved = Array.isArray(purifier.removed) ? purifier.removed.slice() : null;

    // One parse of the output serves both the risk scan and the text
    // comparison; parsing it twice was the single largest avoidable cost.
    let outputDoc = null;
    if (typeof output === 'string' && window && typeof window.DOMParser === 'function') {
      try {
        outputDoc = new window.DOMParser().parseFromString(output, 'text/html');
      } catch {
        outputDoc = null;
      }
    }

    const finished = finalizeSession(session, {
      output,
      upstreamRemoved,
      window,
      input,
      reasons,
      outputDoc,
    });

    const findings = typeof output === 'string' ? scanOutput(output, window, outputDoc) : [];
    const trail = {
      version: VERSION,
      dompurify: purifier.version,
      input: typeof input === 'string' ? input : null,
      output,
      events: finished.events,
      stats: finished.stats,
      bookkeeping: finished.bookkeeping,
      prewalk: finished.prewalk,
      policy: finished.policy,
      findings,
      findingSummary: summarize(findings),
      blocked: hasHigh(findings),
    };
    return { output, trail };
  }

  return {
    version: VERSION,
    dompurify: purifier.version,
    /** Sanitize only — drop-in behaviour of the wrapped instance. */
    sanitize(input, config) {
      return audit(input, config).output;
    },
    /** Sanitize + audit trail. */
    audit,
    /** Escape hatch for advanced users; never used by audit(). */
    get instance() {
      return purifier;
    },
  };
}

export { normalizeConfig } from './policy.js';
export { createReasoner } from './reasons.js';
export { scanOutput, summarize, hasHigh } from './danger.js';
export { installRecorder } from './record.js';
export { renderText, renderJson, renderSarif } from './report.js';
