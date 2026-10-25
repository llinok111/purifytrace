/**
 * Report rendering: human text, JSON and SARIF 2.1.0.
 *
 * SARIF is used because GitHub code scanning and most CI viewers already
 * understand it; emitting it costs ~60 lines and makes the audit consumable
 * without a bespoke parser.
 */

const SEVERITY_TO_SARIF = { high: 'error', medium: 'warning', low: 'note' };

function pad(value, width) {
  const text = String(value);
  return text.length >= width ? text : text + ' '.repeat(width - text.length);
}

/** @param {object} trail */
export function renderJson(trail) {
  return JSON.stringify(trail, null, 2);
}

/** @param {object} trail */
export function renderText(trail) {
  const lines = [];
  const { stats, bookkeeping, prewalk, findingSummary } = trail;
  lines.push(`purifytrace ${trail.version} · DOMPurify ${trail.dompurify}`);
  lines.push('');
  lines.push('INPUT');
  lines.push(`  ${trail.input === null ? '(DOM node)' : JSON.stringify(trail.input)}`);
  lines.push('OUTPUT');
  lines.push(`  ${JSON.stringify(trail.output)}`);
  lines.push('');
  lines.push('COUNTS');
  lines.push(
    `  elements seen ${stats.elementsSeen} · kept ${stats.elementsKept} · removed ${stats.elementsRemoved} · ` +
      `attributes seen ${stats.attributesSeen}`
  );
  lines.push(`  bytes ${stats.bytesIn ?? '-'} → ${stats.bytesOut ?? '-'}`);

  if (trail.events.length > 0) {
    lines.push('');
    lines.push('EVENTS');
    for (const event of trail.events) {
      const where = event.action === 'remove' ? `<${event.target}>` : `${event.target} on <${event.on}>`;
      lines.push(`  ${pad(event.action, 18)} ${where}`);
      lines.push(`    path   ${event.path || '-'}`);
      if (event.subtreeRemoved > 0) {
        lines.push(`    pruned   ${event.subtreeRemoved} descendant(s) never reached by the walker`);
      }
      if (event.value !== undefined) lines.push(`    value  ${JSON.stringify(event.value).slice(0, 160)}`);
      if (event.after !== undefined) lines.push(`    after  ${JSON.stringify(event.after).slice(0, 160)}`);
      lines.push(`    reason ${event.reason.code} [${event.reason.confidence}] ${event.reason.policyKey || '-'}`);
      lines.push(`           ${event.reason.detail}`);
    }
  }

  const mismatch = bookkeeping.auditOnly.length + bookkeeping.upstreamOnly.filter((item) => !item.explained).length +
    bookkeeping.auditOnlyAttributes.length + bookkeeping.upstreamOnlyAttributes.length;
  lines.push('');
  lines.push('BOOKKEEPING (vs DOMPurify.removed)');
  lines.push(`  upstream records ${bookkeeping.upstreamRecords}`);
  if (mismatch === 0) {
    lines.push('  agree with upstream on every element and attribute');
  } else {
    for (const item of bookkeeping.auditOnly) lines.push(`  audit-only  <${item.tag}> ×${item.count} (upstream did not record it)`);
    for (const item of bookkeeping.upstreamOnly) {
      lines.push(
        item.explained
          ? `  upstream-only <${item.tag}> ×${item.count} — ${item.explained}`
          : `  upstream-only <${item.tag}> ×${item.count} (audit missed it)`
      );
    }
    for (const item of bookkeeping.auditOnlyAttributes) lines.push(`  audit-only  @${item.name} ×${item.count}`);
    for (const item of bookkeeping.upstreamOnlyAttributes) lines.push(`  upstream-only @${item.name} ×${item.count}`);
  }

  if (prewalk.headIgnored.length > 0 || prewalk.bodyUnseen.length > 0 || prewalk.textChanged) {
    lines.push('');
    lines.push('PRE-WALK (before DOMPurify saw anything)');
    for (const item of prewalk.headIgnored) {
      lines.push(`  parser moved <${item.tag}> into <head> and dropped it: ${JSON.stringify(item.text).slice(0, 100)}`);
    }
    for (const item of prewalk.bodyUnseen) {
      lines.push(`  <${item.tag}> parsed ${item.parsed}×, walker saw ${item.seen}×`);
    }
    if (prewalk.textChanged) {
      lines.push(`  visible text changed: ${prewalk.inputTextChars} → ${prewalk.outputTextChars} chars`);
    }
  }

  lines.push('');
  lines.push(`RISK SCAN  total ${findingSummary.total} · high ${findingSummary.high} · medium ${findingSummary.medium} · low ${findingSummary.low}`);
  for (const finding of trail.findings) {
    lines.push(`  ${pad(finding.severity.toUpperCase(), 7)} ${finding.code} @ ${finding.path}`);
    lines.push(`          ${finding.note}`);
    lines.push(`          ${finding.evidence}`);
  }
  if (trail.findings.length === 0) lines.push('  no residual sinks found in the output');
  return lines.join('\n');
}

/**
 * SARIF 2.1.0 with one result per finding.
 *
 * @param {object} trail
 * @param {{uri?: string}} [options]
 */
export function renderSarif(trail, options = {}) {
  const uri = options.uri || 'input.html';
  const rules = new Map();
  const results = trail.findings.map((finding) => {
    if (!rules.has(finding.code)) {
      rules.set(finding.code, {
        id: finding.code,
        name: finding.code,
        shortDescription: { text: finding.note },
        defaultConfiguration: { level: SEVERITY_TO_SARIF[finding.severity] || 'warning' },
      });
    }
    return {
      ruleId: finding.code,
      level: SEVERITY_TO_SARIF[finding.severity] || 'warning',
      message: { text: `${finding.note}: ${finding.evidence}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: 1, startColumn: 1 },
          },
          logicalLocations: [{ fullyQualifiedName: finding.path }],
        },
      ],
      properties: { tag: finding.tag, attribute: finding.attr || null, severity: finding.severity },
    };
  });

  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'purifytrace',
              version: trail.version,
              informationUri: 'https://github.com/llinok111/purifytrace',
              rules: [...rules.values()],
            },
          },
          results,
        },
      ],
    },
    null,
    2
  );
}

/**
 * Compare two trails of the same input produced under different configs.
 * Only *changes* are reported — that is the whole point: a policy edit should
 * be reviewed by its delta, not by re-reading the entire trail.
 *
 * @param {object} before
 * @param {object} after
 */
export function diffTrails(before, after) {
  const key = (event) =>
    event.kind === 'element'
      ? `element:${event.path}`
      : `attribute:${event.path}:${event.target}`;
  const beforeMap = new Map(before.events.map((event) => [key(event), event]));
  const afterMap = new Map(after.events.map((event) => [key(event), event]));

  const added = [];
  const removed = [];
  const changed = [];

  for (const [mapKey, event] of afterMap) {
    const previous = beforeMap.get(mapKey);
    if (!previous) {
      added.push(event);
    } else if (previous.reason.code !== event.reason.code) {
      changed.push({ key: mapKey, from: previous.reason.code, to: event.reason.code, event });
    }
  }
  for (const [mapKey, event] of beforeMap) {
    if (!afterMap.has(mapKey)) removed.push(event);
  }

  const beforeFindings = before.findingSummary;
  const afterFindings = after.findingSummary;

  return {
    outputChanged: before.output !== after.output,
    beforeOutput: before.output,
    afterOutput: after.output,
    added,
    removed,
    changed,
    findings: {
      before: beforeFindings,
      after: afterFindings,
      deltaHigh: afterFindings.high - beforeFindings.high,
    },
    policy: { before: before.policy, after: after.policy },
  };
}

/** Human-readable diff. */
export function renderDiffText(diff, beforeLabel = 'before', afterLabel = 'after') {
  const lines = [];
  lines.push(`purifytrace policy diff · ${beforeLabel} → ${afterLabel}`);
  lines.push('');
  lines.push(`output ${diff.outputChanged ? 'CHANGED' : 'unchanged'}`);
  if (diff.outputChanged) {
    lines.push(`  ${beforeLabel}: ${JSON.stringify(diff.beforeOutput).slice(0, 300)}`);
    lines.push(`  ${afterLabel}:  ${JSON.stringify(diff.afterOutput).slice(0, 300)}`);
  }
  lines.push(
    `allow-list size  tags ${diff.policy.before.allowedTags} → ${diff.policy.after.allowedTags} · ` +
      `attrs ${diff.policy.before.allowedAttributes} → ${diff.policy.after.allowedAttributes}`
  );
  lines.push(
    `risk  high ${diff.findings.before.high} → ${diff.findings.after.high} · ` +
      `medium ${diff.findings.before.medium} → ${diff.findings.after.medium}`
  );

  const section = (title, events, marker) => {
    if (events.length === 0) return;
    lines.push('');
    lines.push(title);
    for (const event of events) {
      const where = event.kind === 'element' ? `<${event.target}>` : `${event.target} on <${event.on}>`;
      lines.push(`  ${marker} ${where}  (${event.reason.code}, ${event.reason.confidence})`);
      lines.push(`      ${event.path || '-'}`);
    }
  };
  section('NEWLY DROPPED', diff.added, '+');
  section('NEWLY KEPT', diff.removed, '-');
  if (diff.changed.length > 0) {
    lines.push('');
    lines.push('REASON CHANGED');
    for (const change of diff.changed) {
      lines.push(`  ~ ${change.key}  ${change.from} → ${change.to}`);
    }
  }
  if (diff.added.length === 0 && diff.removed.length === 0 && diff.changed.length === 0) {
    lines.push('');
    lines.push('no decision changed for this input');
  }
  return lines.join('\n');
}
