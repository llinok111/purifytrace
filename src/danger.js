/**
 * Independent post-sanitization risk scan.
 *
 * This module deliberately does not import DOMPurify and does not re-use its
 * regexps: the point is to look at the *output string* with a second pair of
 * eyes. Severities are conservative — a finding means "this construct is still
 * in the payload and needs a human decision", not "this is exploitable in every
 * browser".
 */

const HIGH_TAGS = new Set(['script', 'iframe', 'object', 'embed', 'applet', 'base']);
const DANGEROUS_ATTRIBUTES = /^on/i;
const URL_ATTRIBUTES = new Set([
  'href',
  'src',
  'xlink:href',
  'action',
  'formaction',
  'poster',
  'data',
  'cite',
  'background',
  'longdesc',
  'srcset',
  'srcdoc',
]);

/** Tags whose JS-capable URLs execute without a user gesture. */
const AUTO_URL_TAGS = new Set(['iframe', 'object', 'embed', 'script', 'base']);

function clean(value) {
  return String(value || '').replace(/[\u0000-\u0020\u007f-\u009f]/g, '');
}

export function schemeOf(value) {
  const match = clean(value).match(/^([a-z][a-z0-9+.-]*):/i);
  return match ? `${match[1].toLowerCase()}:` : null;
}

function isDangerousUrl(value, tag) {
  const scheme = schemeOf(value);
  if (!scheme) return null;
  if (scheme === 'javascript:' || scheme === 'vbscript:') {
    return { severity: 'high', note: `executable ${scheme} URL` };
  }
  if (scheme === 'data:') {
    const head = clean(value).slice(0, 48).toLowerCase();
    if (head.startsWith('data:text/html')) {
      return { severity: AUTO_URL_TAGS.has(tag) ? 'high' : 'medium', note: 'data:text/html payload' };
    }
    if (head.startsWith('data:image/svg+xml')) {
      return { severity: 'medium', note: 'SVG data URL can carry script when navigated to' };
    }
  }
  return null;
}

/** Scan every URL in a `srcset`-style list. */
function* candidateUrls(name, value) {
  if (name === 'srcset') {
    for (const part of String(value).split(',')) {
      const url = part.trim().split(/\s+/)[0];
      if (url) yield url;
    }
    return;
  }
  yield value;
}

function cssRisk(value) {
  const text = String(value || '').toLowerCase();
  if (/url\s*\(\s*['"]?\s*(javascript|vbscript)\s*:/i.test(text)) {
    return { severity: 'low', note: 'javascript: inside CSS url() — legacy engines only, but the string survives' };
  }
  if (/expression\s*\(/.test(text)) return { severity: 'low', note: 'IE-era CSS expression() survived' };
  if (/-moz-binding\s*:/.test(text)) return { severity: 'low', note: 'XBL binding survived' };
  if (/behavior\s*:/.test(text)) return { severity: 'low', note: 'IE behavior: directive survived' };
  return null;
}

function textOf(node) {
  return (node.textContent || '').trim().slice(0, 120);
}

/**
 * @param {string} html sanitized output
 * @param {{DOMParser: Function}} window a DOM window/global
 * @param {Document} [preparsed] an already-parsed document for the same html
 */
export function scanOutput(html, window, preparsed) {
  const findings = [];
  if (!window || typeof window.DOMParser !== 'function') {
    throw new TypeError('scanOutput needs a window with DOMParser');
  }
  const doc = preparsed || new window.DOMParser().parseFromString(String(html || ''), 'text/html');

  const walk = (root, basePath) => {
    const elements = root.querySelectorAll ? root.querySelectorAll('*') : [];
    let index = 0;
    for (const element of elements) {
      index += 1;
      const tag = String(element.localName || element.nodeName).toLowerCase();
      const path = `${basePath}${tag}:${index}`;

      if (HIGH_TAGS.has(tag)) {
        findings.push({
          code: `tag:${tag}`,
          severity: 'high',
          tag,
          path,
          evidence: element.outerHTML.slice(0, 160),
          note: `${tag} survives sanitization and can navigate or execute`,
        });
      }

      if (tag === 'meta') {
        const equiv = (element.getAttribute('http-equiv') || '').toLowerCase();
        const content = element.getAttribute('content') || '';
        if (equiv === 'refresh' && /url\s*=/i.test(content)) {
          findings.push({
            code: 'meta-refresh',
            severity: 'medium',
            tag,
            path,
            evidence: content.slice(0, 120),
            note: 'meta refresh can redirect the page',
          });
        }
      }

      if (tag === 'form') {
        const action = element.getAttribute('action');
        if (action && isDangerousUrl(action, tag)) {
          findings.push({
            code: 'form-action-url',
            severity: 'high',
            tag,
            path,
            evidence: action.slice(0, 120),
            note: 'form action points at an executable URL',
          });
        }
      }

      for (const attribute of Array.from(element.attributes || [])) {
        const name = attribute.name.toLowerCase();
        const value = attribute.value;

        if (DANGEROUS_ATTRIBUTES.test(name)) {
          findings.push({
            code: 'event-handler-attribute',
            severity: 'high',
            tag,
            attr: name,
            path,
            evidence: `${name}="${value.slice(0, 80)}"`,
            note: 'inline event handler survived',
          });
          continue;
        }

        if (name === 'style') {
          const risk = cssRisk(value);
          if (risk) {
            findings.push({
              code: 'css-sink',
              severity: risk.severity,
              tag,
              attr: name,
              path,
              evidence: value.slice(0, 120),
              note: risk.note,
            });
          }
          continue;
        }

        if (URL_ATTRIBUTES.has(name)) {
          for (const url of candidateUrls(name, value)) {
            const risk = isDangerousUrl(url, tag);
            if (risk) {
              findings.push({
                code: 'url-scheme',
                severity: risk.severity,
                tag,
                attr: name,
                path,
                evidence: `${name}="${String(url).slice(0, 120)}"`,
                note: risk.note,
              });
              break;
            }
          }
        }
      }
    }
  };

  walk(doc.documentElement, '');
  // `<template>` content lives in a separate fragment and is not matched by
  // querySelectorAll on the document, so walk it explicitly.
  for (const template of Array.from(doc.querySelectorAll('template'))) {
    if (template.content) walk(template.content, 'template>');
  }
  return findings;
}

/** True when any finding is high severity. */
export function hasHigh(findings) {
  return findings.some((finding) => finding.severity === 'high');
}

/** Compact summary used by reports. */
export function summarize(findings) {
  const bySeverity = { high: 0, medium: 0, low: 0 };
  for (const finding of findings) bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
  return { total: findings.length, ...bySeverity };
}
