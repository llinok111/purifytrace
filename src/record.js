/**
 * Recorder: derives an event log from DOMPurify's public hook API.
 *
 * Findings this module is built around, each verified against DOMPurify 3.4.17
 * (see docs/EVIDENCE.md for the commands that produced them):
 *
 *  1. `uponSanitizeElement` fires for every element the walker reaches,
 *     including ones it is about to delete, so removals can be observed by
 *     comparing the recorded node against the final tree.
 *  2. `uponSanitizeAttribute` fires *before* the attribute decision and its
 *     `keepAttr` flag is recomputed afterwards — `onclick` arrives with
 *     keepAttr=true and is still dropped — so the final DOM, not the hook
 *     event, is the source of truth for attributes.
 *  3. Removals mutate the tree while the walk is in progress: KEEP_CONTENT
 *     re-parents survivors, KEEP_CONTENT:false prunes descendants before the
 *     walker reaches them. Both destroy the evidence needed to explain *where*
 *     an item was, so the input tree is snapshotted at the first hook event,
 *     while it is still intact.
 */

const HTML_NS = 'http://www.w3.org/1999/xhtml';
const SVG_NS = 'http://www.w3.org/2000/svg';
const MATHML_NS = 'http://www.w3.org/1998/Math/MathML';

function namespaceLabel(node) {
  const ns = node.namespaceURI;
  if (ns === SVG_NS) return 'svg';
  if (ns === MATHML_NS) return 'mathml';
  if (ns === HTML_NS || ns == null) return 'html';
  return String(ns);
}

function localNameOf(node) {
  return String(node.localName || node.nodeName).toLowerCase();
}

/**
 * Element children, including `<template>.content` (invisible to querySelectorAll).
 *
 * `childNodes` is used instead of `children`: in jsdom, `children` is a live
 * HTMLCollection implemented as a Proxy, and iterating it costs a
 * getOwnPropertyDescriptor call per index — it showed up as 17 % of the whole
 * audit run in a CPU profile.
 */
function elementChildren(node) {
  if (node.content && node.content.nodeType === 11) {
    return elementChildrenOf(node.content);
  }
  return elementChildrenOf(node);
}

function elementChildrenOf(node) {
  const out = [];
  const children = node.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children[i];
    if (child.nodeType === 1) out.push(child);
  }
  return out;
}

/**
 * Freeze the input tree before DOMPurify starts mutating it.
 * Records per element: parent reference, sibling-stable path, descendant count.
 *
 * The descendant count is computed in a single post-order pass. Doing it per
 * element (one subtree walk each) turns the snapshot into O(n²) — measured at
 * 121 ms for a 2000-element document before this was fixed.
 */
function snapshotTree(root) {
  const tree = new Map();
  const walk = (node, prefix) => {
    const counts = new Map();
    const children = elementChildren(node);
    const entries = [];
    for (const child of children) {
      const childTag = localNameOf(child);
      const index = (counts.get(childTag) || 0) + 1;
      counts.set(childTag, index);
      const path = `${prefix}${index > 1 ? `${childTag}[${index}]` : childTag}`;
      entries.push([child, path]);
    }
    let descendants = 0;
    for (const [child, path] of entries) {
      tree.set(child, { parent: node, path, descendantCount: 0 });
      walk(child, `${path} > `);
      const record = tree.get(child);
      descendants += 1 + record.descendantCount;
    }
    const record = tree.get(node);
    if (record) record.descendantCount = descendants;
  };
  if (root && root.nodeType === 1) {
    const path = localNameOf(root);
    tree.set(root, { parent: null, path, descendantCount: 0 });
    walk(root, `${path} > `);
  }
  return tree;
}

function attributeSnapshot(node) {
  if (!node || typeof node.getAttributeNames !== 'function') return [];
  return node.getAttributeNames().map((name) => ({
    name: name.toLowerCase(),
    value: node.getAttribute(name) ?? '',
  }));
}

/**
 * Walk up from a node and report how its branch terminates.
 *
 * `isConnected` alone is not enough: with a narrow ALLOWED_TAGS DOMPurify
 * detaches the walk container but still serializes its innerHTML, and nodes
 * inside `<template>.content` live in a detached DocumentFragment by design.
 */
function branchRoot(node) {
  let current = node;
  let last = null;
  while (current) {
    if (current.nodeType === 9) return { kind: 'document', node: current };
    last = current;
    current = current.parentNode;
  }
  if (!last) return { kind: 'orphan', node: null };
  if (last.nodeType === 11) return { kind: 'fragment', node: last };
  return { kind: 'element', node: last };
}

/**
 * Install the recording hooks once per DOMPurify instance.
 * The instance must be dedicated to tracing: DOMPurify has no per-call hooks.
 *
 * @param {object} DOMPurify
 */
export function installRecorder(DOMPurify) {
  if (!DOMPurify || typeof DOMPurify.addHook !== 'function') {
    throw new TypeError('installRecorder expects a DOMPurify instance');
  }
  const stack = [];
  const current = () => stack[stack.length - 1] || null;

  DOMPurify.addHook('uponSanitizeElement', (node, data) => {
    const session = current();
    if (!session || !node) return;
    if (data && data.allowedTags) session.allowedTags = data.allowedTags;
    if (node.nodeType !== 1) {
      session.textNodes += 1;
      return;
    }
    if (!session.tree) session.tree = snapshotTree(node);
    const snapshot = session.tree.get(node);
    const id = (session.counter += 1);
    session.nodeIds.set(node, id);
    session.elements.push({
      id,
      node,
      tag: String((data && data.tagName) || localNameOf(node)).toLowerCase(),
      ns: namespaceLabel(node),
      path: snapshot ? snapshot.path : localNameOf(node),
      parentId: snapshot && snapshot.parent ? session.nodeIds.get(snapshot.parent) ?? null : null,
      descendantCount: snapshot ? snapshot.descendantCount : 0,
      attrs: attributeSnapshot(node),
    });
  });

  DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
    const session = current();
    if (!session || !node || !data) return;
    if (data.allowedAttributes) session.allowedAttrs = data.allowedAttributes;
    session.attrs.push({
      node,
      nodeId: session.nodeIds.get(node) ?? null,
      name: String(data.attrName || '').toLowerCase(),
      value: String(data.attrValue ?? ''),
    });
  });

  return {
    begin(input) {
      const session = {
        elements: [],
        attrs: [],
        nodeIds: new Map(),
        tree: null,
        counter: 0,
        textNodes: 0,
        allowedTags: null,
        allowedAttrs: null,
        inputWasString: typeof input === 'string',
      };
      stack.push(session);
      return session;
    },
    end(session) {
      const index = stack.lastIndexOf(session);
      if (index >= 0) stack.splice(index, 1);
    },
    get depth() {
      return stack.length;
    },
  };
}

function countBy(items, pick) {
  const map = new Map();
  for (const item of items) {
    const key = pick(item);
    map.set(key, (map.get(key) || 0) + 1);
  }
  return map;
}

/**
 * Visible text of a subtree.
 *
 * The tree is walked directly instead of cloning it: a `cloneNode(true)` of a
 * 2000-element body measured 24.8 ms in jsdom, and the text of script/style/
 * template content is never rendered, so it is skipped while walking.
 */
function visibleText(root) {
  if (!root) return '';
  let text = '';
  const visit = (node) => {
    for (const child of node.childNodes || []) {
      if (child.nodeType === 3) {
        text += child.data;
      } else if (child.nodeType === 1) {
        const tag = localNameOf(child);
        if (tag === 'script' || tag === 'style' || tag === 'template' || tag === 'noscript') continue;
        visit(child);
      }
    }
  };
  visit(root);
  return text;
}

/** Parse a fragment exactly like DOMPurify does, to see what the parser did first. */
export function analyseParsedInput(window, input) {
  if (!window || typeof window.DOMParser !== 'function' || typeof input !== 'string') {
    return { headElements: [], bodyTags: new Map(), text: '' };
  }
  let doc;
  try {
    doc = new window.DOMParser().parseFromString(input, 'text/html');
  } catch {
    return { headElements: [], bodyTags: new Map(), text: '' };
  }
  const headElements = doc.head
    ? Array.from(doc.head.children).map((element) => ({
        tag: localNameOf(element),
        text: (element.textContent || '').slice(0, 80),
      }))
    : [];
  const body = doc.body;
  const bodyTags = body ? countBy(Array.from(body.querySelectorAll('*')), (element) => localNameOf(element)) : new Map();
  return { headElements, bodyTags, text: visibleText(body) };
}

function textOf(window, html, preparsed) {
  if (!window || typeof window.DOMParser !== 'function' || typeof html !== 'string') return '';
  try {
    const doc = preparsed || new window.DOMParser().parseFromString(html, 'text/html');
    return visibleText(doc.body);
  } catch {
    return '';
  }
}

function sameText(a, b) {
  const norm = (value) => String(value || '').replace(/\s+/g, ' ').trim();
  return norm(a) === norm(b);
}

/**
 * Turn a finished recording session into audit events.
 *
 * @param {object} session
 * @param {{output: string, upstreamRemoved: object[]|null, window?: object, input?: unknown, reasons: object}} ctx
 */
export function finalizeSession(session, ctx) {
  const { output, upstreamRemoved, window, input, reasons } = ctx;
  const outputDoc = ctx.outputDoc || null;
  const events = [];
  const keptIds = new Set();
  const removedIds = new Set();
  const byId = new Map(session.elements.map((element) => [element.id, element]));
  const container = session.elements[0] ? session.elements[0].node : null;
  const keptFragments = new Set();

  for (const element of session.elements) {
    const root = branchRoot(element.node);
    let kept = false;
    if (root.kind === 'document') kept = true;
    // The walk container is special: DOMPurify may detach it (narrow
    // ALLOWED_TAGS) yet still return its innerHTML, so its content survives.
    else if (root.node === container) kept = true;
    else if (root.kind === 'fragment') {
      if (!keptFragments.has(root.node)) {
        const host = session.elements.find((candidate) => candidate.node.content === root.node);
        if (host && keptIds.has(host.id)) keptFragments.add(root.node);
      }
      kept = keptFragments.has(root.node);
    }
    if (kept) keptIds.add(element.id);
    else removedIds.add(element.id);
  }

  const isAncestorOf = (ancestorId, candidateId) => {
    let current = byId.get(candidateId);
    while (current && current.parentId != null) {
      if (current.parentId === ancestorId) return true;
      current = byId.get(current.parentId);
    }
    return false;
  };

  const removedElements = session.elements.filter((element) => removedIds.has(element.id));
  for (const element of removedElements) {
    // Every walked element gets its own event: KEEP_CONTENT can re-parent a
    // child out of a removed ancestor and delete it later, so "inside a removed
    // ancestor" does not imply "covered by that ancestor's event".
    const walkedDescendants = session.elements.filter((candidate) => isAncestorOf(element.id, candidate.id));
    // Descendants pruned before the walker reached them never fire a hook and
    // therefore have no event of their own; count them from the snapshot.
    const unwalked = Math.max(0, element.descendantCount - walkedDescendants.length);
    events.push({
      action: 'remove',
      kind: 'element',
      target: element.tag,
      namespace: element.ns,
      path: element.path,
      subtreeRemoved: unwalked,
      reason: reasons.element(element, session),
    });
  }

  const seenAttr = new Set();
  for (const attr of session.attrs) {
    const element = attr.node;
    if (!element || !keptIds.has(attr.nodeId)) continue;
    const key = `${attr.nodeId}:${attr.name}`;
    if (seenAttr.has(key)) continue;
    seenAttr.add(key);
    const record = byId.get(attr.nodeId);
    const present =
      typeof element.getAttributeNames === 'function'
        ? element.getAttributeNames().map((name) => name.toLowerCase())
        : [];
    if (!present.includes(attr.name)) {
      events.push({
        action: 'strip-attribute',
        kind: 'attribute',
        target: attr.name,
        on: record ? record.tag : localNameOf(element),
        path: record ? record.path : localNameOf(element),
        value: attr.value,
        reason: reasons.attribute(attr, record, session),
      });
      continue;
    }
    const after = element.getAttribute(attr.name) ?? '';
    if (after !== attr.value) {
      events.push({
        action: 'rewrite-attribute',
        kind: 'attribute',
        target: attr.name,
        on: record ? record.tag : localNameOf(element),
        path: record ? record.path : localNameOf(element),
        value: attr.value,
        after,
        reason: {
          code: 'value-rewritten',
          confidence: 'confirmed',
          detail: 'value changed between the hook event and the final DOM',
        },
      });
    }
  }

  const upstream = Array.isArray(upstreamRemoved) ? upstreamRemoved : [];
  const upstreamElementTags = countBy(
    upstream.filter((entry) => entry && entry.element),
    (entry) => String(entry.element.nodeName || '').toLowerCase()
  );
  const upstreamAttrNames = countBy(
    upstream.filter((entry) => entry && entry.attribute),
    (entry) => String(entry.attribute.name || entry.attribute).toLowerCase()
  );
  const eventElementTags = countBy(events.filter((event) => event.action === 'remove'), (event) => event.target);
  const eventAttrNames = countBy(events.filter((event) => event.action === 'strip-attribute'), (event) => event.target);

  const containerTag = container ? localNameOf(container) : null;
  const upstreamOnly = diffCounts(upstreamElementTags, eventElementTags, 'tag').map((entry) =>
    entry.tag === containerTag
      ? { ...entry, explained: 'DOMPurify detached the walk container but returned its innerHTML; content survives' }
      : entry
  );

  const prewalk = ctx.skipPrewalk
    ? { headElements: [], bodyTags: new Map(), text: '' }
    : analyseParsedInput(window, input);
  const bodyUnseen = [];
  for (const [tag, count] of prewalk.bodyTags) {
    const seen = countBy(session.elements, (element) => element.tag).get(tag) || 0;
    if (count > seen) bodyUnseen.push({ tag, parsed: count, seen });
  }

  const outputText = textOf(window, output, outputDoc);

  return {
    events,
    stats: {
      // The first recorded element is DOMPurify's walk container (usually
      // <body>). It is an artifact of parsing, not part of the payload, so it
      // is excluded from the element counts and reported separately.
      elementsSeen: Math.max(0, session.elements.length - (container ? 1 : 0)),
      containerTag: container ? localNameOf(container) : null,
      elementsKept: Math.max(0, keptIds.size - (container ? 1 : 0)),
      elementsRemoved: removedIds.size,
      attributesSeen: session.attrs.length,
      textNodesSeen: session.textNodes,
      bytesIn: typeof input === 'string' ? input.length : null,
      bytesOut: typeof output === 'string' ? output.length : null,
    },
    bookkeeping: {
      upstreamRecords: upstream.length,
      upstreamElements: [...upstreamElementTags.entries()].map(([tag, count]) => ({ tag, count })),
      upstreamAttributes: [...upstreamAttrNames.entries()].map(([name, count]) => ({ name, count })),
      auditOnly: diffCounts(eventElementTags, upstreamElementTags, 'tag'),
      upstreamOnly,
      auditOnlyAttributes: diffCounts(eventAttrNames, upstreamAttrNames, 'name'),
      upstreamOnlyAttributes: diffCounts(upstreamAttrNames, eventAttrNames, 'name'),
    },
    prewalk: {
      headIgnored: prewalk.headElements,
      bodyUnseen,
      textChanged: typeof input === 'string' && !sameText(prewalk.text, outputText),
      inputTextChars: prewalk.text.length,
      outputTextChars: outputText.length,
    },
    policy: {
      allowedTags: session.allowedTags ? Object.keys(session.allowedTags).length : null,
      allowedAttributes: session.allowedAttrs ? Object.keys(session.allowedAttrs).length : null,
    },
  };
}

function diffCounts(left, right, field) {
  const out = [];
  for (const [key, count] of left) {
    const other = right.get(key) || 0;
    if (count > other) out.push({ [field]: key, count: count - other });
  }
  return out;
}
