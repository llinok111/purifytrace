# purifytrace

[![CI](https://github.com/llinok111/purifytrace/actions/workflows/ci.yml/badge.svg)](https://github.com/llinok111/purifytrace/actions/workflows/ci.yml)
[![demo](https://img.shields.io/badge/demo-live-7aa2f7)](https://llinok111.github.io/purifytrace/demo/)

**An explainable audit trail for DOMPurify.** It answers the three questions
`DOMPurify.removed` cannot:

1. **What** was dropped — element or attribute, with the path where it was.
2. **Why** — which config key or content rule is responsible, and how confident
   that attribution is.
3. **What you never saw** — payloads the HTML parser discarded *before* the
   sanitizer ran, and sinks that survive the policy.

```bash
npm install purifytrace dompurify
```

```js
import createDOMPurify from 'dompurify';
import { createAuditedSanitizer } from 'purifytrace';

const sanitizer = createAuditedSanitizer({ createDOMPurify, window });

const { output, trail } = sanitizer.audit('<img src=x onerror=alert(1)>');

output; // '<img src="x">'
trail.events[0];
// {
//   action: 'strip-attribute',
//   target: 'onerror',
//   on: 'img',
//   path: 'body > img',
//   value: 'alert(1)',
//   reason: {
//     code: 'event-handler-attribute',
//     policyKey: 'ALLOWED_ATTR (event handlers are never default-allowed)',
//     confidence: 'confirmed',
//     detail: 'onerror is not in the effective attribute allow-list',
//   },
// }
```

---

## Why this exists

DOMPurify is the de-facto HTML sanitizer for the web, and it is very good at
its job. Its audit surface, however, is one property:

```js
DOMPurify.sanitize(dirty);
DOMPurify.removed; // [{ element }, { attribute, from }]
```

No reason, no path, no policy key, and — critically — **no record of anything
the HTML parser threw away before the sanitizer started**. The upstream README
says it plainly: *"Please do not use this property for making any security
critical decisions. This is just a little helper for curious minds."*

purifytrace keeps that property untouched and adds an audit layer on top:

| Question | DOMPurify.removed | purifytrace |
|---|---|---|
| What was dropped? | node object | tag/attribute + path + value |
| Why? | — | policy key + reason code + confidence |
| What did the parser lose first? | — | `prewalk.headIgnored` |
| Is anything dangerous left? | — | independent risk scan (text / JSON / SARIF) |
| What changed between two policies? | — | `--diff` |

### The case upstream itself documents

DOMPurify issue [#988](https://github.com/cure53/DOMPurify/issues/988) asks why
a leading `<script>` never shows up in `.removed`. The maintainer's answer:

> In this case, it never gets removed by DOMPurify, but by the browser before
> sanitization happens. Hence, it never lands in `.removed`.

The issue is closed as "not a bug" — correctly, since the payload *was*
neutralized. But the *observability* gap is real and permanent: a reviewer
looking at `.removed` sees an empty array and cannot tell the difference
between "nothing was dangerous" and "something dangerous was eaten by the
parser". purifytrace reports that case explicitly:

```
PRE-WALK (before DOMPurify saw anything)
  parser moved <script> into <head> and dropped it: "alert('XSS');"
```

Reproduce it:

```bash
printf "<script>alert('XSS');</script> trailing text" > /tmp/p.html
npx purifytrace /tmp/p.html
#   output: "trailing text"
#   upstream records: 0
#   parser moved <script> into <head> and dropped it
```

---

## Install

```bash
npm install purifytrace dompurify
```

Requires Node.js ≥ 18. `dompurify` is a peer dependency (≥ 3.0.0), so the
audit always reports the exact sanitizer version it ran against. A DOM is
required: use `jsdom` on the server, or the browser's own `window`.

```bash
npm install jsdom   # server-side only
```

### A note on loading order (upstream constraint, not a purifytrace bug)

DOMPurify's CommonJS build calls `createDOMPurify()` at module load time, and
its global lookup is `typeof window === "undefined" ? null : window`. In a
CommonJS script, `typeof` on a **temporally dead zone** binding throws instead
of returning `"undefined"` — so this fails:

```js
const createDOMPurify = require('dompurify'); // ← throws ReferenceError
const window = new JSDOM('').window;          // ← `window` is in TDZ here
```

Two ways out:

```js
// A. create the DOM first, then require DOMPurify
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const createDOMPurify = require('dompurify'); // fine

// B. use the ESM build, which does not auto-instantiate
import createDOMPurify from 'dompurify';
```

In ESM there is no TDZ problem at all — the import is hoisted, but the
auto-instantiation path is not taken the same way. purifytrace itself is
unaffected either way; it never imports DOMPurify for you.

---

## Library usage

### `createAuditedSanitizer({ createDOMPurify, window })`

Returns an object with:

| Member | Description |
|---|---|
| `sanitize(input, config?)` | Same behaviour as `DOMPurify.sanitize` — a drop-in replacement. |
| `audit(input, config?)` | `{ output, trail }` — the sanitized output plus the audit trail. |
| `instance` | The underlying DOMPurify instance, for hooks and config you manage yourself. |
| `version` / `dompurify` | purifytrace version / the DOMPurify version in use. |

The `config` argument is passed to DOMPurify **unchanged**. purifytrace never
alters a policy, never widens or narrows an allow-list, and never re-parses the
output to sanitize it again.

```js
const { trail } = sanitizer.audit(dirty, { ALLOWED_TAGS: ['b', 'i'] });
```

### The trail

```js
{
  version: '0.1.0',
  dompurify: '3.4.17',
  input: '<p onclick="x">hi</p>',
  output: '<p>hi</p>',

  events: [
    {
      action: 'strip-attribute',   // 'remove' | 'strip-attribute' | 'rewrite-attribute'
      kind: 'attribute',
      target: 'onclick',
      on: 'p',
      path: 'body > p',
      value: 'x',
      reason: { code, policyKey, confidence, detail },
    },
  ],

  stats: { elementsSeen, elementsKept, elementsRemoved, attributesSeen, bytesIn, bytesOut },
  bookkeeping: { upstreamRecords, auditOnly, upstreamOnly, ... },
  prewalk: { headIgnored, bodyUnseen, textChanged, inputTextChars, outputTextChars },
  policy: { allowedTags, allowedAttributes },
  findings: [ { code, severity, note, evidence } ],
  findingSummary: { total, high, medium, low },
  blocked: false,
}
```

### Reason confidence — read this before trusting a reason

purifytrace never claims more certainty than it has:

- **`confirmed`** — the allow-list DOMPurify handed to the hook does not contain
  the tag or attribute, so a specific config key is directly responsible.
- **`inferred`** — the item *was* allow-listed and was dropped anyway. Upstream
  does not expose the decision, so purifytrace names the most plausible rule
  (mXSS guard, namespace check, URI scheme, …) and marks it inferred.

An `inferred` reason is a lead, not a proof.

### Independent risk scan

After sanitizing, purifytrace re-parses the **output** with its own scanner —
separate code, separate rules, no shared regexps with DOMPurify — and reports
sinks that survived the policy:

| Severity | Meaning |
|---|---|
| `high` | An inline event handler, a `javascript:`/`vbscript:` URL, a `data:text/html` frame, a `<script>`/`<iframe>`/`<object>`/`<embed>` element. |
| `medium` | `data:image/svg+xml`, a `meta refresh` redirect, a `data:text/html` URL outside an auto-loading tag. |
| `low` | CSS `url(javascript:)`, IE-era `expression()` / `behavior:` / `-moz-binding`. |

This is not a second sanitizer. It is a second opinion about a *specific*
policy, and it is what catches the gap DOMPurify documents: CSS is not
sanitized at all.

```bash
npx purifytrace corpus/15-style-attribute.html
# RISK SCAN  total 1 · high 0 · medium 0 · low 1
#   LOW    css-sink @ div:1
#          javascript: inside CSS url() — legacy engines only, but the string survives
#          style="background:url(javascript:alert(1))"
```

---

## CLI

```bash
npx purifytrace <file|-> [options]
npx purifytrace --corpus <dir> [options]
npx purifytrace --diff <presetA> <presetB> <file>
```

| Option | Description |
|---|---|
| `--config <preset\|file.json>` | DOMPurify config. Preset names, or a JSON file (`"ALLOWED_URI_REGEXP": "/…/i"` is parsed as a RegExp). |
| `--format text\|json\|sarif` | Output format. Default `text`. |
| `--dom jsdom\|global` | DOM implementation. Default `jsdom`; `global` uses the runtime's own DOM. |
| `--diff <A> <B> <file>` | Compare two policies on the same input. |
| `--corpus <dir>` | Audit every `.html/.svg/.txt` file in a directory and print a table. |
| `--strict-exit` | Exit 1 on *any* finding, not just high severity. |
| `--quiet` | Print the summary table only. |
| `--presets` | List the built-in presets. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Audit completed, no high-severity residual sink. |
| `1` | Audit completed, at least one high-severity residual sink (or `--strict-exit` and any finding). |
| `2` | Usage, environment or input error. |

`2` is a real failure, never a silent pass: a missing file, an unknown
option, an unknown config name or a DOM that cannot run DOMPurify all land
there.

### Built-in presets

`default`, `strict`, `text`, `safeForTemplates`, `noDataAttrs`, `svgProfile`,
`htmlProfile`.

### JSON output

```bash
npx purifytrace payload.html --format json | jq '.events[0].reason.code'
```

### SARIF output

```bash
npx purifytrace payload.html --format sarif > report.sarif
```

SARIF 2.1.0, one result per finding — consumable by GitHub code scanning and
most CI viewers without a bespoke parser.

### Policy diff

```bash
$ npx purifytrace --diff default strict corpus/28-benign-article.html
purifytrace policy diff · default → strict

output CHANGED
  default: "<article><h2>Title</h2><p>Plain <strong>text</strong>…</article>"
  strict:  "Title<p>Plain <strong>text</strong>…</p>"
allow-list size  tags 219 → 11 · attrs 342 → 2
risk  high 0 → 0 · medium 0 → 0

NEWLY DROPPED
  + <article>  (tag-not-allowed, confirmed)
      body > article
  + <h2>  (tag-not-allowed, confirmed)
      body > article > h2
```

A policy change should be reviewed by its **delta**, not by re-reading the
whole trail. The diff keys on the recorded path, which is stable across
configurations (see the note on paths below).

---

## Demo

A static, offline demo of the audit trail over the 32-payload corpus:

**https://llinok111.github.io/purifytrace/demo/**

Every number on that page comes from the same code in this repository, run at
build time (`npm run demo`). The page makes no network requests and has no
runtime dependency.

---

## What purifytrace does **not** do

- It does not sanitize. It never touches the output.
- It does not change policy. The config reaches DOMPurify exactly as given.
- It is not a second opinion on *whether* DOMPurify is safe. It is a second
  opinion on *what a given policy left behind*.
- It does not make `DOMPurify.removed` safe for security decisions. The
  upstream warning still stands.
- It does not run in a browser without a DOM. On the server you need `jsdom`
  (or another DOM implementation); upstream's
  [wiki](https://github.com/cure53/DOMPurify/wiki/Attack-Classes-&-Bypass-History)
  explains why the server-side DOM is part of your trusted computing base.

---

## Notes on the implementation

Three upstream behaviours drive the design. All three were measured, not
assumed — the commands are in [`docs/EVIDENCE.md`](docs/EVIDENCE.md).

**1. The hook event is not the decision.** `uponSanitizeAttribute` fires
*before* the attribute verdict, and its `keepAttr` flag is recomputed
afterwards. An `onclick` arrives with `keepAttr: true` and is still dropped.
purifytrace therefore treats the **final DOM** as the source of truth and uses
the hook event only to learn *what was considered*.

**2. The walk mutates the tree it is describing.** `KEEP_CONTENT` re-parents
survivors out of a removed ancestor; `KEEP_CONTENT: false` prunes descendants
*before* the walker reaches them, so they never fire a hook at all. Both
destroy the evidence needed to say "where was this?". purifytrace snapshots
the input tree at the first hook event, while it is still intact, and computes
descendant counts in a single post-order pass.

**3. `isConnected` is not "survived".** With a narrow `ALLOWED_TAGS`,
DOMPurify detaches the walk container but still returns its innerHTML, and
nodes inside `<template>.content` live in a detached `DocumentFragment` by
design. purifytrace classifies a node by how its branch *terminates*, and
treats the walk container as kept.

### Recorded paths

Paths are built from the input tree (`body > div > svg > script`), not from
the output tree, and they are stable across configurations. That is what makes
`--diff` able to tell "this node was newly dropped" from "this node moved".

### Performance

The audit layer is not free. Measured on this machine (Node 22, jsdom 26,
DOMPurify 3.4.17, 15 runs, median):

| Payload | DOMPurify alone | purifytrace | Ratio |
|---|---|---|---|
| 1 element | 0.42 ms | 1.52 ms | 3.6× |
| 100 elements | 5.01 ms | 15.88 ms | 3.2× |
| 2000 elements | 54.62 ms | 159.60 ms | 2.9× |

The overhead is roughly constant in the number of elements, because the extra
work is one tree snapshot plus one independent parse of the output. If you
need sanitization without an audit, use `sanitize()` — it has the same
overhead profile as the plain DOMPurify call plus a hook dispatch.

`npm run bench` reproduces the table.

---

## Development

```bash
npm install
npm test                    # 61 tests
npm run corpus              # regenerate docs/corpus-report.json
npm run verify:equivalence  # audited output == plain DOMPurify, byte for byte
npm run bench               # overhead measurement
npm run demo                # rebuild demo/
npm run verify              # test + corpus + equivalence
```

### The equivalence check

`npm run verify:equivalence` is the acceptance gate for the central safety
claim. It sanitizes every corpus payload plus ten extra stress payloads with
a plain DOMPurify instance and with the audited sanitizer, under six
configurations, and requires the outputs to be byte-identical:

```
output-equality check: 252 comparisons across 6 configs
  mismatches: 0
  every audited output is byte-identical to plain DOMPurify
```

### Corpus

`corpus/` holds 32 payloads: XSS classics, mXSS, namespace confusion, parser
tricks, and four benign documents that must come through untouched. The
corpus is a regression baseline — `npm run corpus` writes
`docs/corpus-report.json`, and the tests assert:

- no corpus payload leaves an executable event handler,
- no corpus payload leaves a `javascript:` URL in a URL attribute,
- the audit agrees with `DOMPurify.removed` on every file,
- benign payloads produce zero events and zero findings.

---

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

purifytrace is an independent project. It is **not** affiliated with or
endorsed by the DOMPurify maintainers. DOMPurify itself is Apache-2.0,
copyright © Mario Heiderich and contributors.
