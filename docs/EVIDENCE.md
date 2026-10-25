# Evidence

Every claim in this document was produced by running a command. The commands
are reproducible against DOMPurify **3.4.17** (the version in `package.json`)
with Node 22 and jsdom 26.

The upstream checkout used for the measurements is `cure53/DOMPurify` at commit
`b7e0edc` ("Pr 1686 (#1696)").

---

## 1. `DOMPurify.removed` carries no reason and no path

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
D.sanitize('<p onclick=\"alert(1)\" class=\"c\">x</p>');
console.log(JSON.stringify(D.removed));"
[{"attribute":{"name":"onclick","namespaceURI":null,"value":"alert(1)"},"from":{...}}]
```

The record contains the attribute object and its parent element — nothing that
says *which* policy rule produced the decision.

Upstream's own README (line 90) states the limit explicitly:

> After sanitizing your markup, you can also have a look at the property
> `DOMPurify.removed` and find out, what elements and attributes were thrown
> out. Please **do not use** this property for making any security critical
> decisions. This is just a little helper for curious minds.

**Consequence for purifytrace:** the reason must be inferred from the
effective allow-list, and that inference must be labelled as such.

---

## 2. The hook event is not the decision

`uponSanitizeAttribute` fires *before* the attribute verdict, and its
`keepAttr` flag is recomputed afterwards:

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
const seen=[];
D.addHook('uponSanitizeAttribute',(n,d)=>seen.push({attr:d.attrName,keepAttr:d.keepAttr}));
D.sanitize('<p onclick=\"x\" class=\"c\">t</p>');
console.log(JSON.stringify(seen));"
[{"attr":"class","keepAttr":true},{"attr":"onclick","keepAttr":true}]
```

`onclick` arrives with `keepAttr: true` and is still dropped from the output.
The final DOM is the only trustworthy source of truth.

**Consequence for purifytrace:** attribute events are derived from the DOM
*after* `sanitize()` returns; the hook event is used only to learn *which*
attributes were considered.

---

## 3. The HTML parser discards payloads before the sanitizer runs

This is upstream issue [#988](https://github.com/cure53/DOMPurify/issues/988)
("DOMPurify.removed isn't reporting inline scripts with arbitrary text
afterwards", 2024-08-27). The maintainer's answer:

> In this case, it never gets removed by DOMPurify, but by the browser before
> sanitization happens. Hence, it never lands in `.removed` :slightly_smiling_face:

Reproduced against 3.4.17:

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
const p=\"<script>alert('XSS');</script> Some arbitrary text at the end\";
D.sanitize(p);
console.log('output  :', JSON.stringify(D.sanitize(p)));
console.log('removed :', D.removed.length);"
output  : "Some arbitrary text at the end"
removed : 0
```

Compare with the same script *not* in leading position:

```bash
$ node -e "... D.sanitize('<div>x</div><script>alert(1)</script>'); ..."
removed : ["SCRIPT"]
```

The payload is neutralized either way — there is no security bug. The gap is
observability: `.removed` is empty, and a reviewer cannot tell "nothing was
dangerous" from "something dangerous was eaten by the parser".

**Consequence for purifytrace:** the pre-walk state is parsed separately and
reported as `prewalk.headIgnored`.

---

## 4. CSS is not sanitized at all

Upstream documents this: *"DOMPurify per default allows CSS"*
(README line 172). Measured:

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
D.removed=[];
const out=D.sanitize('<div style=\"background:url(javascript:alert(1))\">x</div>');
console.log('output :', out);
console.log('removed:', D.removed.length);"
output : <div style="background:url(javascript:alert(1))">x</div>
removed: 0
```

The string survives and no record is produced. It only executes on legacy
engines, which is why purifytrace grades it `low` rather than `high` — but a
policy reviewer should still see it.

---

## 5. The walk mutates the tree it is describing

### 5a. `KEEP_CONTENT` re-parents survivors

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
console.log(D.sanitize('<object><p>a</p><b>b</b></object>'));"
<p>a</p><b>b</b>
```

The `<p>` and `<b>` survive but are no longer descendants of the removed
`<object>`. A naive "is it still inside the removed element?" test would
wrongly report them as removed.

### 5b. `KEEP_CONTENT: false` prunes descendants before the walker reaches them

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
console.log(D.sanitize('<div><section><p>a</p><p>b</p></section></div>',
  {FORBID_TAGS:['div'], KEEP_CONTENT:false}));"
```

Output is empty; the `<section>` and both `<p>` never fire a hook event, so
they cannot be reported from the walk alone.

**Consequence for purifytrace:** the input tree is snapshotted at the first
hook event — while it is still intact — and descendant counts are computed in
a single post-order pass.

---

## 6. `isConnected` does not mean "survived"

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
const rec=[];D.addHook('uponSanitizeElement',n=>{if(n.nodeType===1)rec.push(n)});
D.sanitize('<div><b>keep</b></div>', {ALLOWED_TAGS:['b']});
for (const n of rec) console.log(n.nodeName, 'connected=', n.isConnected, 'parent=', n.parentNode&&n.parentNode.nodeName);"
BODY connected= false parent= null
DIV  connected= false parent= null
B    connected= false parent= BODY
```

With a narrow allow-list the walk container (`<body>`) is detached from the
document, yet its `innerHTML` — including the surviving `<b>` — is what
DOMPurify returns. `isConnected` is `false` for elements that **did** survive.

Nodes inside `<template>.content` are in a detached `DocumentFragment` by
design, so the same test would misclassify them as well.

**Consequence for purifytrace:** a node is classified by how its branch
*terminates* (document / walk container / template fragment / detached), and
the walk container is always treated as kept.

---

## 7. Upstream records a container removal that is not a content loss

```bash
$ node -e "
const {JSDOM}=require('jsdom');const create=require('dompurify');
const w=new JSDOM('').window;const D=create(w);
D.removed=[];
console.log(D.sanitize('<article><h2>T</h2><p>x</p></article>', {ALLOWED_TAGS:['p']}));
console.log(D.removed.map(r=>r.element.nodeName));"
T<p>x</p>
["BODY", "ARTICLE", "H2"]
```

`<body>` is in `.removed` even though its content survived. A naive
comparison against `.removed` would flag a permanent mismatch.

**Consequence for purifytrace:** the walk container is excluded from the
bookkeeping comparison and the exclusion is reported explicitly
(`upstreamOnly[].explained`), never silently dropped.

---

## 8. Measured overhead of the audit layer

```bash
$ npm run bench
```

15 runs, median, Node 22 / jsdom 26 / DOMPurify 3.4.17:

| Payload | DOMPurify alone | purifytrace | Ratio |
|---|---|---|---|
| 1 element | 0.42 ms | 1.52 ms | 3.6× |
| 100 elements | 5.01 ms | 15.88 ms | 3.2× |
| 2000 elements | 54.62 ms | 159.60 ms | 2.9× |
| 32-payload corpus | 0.40 ms | 1.29 ms | 3.3× |

Two optimizations were driven by measurement rather than guesswork, and both
were confirmed by a CPU profile (`node --cpu-prof`):

1. **O(n²) tree snapshot.** Counting descendants per element (one subtree walk
   each) cost **121 ms** on a 2000-element document. A single post-order pass
   removed it.
2. **`children` vs `childNodes`.** In jsdom, `children` is a live
   `HTMLCollection` implemented as a Proxy; iterating it calls
   `getOwnPropertyDescriptor` per index. It accounted for **17 %** of the whole
   audit run in the profile. Switching to `childNodes` removed it.

After both fixes the 2000-element case dropped from 572 ms to 160 ms of audit
time.

A third change removed a redundant parse: the output was parsed twice (once
for the risk scan, once for the text comparison); it is now parsed once and
shared.

---

## 9. Upstream test-suite regression

DOMPurify's own suite is the reference implementation's regression gate. It
must stay green:

```bash
$ cd dompurify-up && npm run build && npm run test:jsdom
```

Result: **2455 assertions, 0 failures**, exit code 0 (the runner prints one dot
per assertion; `test/jsdom-node-runner` exits non-zero on any `not ok`).

purifytrace does not patch DOMPurify, so this suite is unchanged by design —
it is run to prove the *upstream* behaviour the audit layer depends on is
stable.

---

## 10. Corpus regression baseline

```bash
$ npm run corpus
corpus report written: docs/corpus-report.json
  default      files 32 · events 21 · findings 1 (high 0) · upstream mismatch 0 · pre-walk 6
  strict       files 32 · events 44 · findings 0 (high 0) · upstream mismatch 0 · pre-walk 17
  text         files 32 · events 51 · findings 0 (high 0) · upstream mismatch 0 · pre-walk 17
  noDataAttrs  files 32 · events 21 · findings 1 (high 0) · upstream mismatch 0 · pre-walk 6
```

`upstream mismatch 0` means: for every corpus file and every config, the
audit's element and attribute decisions match `DOMPurify.removed` exactly,
after the one documented container exclusion (section 7).

`pre-walk 6` under the default config is the number of payloads the HTML
parser discarded before the sanitizer saw them — invisible to
`DOMPurify.removed`.

---

## 11. Output-equality acceptance gate

The central safety claim of purifytrace is that the audit layer never changes
what DOMPurify produces. That is checked mechanically, not asserted:

```bash
$ npm run verify:equivalence
output-equality check: 252 comparisons across 6 configs
  mismatches: 0
  every audited output is byte-identical to plain DOMPurify
```

252 comparisons = 42 payloads (32 corpus files + 10 stress payloads) × 6
configurations (`default`, `strict`, `text`, `noDataAttrs`, `svgProfile`,
`safeTemplates`). Each payload is sanitized by a plain DOMPurify instance and
by the audited sanitizer with the same config, and the two outputs are
compared byte for byte.

This gate runs in CI on every matrix entry.

---

## 12. Demo page, verified against the live deployment

The demo is not a mockup: it is the same audit code, run over the same corpus,
with the results baked into `demo/data.js` at build time.

Local capture and live capture are **pixel-identical** (sha1 of the PNG is the
same for both), which is the strongest available evidence that the deployed
page is the one that was verified locally.

```bash
$ node scripts/verify-demo.mjs    # local file:// render
{ "status": 200, "payloads": 32, "files": 32, "panels": 4, "stats": 6,
  "eventRows": 1, "consoleErrors": [], "failedRequests": [],
  "externalResources": [], "problems": [] }

$ # live https://llinok111.github.io/purifytrace/demo/
{ "status": 200, "payloads": 32, "files": 32, "panels": 4, "stats": 6,
  "rows": 1, "activeFile": "03-event-handler.html",
  "externalRequests": [], "errors": [], "failed": [] }

$ sha1sum shots/live-demo.png shots/demo.png
1e480e373a5027d24b13ca369d1b92d4ce5fa6cd *live-demo.png
1e480e373a5027d24b13ca369d1b92d4ce5fa6cd *demo.png
```

Because the page is dark and uses a single accent hue, the generic
"distinct colours ≥ 200" blank-frame heuristic flags it as SUSPECT even when
fully rendered. The check that actually discriminates is per-region ink
coverage (fraction of pixels differing from the region's own background by
more than 18 luma):

```
  header                     ink= 1.83%  distinct_luma=101  OK
  sidebar (file list)        ink= 6.66%  distinct_luma= 43  OK
  stat boxes                 ink= 4.86%  distinct_luma=108  OK
  input panel                ink= 2.23%  distinct_luma= 57  OK
  output panel               ink= 6.56%  distinct_luma= 91  OK
  events table               ink= 0.54%  distinct_luma= 37  OK
```

All six regions carry content; none is blank. The demo makes zero external
requests — `performance.getEntriesByType('resource')` filtered to non-demo
origins is empty.

---

## 13. Test suite

```bash
$ npm test
# tests 61
# pass 61
# fail 0
```

The suite covers: packaging metadata vs README claims, reason attribution per config key, subtree accounting,
re-parenting by `KEEP_CONTENT`, the pre-walk loss, the risk scan, output
equality with plain DOMPurify on a payload corpus, policy diffing, CLI exit
codes, JSON/SARIF output shape, `IN_PLACE` mode, an unsupported DOM, unicode
round-tripping, and the 32-file corpus invariants.
