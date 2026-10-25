window.PURIFYTRACE_DATA = {
  "generatedBy": "npm run demo",
  "dompurify": "3.4.17",
  "purifytrace": "0.1.0",
  "configs": [
    "default",
    "strict"
  ],
  "entries": [
    {
      "file": "01-inline-script.html",
      "input": "<div>before</div><script>alert(1)</script><div>after</div>",
      "configs": {
        "default": {
          "output": "<div>before</div><div>after</div>\n",
          "events": [
            {
              "action": "remove",
              "target": "script",
              "path": "body > script",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<script> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 3,
            "bytesIn": 59,
            "bytesOut": 34
          }
        },
        "strict": {
          "output": "beforeafter\n",
          "events": [
            {
              "action": "remove",
              "target": "div",
              "path": "body > div",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<div> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "script",
              "path": "body > script",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<script> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "div",
              "path": "body > div[2]",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<div> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 4,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 3,
            "attributesSeen": 0,
            "textNodesSeen": 3,
            "bytesIn": 59,
            "bytesOut": 12
          }
        }
      }
    },
    {
      "file": "02-leading-script.html",
      "input": "<script>alert('XSS');</script> trailing text",
      "configs": {
        "default": {
          "output": "trailing text\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "script",
              "text": "alert('XSS');"
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 0,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 45,
            "bytesOut": 14
          }
        },
        "strict": {
          "output": "trailing text\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "script",
              "text": "alert('XSS');"
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 0,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 45,
            "bytesOut": 14
          }
        }
      }
    },
    {
      "file": "03-event-handler.html",
      "input": "<img src=\"/x.png\" onerror=\"alert(1)\">",
      "configs": {
        "default": {
          "output": "<img src=\"/x.png\">\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "onerror",
              "on": "img",
              "path": "body > img",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "onerror is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 1,
            "bytesIn": 38,
            "bytesOut": 19
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "img",
              "path": "body > img",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<img> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 38,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "04-uppercase-handler.html",
      "input": "<img src=\"/x.png\" ONERROR=alert(1)>",
      "configs": {
        "default": {
          "output": "<img src=\"/x.png\">\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "onerror",
              "on": "img",
              "path": "body > img",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "onerror is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 1,
            "bytesIn": 36,
            "bytesOut": 19
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "img",
              "path": "body > img",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<img> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 36,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "05-javascript-href.html",
      "input": "<a href=\"javascript:alert(1)\">click</a>",
      "configs": {
        "default": {
          "output": "<a>click</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 40,
            "bytesOut": 13
          }
        },
        "strict": {
          "output": "<a>click</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 40,
            "bytesOut": 13
          }
        }
      }
    },
    {
      "file": "06-js-scheme-obfuscated.html",
      "input": "<a href=\"java\nscript:alert(1)\">click</a>",
      "configs": {
        "default": {
          "output": "<a>click</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "java\nscript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 41,
            "bytesOut": 13
          }
        },
        "strict": {
          "output": "<a>click</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "java\nscript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 41,
            "bytesOut": 13
          }
        }
      }
    },
    {
      "file": "07-data-html-iframe.html",
      "input": "<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
      "configs": {
        "default": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 65,
            "bytesOut": 1
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 65,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "08-iframe-external.html",
      "input": "<iframe src=\"https://example.com/frame\"></iframe>",
      "configs": {
        "default": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 50,
            "bytesOut": 1
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 50,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "09-svg-script.html",
      "input": "<svg><script>alert(1)</script></svg>",
      "configs": {
        "default": {
          "output": "<svg></svg>\n",
          "events": [
            {
              "action": "remove",
              "target": "script",
              "path": "body > svg > script",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "svg element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 37,
            "bytesOut": 12
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "svg",
              "path": "body > svg",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "svg element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 37,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "10-svg-onload.html",
      "input": "<svg><circle cx=\"1\" cy=\"1\" r=\"1\" onload=\"alert(1)\"/></svg>",
      "configs": {
        "default": {
          "output": "<svg><circle cx=\"1\" cy=\"1\" r=\"1\"></circle></svg>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "onload",
              "on": "circle",
              "path": "body > svg > circle",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "onload is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 0,
            "attributesSeen": 4,
            "textNodesSeen": 1,
            "bytesIn": 59,
            "bytesOut": 49
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "svg",
              "path": "body > svg",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "svg element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 59,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "11-mathml-xlink.html",
      "input": "<math><mi xlink:href=\"javascript:alert(1)\">x</mi></math>",
      "configs": {
        "default": {
          "output": "<math><mi>x</mi></math>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "xlink:href",
              "on": "mi",
              "path": "body > math > mi",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 57,
            "bytesOut": 24
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "math",
              "path": "body > math",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "mathml element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": true,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 57,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "12-mxss-mglyph.html",
      "input": "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
      "configs": {
        "default": {
          "output": "<math><mtext><table></table></mtext></math>",
          "events": [
            {
              "action": "remove",
              "target": "mglyph",
              "path": "body > math > mtext > mglyph",
              "reason": "content-rule",
              "policyKey": null,
              "confidence": "inferred",
              "detail": "<mglyph> is allow-listed but was removed by a content rule (mXSS guard, namespace check or forbidden contents)"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 4,
            "containerTag": "body",
            "elementsKept": 3,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 0,
            "bytesIn": 64,
            "bytesOut": 43
          }
        },
        "strict": {
          "output": "",
          "events": [
            {
              "action": "remove",
              "target": "math",
              "path": "body > math",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "mathml element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 0,
            "bytesIn": 64,
            "bytesOut": 0
          }
        }
      }
    },
    {
      "file": "13-template-payload.html",
      "input": "<div><template><img src=x onerror=alert(1)></template></div>",
      "configs": {
        "default": {
          "output": "<div><template><img src=\"x\"></template></div>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "onerror",
              "on": "img",
              "path": "body > div > template > img",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "onerror is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 3,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 1,
            "bytesIn": 61,
            "bytesOut": 46
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "div",
              "path": "body > div",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<div> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "template",
              "path": "body > div > template",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<template> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "img",
              "path": "body > div > template > img",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<img> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 4,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 3,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 61,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "14-style-tag.html",
      "input": "<style>body{background:url(javascript:alert(1))}</style><p>text</p>",
      "configs": {
        "default": {
          "output": "<p>text</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "style",
              "text": "body{background:url(javascript:alert(1))}"
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 68,
            "bytesOut": 12
          }
        },
        "strict": {
          "output": "<p>text</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "style",
              "text": "body{background:url(javascript:alert(1))}"
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 68,
            "bytesOut": 12
          }
        }
      }
    },
    {
      "file": "15-style-attribute.html",
      "input": "<div style=\"background:url(javascript:alert(1))\">text</div>",
      "configs": {
        "default": {
          "output": "<div style=\"background:url(javascript:alert(1))\">text</div>\n",
          "events": [],
          "findings": [
            {
              "code": "css-sink",
              "severity": "low",
              "note": "javascript: inside CSS url() — legacy engines only, but the string survives",
              "evidence": "background:url(javascript:alert(1))"
            }
          ],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 60,
            "bytesOut": 60
          }
        },
        "strict": {
          "output": "text\n",
          "events": [
            {
              "action": "remove",
              "target": "div",
              "path": "body > div",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<div> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 60,
            "bytesOut": 5
          }
        }
      }
    },
    {
      "file": "16-form-action.html",
      "input": "<form action=\"javascript:alert(1)\"><input name=\"q\"></form>",
      "configs": {
        "default": {
          "output": "<form><input name=\"q\"></form>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "action",
              "on": "form",
              "path": "body > form",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 1,
            "bytesIn": 59,
            "bytesOut": 30
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "form",
              "path": "body > form",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<form> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "input",
              "path": "body > form > input",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<input> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 3,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 2,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 59,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "17-base-tag.html",
      "input": "<base href=\"javascript:alert(1)//\"><a href=\"x\">link</a>",
      "configs": {
        "default": {
          "output": "<a href=\"x\">link</a>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "base",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 56,
            "bytesOut": 21
          }
        },
        "strict": {
          "output": "<a href=\"x\">link</a>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "base",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 56,
            "bytesOut": 21
          }
        }
      }
    },
    {
      "file": "18-meta-refresh.html",
      "input": "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\"><p>x</p>",
      "configs": {
        "default": {
          "output": "<p>x</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "meta",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 72,
            "bytesOut": 9
          }
        },
        "strict": {
          "output": "<p>x</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "meta",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 72,
            "bytesOut": 9
          }
        }
      }
    },
    {
      "file": "19-object-data.html",
      "input": "<object data=\"javascript:alert(1)\"></object>",
      "configs": {
        "default": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "object",
              "path": "body > object",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<object> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 45,
            "bytesOut": 1
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "object",
              "path": "body > object",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<object> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 45,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "20-embed-src.html",
      "input": "<embed src=\"data:text/html,<script>alert(1)</script>\">",
      "configs": {
        "default": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "embed",
              "path": "body > embed",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<embed> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 55,
            "bytesOut": 1
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "embed",
              "path": "body > embed",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<embed> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 55,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "21-srcdoc.html",
      "input": "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\"></iframe>",
      "configs": {
        "default": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS (default)",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 65,
            "bytesOut": 1
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "iframe",
              "path": "body > iframe",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<iframe> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 65,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "22-entity-encoded.html",
      "input": "<a href=\"&#106;avascript:alert(1)\">x</a>",
      "configs": {
        "default": {
          "output": "<a>x</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 41,
            "bytesOut": 9
          }
        },
        "strict": {
          "output": "<a>x</a>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "href",
              "on": "a",
              "path": "body > a",
              "value": "javascript:alert(1)",
              "reason": "uri-scheme-blocked",
              "policyKey": "ALLOWED_URI_REGEXP",
              "confidence": "inferred",
              "detail": "scheme javascript: is outside the URI allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 2,
            "bytesIn": 41,
            "bytesOut": 9
          }
        }
      }
    },
    {
      "file": "23-noscript.html",
      "input": "<noscript><p>fallback</p></noscript>",
      "configs": {
        "default": {
          "output": "<p>fallback</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "noscript",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 37,
            "bytesOut": 16
          }
        },
        "strict": {
          "output": "<p>fallback</p>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [
            {
              "tag": "noscript",
              "text": ""
            }
          ],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 37,
            "bytesOut": 16
          }
        }
      }
    },
    {
      "file": "24-comment-split.html",
      "input": "<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>",
      "configs": {
        "default": {
          "output": "ipt&gt;alert(1)ipt&gt;\n",
          "events": [
            {
              "action": "remove",
              "target": "scr<!--",
              "path": "body > scr<!--",
              "reason": "custom-element-disallowed",
              "policyKey": "CUSTOM_ELEMENT_HANDLING",
              "confidence": "confirmed",
              "detail": "custom elements need CUSTOM_ELEMENT_HANDLING; ADD_TAGS alone only allow-lists the name"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 42,
            "bytesOut": 23
          }
        },
        "strict": {
          "output": "ipt&gt;alert(1)ipt&gt;\n",
          "events": [
            {
              "action": "remove",
              "target": "scr<!--",
              "path": "body > scr<!--",
              "reason": "custom-element-disallowed",
              "policyKey": "CUSTOM_ELEMENT_HANDLING",
              "confidence": "confirmed",
              "detail": "custom elements need CUSTOM_ELEMENT_HANDLING; ADD_TAGS alone only allow-lists the name"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 42,
            "bytesOut": 23
          }
        }
      }
    },
    {
      "file": "25-double-encoded.html",
      "input": "<img src=x onerror=\"&#x61;lert(1)\">",
      "configs": {
        "default": {
          "output": "<img src=\"x\">\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "onerror",
              "on": "img",
              "path": "body > img",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "onerror is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 1,
            "bytesIn": 36,
            "bytesOut": 14
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "img",
              "path": "body > img",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<img> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 36,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "26-svg-use-data.html",
      "input": "<svg><use href=\"data:image/svg+xml,<svg onload=alert(1)>\"></use></svg>",
      "configs": {
        "default": {
          "output": "<svg></svg>\n",
          "events": [
            {
              "action": "remove",
              "target": "use",
              "path": "body > svg > use",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "svg element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 1,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 71,
            "bytesOut": 12
          }
        },
        "strict": {
          "output": "\n",
          "events": [
            {
              "action": "remove",
              "target": "svg",
              "path": "body > svg",
              "reason": "namespace-tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "svg element is not in the effective allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 2,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 1,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 1,
            "attributesSeen": 0,
            "textNodesSeen": 1,
            "bytesIn": 71,
            "bytesOut": 1
          }
        }
      }
    },
    {
      "file": "27-details-ontoggle.html",
      "input": "<details open ontoggle=\"alert(1)\"><summary>s</summary></details>",
      "configs": {
        "default": {
          "output": "<details open=\"\"><summary>s</summary></details>\n",
          "events": [
            {
              "action": "strip-attribute",
              "target": "ontoggle",
              "on": "details",
              "path": "body > details",
              "value": "alert(1)",
              "reason": "event-handler-attribute",
              "policyKey": "ALLOWED_ATTR (event handlers are never default-allowed)",
              "confidence": "confirmed",
              "detail": "ontoggle is not in the effective attribute allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 1,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 2,
            "bytesIn": 65,
            "bytesOut": 48
          }
        },
        "strict": {
          "output": "s\n",
          "events": [
            {
              "action": "remove",
              "target": "details",
              "path": "body > details",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<details> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "summary",
              "path": "body > details > summary",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<summary> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 3,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 2,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 65,
            "bytesOut": 2
          }
        }
      }
    },
    {
      "file": "28-benign-article.html",
      "input": "<article><h2>Title</h2><p>Plain <strong>text</strong> with <a href=\"https://example.com\">link</a>.</p></article>",
      "configs": {
        "default": {
          "output": "<article><h2>Title</h2><p>Plain <strong>text</strong> with <a href=\"https://example.com\">link</a>.</p></article>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 5,
            "containerTag": "body",
            "elementsKept": 5,
            "elementsRemoved": 0,
            "attributesSeen": 1,
            "textNodesSeen": 7,
            "bytesIn": 113,
            "bytesOut": 113
          }
        },
        "strict": {
          "output": "Title<p>Plain <strong>text</strong> with <a href=\"https://example.com\">link</a>.</p>\n",
          "events": [
            {
              "action": "remove",
              "target": "article",
              "path": "body > article",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<article> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "h2",
              "path": "body > article > h2",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<h2> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 3,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 5,
            "containerTag": "body",
            "elementsKept": 3,
            "elementsRemoved": 2,
            "attributesSeen": 1,
            "textNodesSeen": 7,
            "bytesIn": 113,
            "bytesOut": 85
          }
        }
      }
    },
    {
      "file": "29-benign-figure.html",
      "input": "<figure><img src=\"/a.png\" alt=\"a\"><figcaption>caption</figcaption></figure>",
      "configs": {
        "default": {
          "output": "<figure><img src=\"/a.png\" alt=\"a\"><figcaption>caption</figcaption></figure>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 3,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 2,
            "bytesIn": 76,
            "bytesOut": 76
          }
        },
        "strict": {
          "output": "caption\n",
          "events": [
            {
              "action": "remove",
              "target": "figure",
              "path": "body > figure",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<figure> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "img",
              "path": "body > figure > img",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<img> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "figcaption",
              "path": "body > figure > figcaption",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<figcaption> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 4,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 3,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 3,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 76,
            "bytesOut": 8
          }
        }
      }
    },
    {
      "file": "30-benign-table.html",
      "input": "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>v</td></tr></tbody></table>",
      "configs": {
        "default": {
          "output": "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>v</td></tr></tbody></table>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 7,
            "containerTag": "body",
            "elementsKept": 7,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 3,
            "bytesIn": 84,
            "bytesOut": 84
          }
        },
        "strict": {
          "output": "v\n",
          "events": [
            {
              "action": "remove",
              "target": "table",
              "path": "body > table",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<table> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "thead",
              "path": "body > table > thead",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<thead> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "tbody",
              "path": "body > table > tbody",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<tbody> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "tr",
              "path": "body > table > tbody > tr",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<tr> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "td",
              "path": "body > table > tbody > tr > td",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<td> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 6,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": true,
          "stats": {
            "elementsSeen": 5,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 5,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 84,
            "bytesOut": 2
          }
        }
      }
    },
    {
      "file": "31-benign-form.html",
      "input": "<form action=\"/search\"><label>q<input name=\"q\"></label><button>go</button></form>",
      "configs": {
        "default": {
          "output": "<form action=\"/search\"><label>q<input name=\"q\"></label><button>go</button></form>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 4,
            "containerTag": "body",
            "elementsKept": 4,
            "elementsRemoved": 0,
            "attributesSeen": 2,
            "textNodesSeen": 3,
            "bytesIn": 82,
            "bytesOut": 82
          }
        },
        "strict": {
          "output": "qgo\n",
          "events": [
            {
              "action": "remove",
              "target": "form",
              "path": "body > form",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<form> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "label",
              "path": "body > form > label",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<label> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "input",
              "path": "body > form > label > input",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<input> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "button",
              "path": "body > form > button",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<button> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 5,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 4,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 4,
            "attributesSeen": 0,
            "textNodesSeen": 3,
            "bytesIn": 82,
            "bytesOut": 4
          }
        }
      }
    },
    {
      "file": "32-benign-code.html",
      "input": "<pre><code>const a = 1 &lt; 2;</code></pre>",
      "configs": {
        "default": {
          "output": "<pre><code>const a = 1 &lt; 2;</code></pre>\n",
          "events": [],
          "findings": [],
          "upstreamRecords": 0,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 2,
            "elementsRemoved": 0,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 44,
            "bytesOut": 44
          }
        },
        "strict": {
          "output": "const a = 1 &lt; 2;\n",
          "events": [
            {
              "action": "remove",
              "target": "pre",
              "path": "body > pre",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<pre> is not in the effective tag allow-list"
            },
            {
              "action": "remove",
              "target": "code",
              "path": "body > pre > code",
              "reason": "tag-not-allowed",
              "policyKey": "ALLOWED_TAGS",
              "confidence": "confirmed",
              "detail": "<code> is not in the effective tag allow-list"
            }
          ],
          "findings": [],
          "upstreamRecords": 3,
          "upstreamMismatch": 0,
          "headIgnored": [],
          "textChanged": false,
          "stats": {
            "elementsSeen": 2,
            "containerTag": "body",
            "elementsKept": 0,
            "elementsRemoved": 2,
            "attributesSeen": 0,
            "textNodesSeen": 2,
            "bytesIn": 44,
            "bytesOut": 20
          }
        }
      }
    }
  ]
};
