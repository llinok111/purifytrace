/**
 * Reason inference.
 *
 * A reason is the *narrowest config key or content rule* that explains why
 * DOMPurify dropped something. Two confidence levels are reported honestly:
 *
 *  - `confirmed`  the allow-list DOMPurify handed to the hook does not contain
 *                 the tag/attribute, so a config key is directly responsible.
 *  - `inferred`   the item was allow-listed yet still removed. Upstream does not
 *                 expose the decision, so we name the most plausible rule and
 *                 mark it inferred. purifytrace never claims certainty here.
 */

import { attributePolicyKey, looksLikeCustomElement, tagPolicyKey, URI_ATTRIBUTES, uriAllowed } from './policy.js';

const SCRIPTABLE_TAGS = new Set(['script', 'style', 'noscript', 'template', 'title', 'base', 'meta', 'link']);

/** Extract a URI scheme without letting control characters hide it. */
export function schemeOf(value) {
  const cleaned = String(value || '').replace(/[\u0000-\u0020\u007f-\u009f]/g, '');
  const match = cleaned.match(/^([a-z][a-z0-9+.-]*):/i);
  return match ? `${match[1].toLowerCase()}:` : null;
}

/**
 * @param {Record<string, unknown>} config normalised config (see policy.normalizeConfig)
 */
export function createReasoner(config = {}) {
  return {
    /**
     * @param {{tag: string, ns: string}} element
     * @param {{allowedTags: Record<string, boolean>|null}} session
     */
    element(element, session) {
      const tag = element.tag;
      const allowed = session.allowedTags ? session.allowedTags[tag] === true : null;

      // FORBID_TAGS wins even when the tag is also in the allow-list: DOMPurify
      // checks the forbid set separately, so `allowedTags[tag]` can still be true.
      if (config.FORBID_TAGS instanceof Set && config.FORBID_TAGS.has(tag)) {
        return {
          code: 'tag-forbidden',
          policyKey: 'FORBID_TAGS',
          confidence: 'confirmed',
          detail: `<${tag}> is listed in FORBID_TAGS`,
        };
      }

      if (allowed === false) {
        if (looksLikeCustomElement(tag) && !customElementsEnabled(config)) {
          return {
            code: 'custom-element-disallowed',
            policyKey: 'CUSTOM_ELEMENT_HANDLING',
            confidence: 'confirmed',
            detail: 'custom elements need CUSTOM_ELEMENT_HANDLING; ADD_TAGS alone only allow-lists the name',
          };
        }
        if (element.ns !== 'html') {
          return {
            code: 'namespace-tag-not-allowed',
            policyKey: config.USE_PROFILES ? 'USE_PROFILES' : 'ALLOWED_TAGS',
            confidence: 'confirmed',
            detail: `${element.ns} element is not in the effective allow-list`,
          };
        }
        return {
          code: 'tag-not-allowed',
          policyKey: tagPolicyKey(config, tag),
          confidence: 'confirmed',
          detail: `<${tag}> is not in the effective tag allow-list`,
        };
      }

      return {
        code: SCRIPTABLE_TAGS.has(tag) ? 'scriptable-tag-removed' : 'content-rule',
        policyKey: null,
        confidence: 'inferred',
        detail: `<${tag}> is allow-listed but was removed by a content rule (mXSS guard, namespace check or forbidden contents)`,
      };
    },

    /**
     * @param {{name: string, value: string}} attr
     * @param {{tag: string}|undefined} element
     * @param {{allowedAttrs: Record<string, boolean>|null}} session
     */
    attribute(attr, element, session) {
      const name = attr.name;
      const allowed = session.allowedAttrs ? session.allowedAttrs[name] === true : null;

      if (config.FORBID_ATTR instanceof Set && config.FORBID_ATTR.has(name)) {
        return {
          code: 'attribute-forbidden',
          policyKey: 'FORBID_ATTR',
          confidence: 'confirmed',
          detail: `${name} is listed in FORBID_ATTR`,
        };
      }

      if (allowed === false) {
        return {
          code: /^on/.test(name) ? 'event-handler-attribute' : name.startsWith('data-') ? 'data-attribute-not-allowed' : 'attribute-not-allowed',
          policyKey: attributePolicyKey(config, name),
          confidence: 'confirmed',
          detail: `${name} is not in the effective attribute allow-list`,
        };
      }

      if (URI_ATTRIBUTES.has(name) && !uriAllowed(attr.value, config.ALLOWED_URI_REGEXP)) {
        return {
          code: 'uri-scheme-blocked',
          policyKey: 'ALLOWED_URI_REGEXP',
          confidence: 'inferred',
          detail: `scheme ${schemeOf(attr.value) || '(none)'} is outside the URI allow-list`,
        };
      }

      if (config.SAFE_FOR_TEMPLATES) {
        return {
          code: 'template-expression-blocked',
          policyKey: 'SAFE_FOR_TEMPLATES',
          confidence: 'inferred',
          detail: 'template expression markers are stripped when SAFE_FOR_TEMPLATES is on',
        };
      }

      return {
        code: 'value-rejected',
        policyKey: null,
        confidence: 'inferred',
        detail: `${name} is allow-listed on <${element ? element.tag : 'unknown'}> but its value failed a value-level check`,
      };
    },
  };
}

function customElementsEnabled(config) {
  const handling = config.CUSTOM_ELEMENT_HANDLING;
  if (!handling) return false;
  if (handling.tagNameCheck instanceof RegExp) return true;
  if (typeof handling.tagNameCheck === 'function') return true;
  if (handling.allowCustomizedBuiltInElements) return true;
  return false;
}
