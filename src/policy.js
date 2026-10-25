/**
 * Policy snapshot helpers.
 *
 * purifytrace never guesses what DOMPurify's effective allow-lists are: the
 * sanitizer hands the live sets to `uponSanitizeElement` / `uponSanitizeAttribute`
 * hook events (`allowedTags`, `allowedAttributes`). We keep the reference for the
 * duration of one call and read it only after the walk has finished.
 */

/** Attributes whose value DOMPurify treats as a URI. */
export const URI_ATTRIBUTES = new Set([
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
  'usemap',
  'ping',
  'manifest',
  'codebase',
  'profile',
  'srcset',
]);

/** DOMPurify's built-in URI allow-list, mirrored for *explanation only*. */
export const DEFAULT_URI_REGEXP =
  /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp):|[^a-z]|[a-z+.-]+(?:[^a-z+.-:]|$))/i;

const TAG_KEYS = ['ALLOWED_TAGS', 'ADD_TAGS', 'FORBID_TAGS'];
const ATTR_KEYS = ['ALLOWED_ATTR', 'ADD_ATTR', 'FORBID_ATTR'];

/**
 * Normalise a DOMPurify config object into lookup-friendly form.
 * Arrays become Sets; everything else is passed through untouched so callers
 * can still recognise their own custom keys.
 *
 * @param {Record<string, unknown>|undefined} config
 */
export function normalizeConfig(config = {}) {
  const out = { ...config };
  for (const key of [...TAG_KEYS, ...ATTR_KEYS]) {
    const value = config[key];
    if (Array.isArray(value)) out[key] = new Set(value.map((entry) => String(entry).toLowerCase()));
  }
  return out;
}

/** True when the config narrows tags via an explicit allow-list. */
export function hasExplicitTagAllowlist(config) {
  return config.ALLOWED_TAGS instanceof Set;
}

/** Human-readable name of the config key that produced a tag decision. */
export function tagPolicyKey(config, tag) {
  if (config.FORBID_TAGS instanceof Set && config.FORBID_TAGS.has(tag)) return 'FORBID_TAGS';
  if (hasExplicitTagAllowlist(config) && !config.ALLOWED_TAGS.has(tag)) return 'ALLOWED_TAGS';
  if (config.USE_PROFILES) return 'USE_PROFILES';
  return 'ALLOWED_TAGS (default)';
}

/** Human-readable name of the config key that produced an attribute decision. */
export function attributePolicyKey(config, name) {
  if (config.FORBID_ATTR instanceof Set && config.FORBID_ATTR.has(name)) return 'FORBID_ATTR';
  if (config.ALLOWED_ATTR instanceof Set && !config.ALLOWED_ATTR.has(name)) return 'ALLOWED_ATTR';
  if (name.startsWith('data-') && config.ALLOW_DATA_ATTR === false) return 'ALLOW_DATA_ATTR';
  if (name.startsWith('aria-') && config.ALLOW_ARIA_ATTR === false) return 'ALLOW_ARIA_ATTR';
  if (name.startsWith('on')) return 'ALLOWED_ATTR (event handlers are never default-allowed)';
  return 'ALLOWED_ATTR (default)';
}

/** True for `foo-bar` style names that the HTML parser treats as custom elements. */
export function looksLikeCustomElement(tag) {
  return tag.includes('-');
}

/**
 * Strip characters a browser ignores before a URL scheme, then compare the
 * scheme against a policy regexp. Used to *explain* a value rejection, not to
 * make a security decision.
 *
 * @param {string} value
 * @param {RegExp} [regexp]
 */
export function uriAllowed(value, regexp) {
  const cleaned = String(value).replace(/[\u0000-\u0020\u007f-\u009f]/g, '');
  const rx = regexp instanceof RegExp ? regexp : DEFAULT_URI_REGEXP;
  return rx.test(cleaned);
}

/** Lowercased, whitespace-trimmed attribute name list of a DOM element. */
export function attributeNames(node) {
  if (!node || typeof node.getAttributeNames !== 'function') return [];
  return node.getAttributeNames().map((name) => name.toLowerCase());
}
