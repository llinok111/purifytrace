import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { JSDOM } from 'jsdom';
import { createAuditedSanitizer } from '../src/index.js';

const require = createRequire(import.meta.url);

export const window = new JSDOM('<!doctype html><html><body></body></html>').window;

export function loadFactory() {
  // The installed dompurify build, so the tests exercise the exact version the
  // package declares as its peer dependency.
  const local = require('dompurify');
  return local.default || local;
}

export function makeSanitizer() {
  return createAuditedSanitizer({ createDOMPurify: loadFactory(), window });
}

export function plainPurifier() {
  const factory = loadFactory();
  return factory(window);
}

export { assert };
