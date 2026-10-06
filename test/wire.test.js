import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { IDENTITY_HEADER } from '../dist/index.js';

const SPEC = JSON.parse(readFileSync(new URL('./fixtures/wire-constants.json', import.meta.url), 'utf8'));

test('the identity header is the spec’s', () => {
  assert.equal(IDENTITY_HEADER, SPEC.identity.header);
});

test('the spec copy is the version this client was written against', () => {
  assert.equal(SPEC.version, '1.0.0');
});
