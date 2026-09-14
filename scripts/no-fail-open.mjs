#!/usr/bin/env node
/**
 * Repo invariant for sdk-typescript: no error path may produce an allow.
 *
 * Scoped to this package. The Python SDK's reviewed fail_open opt-in and the
 * Guardian operator setting live elsewhere and are not this script's business.
 *
 * Checks, on src/ only (tests are expected to mention these tokens):
 *   1. No option that converts a failure into a verdict: continueOnError,
 *      failOpen, fail_open, onErrorAllow, defaultAction.
 *   2. No catch block whose body returns or builds an allow-shaped value.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('../src', import.meta.url).pathname;
const files = [];
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith('.ts')) files.push(p);
  }
})(root);

const forbiddenOptions = /\b(continueOnError|failOpen|fail_open|onErrorAllow|defaultAction)\b/;
// catch (...) { ... allow ... } within a bounded window, ignoring comments
const catchAllow = /catch\s*(\([^)]*\))?\s*\{[^}]{0,400}(action:\s*['"]allow['"]|blocked:\s*false|isThreat:\s*false)/s;

let failed = false;
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const rel = relative(process.cwd(), f);
  const m1 = code.match(forbiddenOptions);
  if (m1) { console.error(`::error file=${rel}::fail-open option "${m1[1]}" is not allowed in this SDK`); failed = true; }
  const m2 = code.match(catchAllow);
  if (m2) { console.error(`::error file=${rel}::a catch block appears to produce an allow`); failed = true; }
}
if (failed) process.exit(1);
console.log(`ok: ${files.length} source files, no fail-open paths`);
