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
 *   3. No allow-shaped literal anywhere but the response parser (src/parse.ts): only parsing a
 *      server response may produce an allow. Rule 2 alone let a fabricated allow on a non-error
 *      path through -- found re-pointing this client at the control plane (BlindAI pilot S,
 *      2026-10-06), where `authorize` returning `{ blocked: false }` for some input passed.
 *      Exempt: src/types.ts (declarations) and src/testing/ (builds server-shaped BODIES, which
 *      still reach the client through parseDecision). The exemptions are held to that, after the
 *      cold review of this rule (blindai-js#3):
 *   4. No src file outside src/testing/ imports from it: `parseDecision(decision.allow().body)` in
 *      the client would otherwise be an allow the server never gave, built from shipped helpers.
 *   5. src/types.ts exports no values (const, let, var, function, class, enum, default): exempt
 *      because it only declares, so it must only declare.
 *   Keys are matched quoted or not: `"blocked": false` is the same allow as `blocked: false`.
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
const q = `["'\`]?`;
const allowLiteral = new RegExp(
  `(${q}blocked${q}\\s*:\\s*false|${q}allowed${q}\\s*:\\s*true|${q}action${q}\\s*:\\s*['"\`]allow['"\`]|${q}isThreat${q}\\s*:\\s*false)`,
);
const testingImport = /from\s+['"][^'"]*\/testing(?:\/[^'"]*)?(?:\.js)?['"]|import\(\s*['"][^'"]*\/testing/;
const valueExport = /\bexport\s+(?:default\b|const\b|let\b|var\b|function\b|async\s+function\b|class\b|enum\b)/;
const parserOrExempt = (rel) =>
  rel.endsWith('src/parse.ts') || rel.endsWith('src/types.ts') || rel.includes('src/testing/');
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
  const m3 = parserOrExempt(rel) ? null : code.match(allowLiteral);
  if (m3) { console.error(`::error file=${rel}::an allow-shaped value ("${m3[1]}") outside the response parser`); failed = true; }
  if (!rel.includes('src/testing/') && testingImport.test(code)) {
    console.error(`::error file=${rel}::imports the shipped testing helpers, which build allow-shaped bodies`);
    failed = true;
  }
  if (rel.endsWith('src/types.ts') && valueExport.test(code)) {
    console.error(`::error file=${rel}::exports a value; types.ts is exempt from rule 3 only because it declares`);
    failed = true;
  }
}
if (failed) process.exit(1);
console.log(`ok: ${files.length} source files, no fail-open paths`);
