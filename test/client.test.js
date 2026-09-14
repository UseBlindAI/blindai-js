import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BlindAIClient,
  parseDecision,
  ContractError,
  ApiError,
  AuthError,
  ValidationError,
  PresetUnavailableError,
  TimeoutError,
  TransportError,
} from '../dist/index.js';

const OK = { allowed: true, blocked: false, latency_ms: 3, threats: [] };

function stub(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return handler(calls.length, { url, init });
  };
  return { fetchImpl, calls };
}
function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}
function client(fetchImpl, opts = {}) {
  return new BlindAIClient({
    apiKey: 'ba_live_test',
    baseUrl: 'https://example.invalid',
    fetch: fetchImpl,
    retryBaseMs: 1,
    ...opts,
  });
}

// ---------------------------------------------------------------- the contract

test('throws when neither blocked nor allowed is present', () => {
  assert.throws(() => parseDecision({ latency_ms: 1, threats: [] }), ContractError);
  assert.throws(() => parseDecision({ reason: 'ok' }), ContractError);
  assert.throws(() => parseDecision({}), ContractError);
});

test('throws rather than coercing a non-boolean blocked or allowed', () => {
  for (const body of [
    { blocked: 'false', latency_ms: 1 },
    { blocked: 0, latency_ms: 1 },
    { allowed: 'true', latency_ms: 1 },
    { allowed: 1, latency_ms: 1 },
    { blocked: {}, latency_ms: 1 },
  ]) {
    assert.throws(() => parseDecision(body), ContractError, JSON.stringify(body));
  }
});

test('throws on a non-object body', () => {
  for (const body of [null, undefined, 'allow', 7, true, []]) {
    assert.throws(() => parseDecision(body), ContractError);
  }
});

test('blocked wins when present, else !allowed', () => {
  assert.equal(parseDecision({ blocked: true, allowed: true, threats: [] }).blocked, true);
  assert.equal(parseDecision({ blocked: false, allowed: false, threats: [] }).blocked, false);
  assert.equal(parseDecision({ allowed: false, threats: [] }).blocked, true);
  assert.equal(parseDecision({ allowed: true, threats: [] }).blocked, false);
});

test('action mirrors blocked', () => {
  assert.equal(parseDecision({ blocked: true, threats: [] }).action, 'block');
  assert.equal(parseDecision({ blocked: false, threats: [] }).action, 'allow');
});

test('isThreat is blocked or any threat present', () => {
  const t = [{ type: 'prompt_injection', confidence: 0.4 }];
  assert.equal(parseDecision({ blocked: false, threats: [] }).isThreat, false);
  assert.equal(parseDecision({ blocked: true, threats: [] }).isThreat, true);
  assert.equal(parseDecision({ blocked: false, threats: t }).isThreat, true);
});

test('confidence is the max across threats, 0 when none', () => {
  const d = parseDecision({
    blocked: true,
    threats: [
      { type: 'a', confidence: 0.2 },
      { type: 'b', confidence: 0.91 },
      { type: 'c', confidence: 0.5 },
    ],
  });
  assert.equal(d.confidence, 0.91);
  assert.equal(parseDecision({ blocked: false, threats: [] }).confidence, 0);
});

test('missing threats defaults to an empty list', () => {
  const d = parseDecision({ blocked: false });
  assert.deepEqual(d.threats, []);
  assert.equal(d.confidence, 0);
});

test('malformed threat entries throw', () => {
  assert.throws(() => parseDecision({ blocked: false, threats: 'none' }), ContractError);
  assert.throws(() => parseDecision({ blocked: false, threats: [{ confidence: 1 }] }), ContractError);
  assert.throws(
    () => parseDecision({ blocked: false, threats: [{ type: 'a', confidence: 'high' }] }),
    ContractError,
  );
});

// ------------------------------------------------------------------- transport

test('posts to /v1/authorize with a bearer token', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await client(fetchImpl).authorize({ input_text: 'hello' });
  assert.equal(calls[0].url, 'https://example.invalid/v1/authorize');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers.authorization, 'Bearer ba_live_test');
  assert.deepEqual(JSON.parse(calls[0].init.body), { input_text: 'hello' });
});

test('x-api-key style is supported', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await client(fetchImpl, { authStyle: 'x-api-key' }).authorize({ input_text: 'hi' });
  assert.equal(calls[0].init.headers['x-api-key'], 'ba_live_test');
  assert.equal(calls[0].init.headers.authorization, undefined);
});

test('scan uses /v1/scan with the same models', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await client(fetchImpl).scan({ input_text: 'hello' });
  assert.equal(calls[0].url, 'https://example.invalid/v1/scan');
});

test('sends only the fields given: no metadata, no invented defaults', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await client(fetchImpl).authorize({ input_text: 'x', role: 'guest' });
  const sent = JSON.parse(calls[0].init.body);
  assert.deepEqual(Object.keys(sent).sort(), ['input_text', 'role']);
  assert.equal('metadata' in sent, false);
});

test('baseUrl is required: no production default', () => {
  assert.throws(() => new BlindAIClient({ apiKey: 'k' }), /baseUrl is required/);
});

test('apiKey is required', () => {
  assert.throws(() => new BlindAIClient({ baseUrl: 'https://x.invalid' }), /apiKey is required/);
});

test('input_text is required', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await assert.rejects(() => client(fetchImpl).authorize({}), /input_text is required/);
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: '' }),
    /input_text is required/,
  );
  assert.equal(calls.length, 0, 'must not hit the network');
});

// ---------------------------------------------------------------------- errors

test('401 and 403 raise AuthError and are not retried', async () => {
  for (const status of [401, 403]) {
    const { fetchImpl, calls } = stub(() => jsonResponse(status, { detail: 'nope' }));
    await assert.rejects(() => client(fetchImpl).authorize({ input_text: 'x' }), AuthError);
    assert.equal(calls.length, 1);
  }
});

test('422 message is built from loc and msg, never echoing the body', async () => {
  const secret = 'my-private-prompt-text';
  const body = {
    detail: [
      {
        type: 'string_type',
        loc: ['body', 'input_text'],
        msg: 'Input should be a valid string',
        input: { input_text: secret, user_id: 'u1' },
      },
    ],
  };
  const { fetchImpl } = stub(() => jsonResponse(422, body));
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: 'x' }),
    (err) => {
      assert.ok(err instanceof ValidationError);
      assert.deepEqual(err.fields, ['input_text'], 'leading "body" segment is stripped');
      assert.match(err.message, /input_text: Input should be a valid string/);
      assert.equal(err.message.includes('body.'), false);
      const serialised = `${err.message} ${JSON.stringify(err.fields)} ${err.stack}`;
      assert.equal(serialised.includes(secret), false, 'must not echo the submitted body');
      return true;
    },
  );
});

test('503 surfaces as PresetUnavailableError and is not retried', async () => {
  const { fetchImpl, calls } = stub(() =>
    jsonResponse(503, { detail: 'ANTHROPIC_API_KEY not configured' }),
  );
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: 'x', preset: 'strict' }),
    (err) => {
      assert.ok(err instanceof PresetUnavailableError);
      assert.match(err.message, /ANTHROPIC_API_KEY not configured/);
      assert.match(err.message, /does not downgrade/);
      return true;
    },
  );
  assert.equal(calls.length, 1, '503 must not be retried');
});

test('other 4xx are not retried', async () => {
  for (const status of [400, 404, 409, 418]) {
    const { fetchImpl, calls } = stub(() => jsonResponse(status, { detail: 'x' }));
    await assert.rejects(() => client(fetchImpl).authorize({ input_text: 'x' }), ApiError);
    assert.equal(calls.length, 1, `status ${status} must not be retried`);
  }
});

test('a 404 throws rather than allowing: the old silent-bypass case', async () => {
  const { fetchImpl } = stub(() => jsonResponse(404, { detail: 'Not Found' }));
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: 'x' }),
    (err) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.status, 404);
      return true;
    },
  );
});

// --------------------------------------------------------------------- retries

test('5xx, 408 and 429 are retried', async () => {
  for (const status of [408, 429, 500, 502, 504]) {
    const { fetchImpl, calls } = stub((n) =>
      n === 1 ? jsonResponse(status, {}) : jsonResponse(200, OK),
    );
    const d = await client(fetchImpl).authorize({ input_text: 'x' });
    assert.equal(d.action, 'allow');
    assert.equal(calls.length, 2, `status ${status} should be retried`);
  }
});

test('retries are bounded and then the error surfaces', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(500, {}));
  await assert.rejects(
    () => client(fetchImpl, { maxRetries: 2 }).authorize({ input_text: 'x' }),
    ApiError,
  );
  assert.equal(calls.length, 3);
});

test('transport failures are retried then surface as TransportError', async () => {
  const { fetchImpl, calls } = stub(() => {
    throw new Error('ECONNREFUSED');
  });
  await assert.rejects(
    () => client(fetchImpl, { maxRetries: 1 }).authorize({ input_text: 'x' }),
    TransportError,
  );
  assert.equal(calls.length, 2);
});

test('a timeout surfaces as TimeoutError, never as a decision', async () => {
  const fetchImpl = async (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => {
        const e = new Error('aborted');
        e.name = 'AbortError';
        reject(e);
      });
    });
  await assert.rejects(
    () => client(fetchImpl, { timeoutMs: 10, maxRetries: 0 }).authorize({ input_text: 'x' }),
    TimeoutError,
  );
});

test('non-JSON 2xx body throws rather than allowing', async () => {
  const { fetchImpl } = stub(() => new Response('<html>gateway</html>', { status: 200 }));
  await assert.rejects(
    () => client(fetchImpl, { maxRetries: 0 }).authorize({ input_text: 'x' }),
    TransportError,
  );
});

// ----------------------------------------------------------------------- batch

test('batch reports per-item outcomes and never a collective allow', async () => {
  const { fetchImpl } = stub((n) => {
    if (n === 2) return jsonResponse(500, {});
    if (n === 3) return jsonResponse(200, { blocked: true, allowed: false, threats: [] });
    return jsonResponse(200, OK);
  });
  const c = client(fetchImpl, { maxRetries: 0 });
  const results = await c.authorizeBatch([
    { input_text: 'a' },
    { input_text: 'b' },
    { input_text: 'c' },
  ]);
  assert.equal(results.length, 3);
  const failed = results.filter((r) => !r.ok);
  assert.equal(failed.length, 1);
  assert.equal('finalAction' in results[0], false, 'no collapsed verdict');
  assert.equal(failed[0].ok, false);
  assert.ok(failed[0].error instanceof ApiError);
  // the failed item carries no decision at all, so it cannot read as an allow
  assert.equal('decision' in failed[0], false);
});

test('no option exists to turn an error into an allow', async () => {
  const { fetchImpl } = stub(() => jsonResponse(500, {}));
  const c = client(fetchImpl, { maxRetries: 0 });
  // no such option is part of the API; passing anything changes nothing
  const results = await c.authorizeBatch([{ input_text: 'a' }], { continueOnError: true });
  assert.equal(results[0].ok, false);
  assert.equal(results[0].decision, undefined);
});

test('POWER_USER is passed through untouched, never mapped to admin', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
  await client(fetchImpl).authorize({ input_text: 'x', role: 'POWER_USER' });
  assert.equal(JSON.parse(calls[0].init.body).role, 'POWER_USER');
});

// ------------------------------------------------- contract-doc corrections

test('threatLevel falls back to none with no threats, medium with some', () => {
  assert.equal(parseDecision({ blocked: false, threats: [] }).threatLevel, 'none');
  assert.equal(
    parseDecision({ blocked: false, threats: [{ type: 'a', confidence: 0.3 }] }).threatLevel,
    'medium',
  );
  assert.equal(
    parseDecision({ blocked: true, threat_level: 'critical', threats: [] }).threatLevel,
    'critical',
  );
  // never null: callers can switch on it without a guard
  assert.equal(parseDecision({ blocked: true, threat_level: null, threats: [] }).threatLevel, 'none');
});

test('401 detail string is surfaced in the message', async () => {
  const { fetchImpl } = stub(() =>
    jsonResponse(401, { detail: 'This endpoint requires an API key (ba_live_xxx), not JWT' }),
  );
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: 'x' }),
    /requires an API key/,
  );
});

test('a non-JSON error body does not replace the error', async () => {
  const { fetchImpl } = stub(
    () => new Response('<html>502 Bad Gateway</html>', { status: 502 }),
  );
  await assert.rejects(
    () => client(fetchImpl, { maxRetries: 0 }).authorize({ input_text: 'x' }),
    (err) => {
      assert.ok(err instanceof ApiError);
      assert.equal(err.status, 502);
      return true;
    },
  );
});

test('ragScan posts to /v1/rag/scan and validates the result shape', async () => {
  const body = {
    threats_found: true,
    total_documents: 2,
    safe_count: 1,
    unsafe_count: 1,
    flagged_indices: [1],
  };
  const { fetchImpl, calls } = stub(() => jsonResponse(200, body));
  const r = await client(fetchImpl).ragScan({ documents: [{ content: 'a' }, { content: 'b' }] });
  assert.equal(calls[0].url, 'https://example.invalid/v1/rag/scan');
  assert.deepEqual(r.flagged_indices, [1]);
});

test('ragScan throws on a body with no usable result', async () => {
  const { fetchImpl } = stub(() => jsonResponse(200, { ok: true }));
  await assert.rejects(
    () => client(fetchImpl, { maxRetries: 0 }).ragScan({ documents: [{ content: 'a' }] }),
    /refusing to infer a result/,
  );
});

test('ragScan requires documents and does not hit the network without them', async () => {
  const { fetchImpl, calls } = stub(() => jsonResponse(200, {}));
  await assert.rejects(() => client(fetchImpl).ragScan({}), /documents is required/);
  assert.equal(calls.length, 0);
});

test('viewer and foreign are valid roles and pass through', async () => {
  for (const role of ['admin', 'user', 'viewer', 'guest', 'foreign']) {
    const { fetchImpl, calls } = stub(() => jsonResponse(200, OK));
    await client(fetchImpl).authorize({ input_text: 'x', role });
    assert.equal(JSON.parse(calls[0].init.body).role, role);
  }
});

test('a threat with no severity is preserved, and server confidence is trusted', () => {
  const d = parseDecision({
    blocked: true,
    allowed: false,
    threats: [{ type: 'prompt_injection', confidence: 0.9 }],
  });
  assert.equal(d.threats[0].severity, null);
  assert.equal(d.confidence, 0.9);
});

// -------------------------------------------------------------- testing helpers

test('stubFetch fails an unscripted call instead of inventing a response', async () => {
  const { stubFetch, decision } = await import('../dist/testing.js');
  const { fetch, calls } = stubFetch([decision.allow()]);
  const c = new BlindAIClient({ apiKey: 'ba_live_t', baseUrl: 'https://x.invalid', fetch, maxRetries: 0 });
  const d = await c.authorize({ input_text: 'a' });
  assert.equal(d.action, 'allow');
  await assert.rejects(() => c.authorize({ input_text: 'b' }), /no scripted response/);
  assert.equal(calls.length, 2);
});

test('decision.malformed() makes the client throw, never allow', async () => {
  const { stubFetch, decision } = await import('../dist/testing.js');
  const { fetch } = stubFetch([decision.malformed()]);
  const c = new BlindAIClient({ apiKey: 'ba_live_t', baseUrl: 'https://x.invalid', fetch, maxRetries: 0 });
  await assert.rejects(() => c.authorize({ input_text: 'a' }), ContractError);
});

test('CJS build exposes the same named exports', async () => {
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const cjs = require('../dist/index.cjs');
  assert.equal(typeof cjs.BlindAIClient, 'function');
  assert.equal(typeof cjs.parseDecision, 'function');
  assert.equal(typeof cjs.ContractError, 'function');
});
