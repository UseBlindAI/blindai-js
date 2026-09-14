/**
 * Every public call either makes exactly one request, or raises.
 *
 * The companion to the static no-fail-open check, and it covers what that one structurally cannot.
 * A fabricated allow is a literal a parser can find. These two are not:
 *
 *   - Not asking. A rollout middleware at 10% returns without a request for nine calls in ten.
 *     No permissive literal appears anywhere in it; it simply skips the question.
 *   - Reusing an answer. A client-side verdict cache does make requests, just not for this call.
 *     The verdict it returns was real once, for different input under a policy version that may
 *     since have changed.
 *
 * Both produce a log that is not merely thin but false: it asserts that nothing else happened.
 *
 * The invariant, stated so that a client-side rate limiter still passes — it raises before the
 * transport, which is correct, and "must reach the transport" would wrongly fail it:
 *
 *     On return:  exactly one request was made for this call.
 *     On throw:   zero or one request was made.
 *     Always:     the Decision was built from the body served for THIS request.
 *
 * The last line is what catches a cache. Each response carries a unique nonce; a returned decision
 * must carry that same nonce back in `raw`. A cached verdict returns an earlier one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BlindAIClient } from '../dist/index.js';

let nonceSeq = 0;

/** A transport that counts calls and stamps each response with a nonce unique to that request. */
function countingFetch(bodyFor = () => ({ allowed: true, blocked: false, latency_ms: 1, threats: [] })) {
  const state = { requests: 0, nonces: [] };
  const fetchImpl = async (url, init) => {
    state.requests += 1;
    const nonce = `n-${++nonceSeq}`;
    state.nonces.push(nonce);
    const body = { ...bodyFor(url, init), request_id: nonce };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { state, fetchImpl };
}

function client(fetchImpl, extra = {}) {
  return new BlindAIClient({
    apiKey: 'ba_live_test', baseUrl: 'http://test', maxRetries: 0, fetch: fetchImpl, ...extra,
  });
}

const RAG_BODY = {
  threats_found: false, total_documents: 1, safe_count: 1, unsafe_count: 0, flagged_indices: [],
};

// Each call gets the body ITS endpoint returns. Serving an AuthorizeResponse to `ragScan` makes
// the client throw, correctly — it refuses to infer a RAG result from a shape that isn't one —
// so a stub that does it is testing the stub, not the invariant.
const CALLS = [
  ['authorize', (c) => c.authorize({ input_text: 'hello' }), undefined],
  ['scan', (c) => c.scan({ input_text: 'hello' }), undefined],
  ['ragScan', (c) => c.ragScan({ documents: [{ content: 'hello' }] }), () => RAG_BODY],
];

for (const [name, invoke, bodyFor] of CALLS) {
  test(`${name} makes exactly one request when it returns`, async () => {
    const { state, fetchImpl } = bodyFor ? countingFetch(bodyFor) : countingFetch();
    await invoke(client(fetchImpl));
    assert.equal(state.requests, 1,
      `${name} returned after ${state.requests} requests; a value without a question is a log ` +
      'entry asserting something that never happened');
  });
}

test('authorizeBatch makes exactly one request per item, and no item is answered without one', async () => {
  const { state, fetchImpl } = countingFetch();
  const items = await client(fetchImpl).authorizeBatch([
    { input_text: 'a' }, { input_text: 'b' }, { input_text: 'c' },
  ]);
  assert.equal(state.requests, 3, `three inputs produced ${state.requests} requests`);
  assert.equal(items.length, 3);
  assert.equal(items.filter((i) => i.ok).length, 3, 'every item should carry a real decision');
});

test('a call that throws made at most one request, and returned no value', async () => {
  const state = { requests: 0 };
  const fetchImpl = async () => {
    state.requests += 1;
    return new Response('{"detail":"Invalid or expired API key"}', {
      status: 401, headers: { 'content-type': 'application/json' },
    });
  };
  await assert.rejects(() => client(fetchImpl).authorize({ input_text: 'hello' }));
  assert.ok(state.requests <= 1, `a 401 must not be retried; made ${state.requests} requests`);
});

test('a transport that is never called cannot produce a decision', async () => {
  // The rollout shape: if anything ever short-circuits before the transport, it must raise rather
  // than return. A client that answers without asking is the failure this whole file exists for.
  const fetchImpl = async () => {
    throw new Error('transport unreachable');
  };
  await assert.rejects(
    () => client(fetchImpl).authorize({ input_text: 'hello' }),
    'an unreachable transport must raise, never return a decision');
});

test('the decision is built from the body served for THIS request, not an earlier one', async () => {
  const { state, fetchImpl } = countingFetch();
  const c = client(fetchImpl);

  const first = await c.authorize({ input_text: 'same text every time' });
  const second = await c.authorize({ input_text: 'same text every time' });

  assert.equal(state.requests, 2,
    'identical input must still be asked about; a cached verdict outlives the policy that made it');
  assert.notEqual(state.nonces[0], state.nonces[1], 'the stub should mint a fresh nonce per call');
  assert.equal(first.raw.request_id, state.nonces[0]);
  assert.equal(second.raw.request_id, state.nonces[1],
    'the second decision carried the first response back: an answer was reused');
});
