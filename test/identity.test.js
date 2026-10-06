import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BlindAIClient, ContractError, IDENTITY_HEADER } from '../dist/index.js';

function recording(body) {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push({ url, init });
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { seen, fetchImpl };
}

const ALLOW = { allowed: true, blocked: false, threats: [] };
const client = (fetchImpl) =>
  new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'http://test', maxRetries: 0, fetch: fetchImpl });

test('a call with a token carries it, and one without carries no identity header', async () => {
  const { seen, fetchImpl } = recording(ALLOW);
  const c = client(fetchImpl);
  await c.authorize({ input_text: 'pay', tool: 'pay' }, { identityToken: 'tok-1' });
  await c.authorize({ input_text: 'hello' });
  assert.equal(seen[0].init.headers[IDENTITY_HEADER], 'tok-1');
  assert.equal(IDENTITY_HEADER in seen[1].init.headers, false);
});

for (const bad of ['', '   ']) {
  test(`an empty token (${JSON.stringify(bad)}) is refused before any request`, async () => {
    const { seen, fetchImpl } = recording(ALLOW);
    await assert.rejects(client(fetchImpl).authorize({ input_text: 'pay' }, { identityToken: bad }));
    assert.equal(seen.length, 0);
  });
}

test('the exchange posts the runtime secret and returns the grant', async () => {
  const { seen, fetchImpl } = recording({ tokens: { 'a-1': 'tok-1' }, expires_in: 14400 });
  const grant = await client(fetchImpl).exchangeTokens('rs_secret', ['a-1']);
  assert.equal(new URL(seen[0].url).pathname, '/v1/cp/tokens');
  assert.deepEqual(JSON.parse(seen[0].init.body), { runtime_secret: 'rs_secret', agent_ids: ['a-1'] });
  assert.deepEqual(grant, { tokens: { 'a-1': 'tok-1' }, expiresIn: 14400 });
});

for (const body of [{}, { tokens: [] }, { tokens: { a: 1 }, expires_in: 1 }, { tokens: {}, expires_in: 'soon' }]) {
  test(`a body that is not a grant is a contract error: ${JSON.stringify(body)}`, async () => {
    const { fetchImpl } = recording(body);
    await assert.rejects(client(fetchImpl).exchangeTokens('rs_secret', ['a-1']), ContractError);
  });
}
