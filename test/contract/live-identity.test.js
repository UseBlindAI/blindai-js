/**
 * The P1 journey's calls, through this client, against a real control plane (BlindAI pilot S).
 * Run against a stack seeded by BlindAI's scripts/pilot_stack.py, which prints the variables below.
 * Skipped when BLINDAI_RUNTIME_SECRET is unset: these need a control plane.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BlindAIClient } from '../../dist/index.js';

const { BLINDAI_BASE_URL: BASE, BLINDAI_API_KEY: KEY, BLINDAI_RUNTIME_SECRET: SECRET, BLINDAI_AGENT_ID: AGENT } = process.env;
const skip = !(BASE && KEY && SECRET && AGENT) && 'needs a seeded control plane (BLINDAI_RUNTIME_SECRET)';

async function agent() {
  const client = new BlindAIClient({ apiKey: KEY, baseUrl: BASE });
  const grant = await client.exchangeTokens(SECRET, [AGENT]);
  assert.ok(grant.tokens[AGENT], "the runtime's own active agent was not granted a token");
  return { client, token: grant.tokens[AGENT] };
}

const order = (client, token, amount) =>
  client.authorize(
    { input_text: 'place the order', tool: 'purchase.order', action: 'run', parameters: { amount, supplier: 'Acier SA' } },
    token ? { identityToken: token } : {},
  );

test('an order under the threshold is allowed', { skip }, async () => {
  const { client, token } = await agent();
  assert.equal((await order(client, token, 250)).blocked, false);
});

test('an order over the threshold is refused by the rule', { skip }, async () => {
  const { client, token } = await agent();
  const d = await order(client, token, 5000);
  assert.equal(d.blocked, true);
  assert.equal(d.reason, 'Orders over 1000 need a human.');
});

test('a tool call without the token is refused', { skip }, async () => {
  const { client } = await agent();
  const d = await order(client, null, 250);
  assert.equal(d.blocked, true);
  assert.equal(d.reason, 'identity_token_required');
});
