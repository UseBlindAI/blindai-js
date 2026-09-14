/**
 * The smallest useful integration: gate one tool call.
 *
 *   npx tsx examples/quickstart.ts
 *
 * Needs BLINDAI_API_KEY and BLINDAI_BASE_URL. There is no production default for the URL on
 * purpose — a client that guesses where to send authorization requests is a client that can be
 * pointed somewhere else.
 */
import { BlindAIClient, AuthError, PresetUnavailableError } from '@blindai/sdk';

const blindai = new BlindAIClient({
  apiKey: process.env.BLINDAI_API_KEY!,
  baseUrl: process.env.BLINDAI_BASE_URL!,
});

async function main(): Promise<void> {
  const decision = await blindai.authorize({
    input_text: 'Look up invoice 4471 for the Contoso account',
    user_id: 'u-1024',
    role: 'user',
    tool: 'crm_lookup',
    preset: 'strict',
  });

  // `blocked` is the enforcement signal. `isThreat` is for reporting: a request can carry detected
  // threats and still be allowed, so gating on isThreat would refuse work the policy permitted.
  if (decision.blocked) {
    console.error(`refused: ${decision.reason ?? 'blocked by policy'}`);
    return;
  }

  console.log(`allowed in ${decision.latencyMs.toFixed(1)}ms under preset ${decision.preset}`);
  if (decision.isThreat) {
    console.warn(`allowed, but flagged: ${decision.threats.map((t) => t.type).join(', ')}`);
  }
}

main().catch((error: unknown) => {
  // Nothing in this SDK returns an allow on failure. Every error path throws, and the decision
  // about what to do when authorization is unavailable is yours to make here, in your own code,
  // where a reviewer can see it.
  if (error instanceof AuthError) {
    console.error('API key rejected:', error.message);
  } else if (error instanceof PresetUnavailableError) {
    console.error('that preset is not running on this deployment:', error.message);
  } else {
    console.error('authorization unavailable:', error);
  }
  process.exitCode = 1;
});
