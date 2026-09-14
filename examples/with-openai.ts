/**
 * Gating a tool call inside an agent loop.
 *
 * The shape that matters: authorize BEFORE the tool runs, and treat a throw as "do not run it".
 * The model proposes; the policy decides; the tool executes only if it was allowed.
 */
import { BlindAIClient } from '@blindai/sdk';

const blindai = new BlindAIClient({
  apiKey: process.env.BLINDAI_API_KEY!,
  baseUrl: process.env.BLINDAI_BASE_URL!,
});

/** A tool call as a model would propose it. */
interface ProposedCall {
  name: string;
  arguments: Record<string, unknown>;
  userMessage: string;
}

export async function runToolIfAllowed(
  call: ProposedCall,
  userId: string,
  execute: (args: Record<string, unknown>) => Promise<string>,
): Promise<string> {
  const decision = await blindai.authorize({
    input_text: call.userMessage,
    user_id: userId,
    tool: call.name,
    parameters: call.arguments,
    session_id: `conversation-${userId}`,
    preset: 'strict',
  });

  if (decision.blocked) {
    // Hand the refusal back to the model as a tool result, so the agent can explain itself rather
    // than retrying blindly.
    return `Refused by policy: ${decision.reason ?? 'not permitted'}`;
  }

  return execute(call.arguments);
}

// If authorization is unreachable this throws, and the call never runs. That is the intended
// behaviour: an agent that proceeds when the policy engine is down is an unprotected agent.
