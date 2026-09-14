/**
 * Testing your integration without a server.
 *
 * `stubFetch` fails an unscripted call rather than inventing a response, so a test cannot
 * accidentally receive an allow it never asked for — the same rule the client itself follows.
 */
import { BlindAIClient } from '@blindai/sdk';
import { decision, stubFetch } from '@blindai/sdk/testing';

export function clientThatAllows(): BlindAIClient {
  const { fetch } = stubFetch([decision.allow()]);
  return new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'http://test', fetch });
}

export function clientThatBlocks(): BlindAIClient {
  const { fetch } = stubFetch([decision.block('prompt injection detected')]);
  return new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'http://test', fetch });
}

/** The case worth testing and usually skipped: what your code does when the server is down. */
export function clientThatIsDown(): BlindAIClient {
  const { fetch } = stubFetch([decision.down()]);
  return new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'http://test', fetch });
}

/** And the case that must never silently pass: a response that is not an AuthorizeResponse. */
export function clientThatReturnsNonsense(): BlindAIClient {
  const { fetch } = stubFetch([decision.malformed()]);
  return new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'http://test', fetch });
}
