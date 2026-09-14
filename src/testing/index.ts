/**
 * Test helpers for callers of @blindai/sdk.
 *
 * Replaces the old-API helpers. Nothing here can produce an allow on error:
 * a stub either returns a decision body or fails the request.
 *
 *   import { stubFetch, decision } from '@blindai/sdk/testing';
 *
 *   const { fetch, calls } = stubFetch([decision.allow(), decision.block('policy')]);
 *   const client = new BlindAIClient({ apiKey: 'ba_live_test', baseUrl: 'https://x.invalid', fetch });
 */

import type { AuthorizeResponse, ThreatDetail } from '../types.js';

export interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

/** One scripted response: a decision body, a raw status, or a thrown error. */
export type Scripted =
  | { status?: 200; body: AuthorizeResponse | Record<string, unknown> }
  | { status: number; body?: unknown }
  | { throw: Error };

export const decision = {
  allow(overrides: Partial<AuthorizeResponse> = {}): { body: AuthorizeResponse } {
    return { body: { allowed: true, blocked: false, latency_ms: 1, threats: [], ...overrides } };
  },
  block(reason = 'blocked by policy', threats: ThreatDetail[] = []): { body: AuthorizeResponse } {
    return { body: { allowed: false, blocked: true, latency_ms: 1, reason, threats } };
  },
  flagged(threats: ThreatDetail[]): { body: AuthorizeResponse } {
    return { body: { allowed: true, blocked: false, latency_ms: 1, threats } };
  },
  /** A body with no verdict at all. The client must throw on this. */
  malformed(): { body: Record<string, unknown> } {
    return { body: { latency_ms: 1 } };
  },
  status(status: number, detail?: unknown): { status: number; body?: unknown } {
    return { status, body: detail === undefined ? undefined : { detail } };
  },
  down(message = 'ECONNREFUSED'): { throw: Error } {
    return { throw: new Error(message) };
  },
};

/**
 * A fetch implementation that plays back `script` in order and records every
 * call. Once the script is exhausted it fails the request rather than
 * inventing a response, so an unscripted call can never read as an allow.
 */
export function stubFetch(script: Scripted[]): {
  fetch: typeof globalThis.fetch;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const queue = [...script];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers: Record<string, string> = {};
    const h = init?.headers;
    if (h) {
      if (h instanceof Headers) h.forEach((v, k) => (headers[k] = v));
      else if (Array.isArray(h)) for (const [k, v] of h) headers[k] = v;
      else Object.assign(headers, h as Record<string, string>);
    }
    let body: unknown = undefined;
    if (typeof init?.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    calls.push({ url, method: init?.method ?? 'GET', headers, body });

    const next = queue.shift();
    if (!next) throw new Error(`stubFetch: no scripted response for call ${calls.length} (${url})`);
    if ('throw' in next) throw next.throw;
    const status = next.status ?? 200;
    return new Response(next.body === undefined ? null : JSON.stringify(next.body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { fetch, calls };
}
