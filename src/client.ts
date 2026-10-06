import {
  ApiError,
  ContractError,
  AuthError,
  BlindAIError,
  PresetUnavailableError,
  TimeoutError,
  TransportError,
  formatValidationError,
} from './errors.js';
import { parseDecision } from './parse.js';
import type {
  AuthorizeRequest,
  CallOptions,
  ClientOptions,
  Decision,
  RAGScanRequest,
  RAGScanResponse,
  TokenGrant,
} from './types.js';
import { IDENTITY_HEADER, TOKENS_PATH } from './wire.js';

const RETRYABLE_STATUSES = new Set([408, 429, 500, 502, 503, 504]);

/**
 * Result of one item in a batch.
 *
 * A batch reports per-item outcomes only. There is no collapsed verdict and no
 * option to convert a failure into an allow. Deciding what to do with a failed
 * item is the caller's call, made visibly in the caller's own code.
 */
export type BatchItem =
  | { ok: true; index: number; decision: Decision }
  | { ok: false; index: number; error: BlindAIError };

export class BlindAIClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseMs: number;
  private readonly authStyle: 'bearer' | 'x-api-key';
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: ClientOptions) {
    if (!options?.apiKey) throw new BlindAIError('apiKey is required');
    if (!options?.baseUrl) {
      throw new BlindAIError(
        'baseUrl is required: point the client at your own deployment explicitly',
      );
    }
    this.apiKey = options.apiKey;
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxRetries = options.maxRetries ?? 2;
    this.retryBaseMs = options.retryBaseMs ?? 200;
    this.authStyle = options.authStyle ?? 'bearer';
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== 'function') {
      throw new BlindAIError('No fetch implementation available; pass options.fetch');
    }
    this.fetchImpl = f;
  }

  /**
   * POST /v1/authorize
   *
   * `options.identityToken`: the agent's token from {@link exchangeTokens}. A tool call needs one on
   * a deployment whose control plane is on; without it the call is refused `identity_token_required`.
   */
  authorize(request: AuthorizeRequest, options: CallOptions = {}): Promise<Decision> {
    return this.post('/v1/authorize', request, options);
  }

  /** POST /v1/scan — identical models to /v1/authorize. */
  scan(request: AuthorizeRequest, options: CallOptions = {}): Promise<Decision> {
    return this.post('/v1/scan', request, options);
  }

  /**
   * POST /v1/cp/tokens: a runtime's secret for its agents' identity tokens.
   *
   * Exactly one request, or a throw. An agent id the runtime does not own, or that is not active,
   * is absent from the grant rather than an error (the server's rule: no probing for agents).
   */
  async exchangeTokens(runtimeSecret: string, agentIds: string[]): Promise<TokenGrant> {
    if (!runtimeSecret) throw new BlindAIError('runtimeSecret is required');
    const body = await this.sendJson(
      TOKENS_PATH,
      JSON.stringify({ runtime_secret: runtimeSecret, agent_ids: agentIds }),
    );
    return parseTokenGrant(body);
  }

  /**
   * POST /v1/rag/scan
   *
   * Different models from authorize: this returns document counts and flagged
   * indices, not a decision. It still throws on any failure.
   */
  async ragScan(request: RAGScanRequest): Promise<RAGScanResponse> {
    if (!request || !Array.isArray(request.documents)) {
      throw new BlindAIError('documents is required and must be an array');
    }
    const body = await this.sendJson('/v1/rag/scan', JSON.stringify(request));
    const b = body as Record<string, unknown>;
    if (typeof b?.threats_found !== 'boolean' || !Array.isArray(b?.flagged_indices)) {
      throw new ContractError(
        'Response did not carry threats_found and flagged_indices; refusing to infer a result',
      );
    }
    return b as unknown as RAGScanResponse;
  }

  /**
   * Authorize several inputs.
   *
   * Every item is reported on its own terms: a decision or an error. Failures
   * stay failures. If you want the batch to stop at the first error, check
   * `ok` as you iterate; nothing here decides that for you.
   */
  async authorizeBatch(requests: AuthorizeRequest[]): Promise<BatchItem[]> {
    return Promise.all(
      requests.map(async (request, index): Promise<BatchItem> => {
        try {
          return { ok: true, index, decision: await this.authorize(request) };
        } catch (err) {
          return {
            ok: false,
            index,
            error: err instanceof BlindAIError ? err : new TransportError(String(err), err),
          };
        }
      }),
    );
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    const h: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
    };
    if (this.authStyle === 'bearer') h.authorization = `Bearer ${this.apiKey}`;
    else h['x-api-key'] = this.apiKey;
    return { ...h, ...extra };
  }

  private async post(path: string, body: AuthorizeRequest, options: CallOptions): Promise<Decision> {
    if (!body || typeof body.input_text !== 'string' || body.input_text.length === 0) {
      throw new BlindAIError('input_text is required and must be a non-empty string');
    }
    return parseDecision(await this.sendJson(path, JSON.stringify(body), identity(options)));
  }

  /** POST with retry. Retries transport failures, 5xx, 408 and 429 only. */
  private async sendJson(
    path: string,
    payload: string,
    extra: Record<string, string> = {},
  ): Promise<unknown> {
    const url = `${this.baseUrl}${path}`;
    let lastError: BlindAIError | undefined;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) await sleep(this.retryBaseMs * 2 ** (attempt - 1));
      try {
        return await this.send(url, payload, extra);
      } catch (err) {
        const e = err instanceof BlindAIError ? err : new TransportError(String(err), err);
        const retryable = e instanceof TransportError || (e instanceof ApiError && e.retryable);
        if (!retryable || attempt === this.maxRetries) throw e;
        lastError = e;
      }
    }
    /* c8 ignore next */
    throw lastError ?? new TransportError('Request failed');
  }

  private async send(url: string, payload: string, extra: Record<string, string>): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method: 'POST',
        headers: this.headers(extra),
        body: payload,
        signal: controller.signal,
      });
    } catch (err) {
      if ((err as { name?: string })?.name === 'AbortError') {
        throw new TimeoutError(`Request to ${url} timed out after ${this.timeoutMs}ms`, err);
      }
      const why = err instanceof Error && err.message ? `: ${err.message}` : '';
      throw new TransportError(`Request to ${url} failed${why}`, err);
    } finally {
      clearTimeout(timer);
    }

    if (response.ok) return await this.json(response, url);

    const status = response.status;
    if (status === 401 || status === 403) {
      // detail is a plain string here, e.g. "Invalid or expired API key" or
      // "This endpoint requires an API key (ba_live_xxx), not JWT".
      const detail = await this.detailText(response);
      throw new AuthError(
        detail ? `Authentication failed (${status}): ${detail}` : `Authentication failed (${status}) for ${url}`,
        status,
      );
    }
    if (status === 422) {
      // Built from loc and msg only: `input` echoes the submitted body.
      throw formatValidationError(await this.jsonOrNull(response));
    }
    if (status === 503) {
      const detail = await this.detailText(response);
      throw new PresetUnavailableError(
        detail
          ? `Service unavailable (503): ${detail}. A preset may require server-side configuration; the server does not downgrade it.`
          : 'Service unavailable (503). A preset may require server-side configuration; the server does not downgrade it.',
      );
    }
    const detail = await this.detailText(response);
    throw new ApiError(
      detail
        ? `Request to ${url} failed with ${status}: ${detail}`
        : `Request to ${url} failed with ${status}`,
      status,
      RETRYABLE_STATUSES.has(status),
    );
  }

  private async json(response: Response, url: string): Promise<unknown> {
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (err) {
      throw new TransportError(`Response from ${url} was not valid JSON`, err);
    }
  }

  private async jsonOrNull(response: Response): Promise<unknown> {
    try {
      return JSON.parse(await response.text());
    } catch {
      return null;
    }
  }

  private async detailText(response: Response): Promise<string | null> {
    const body = await this.jsonOrNull(response);
    const detail = (body as { detail?: unknown } | null)?.detail;
    return typeof detail === 'string' ? detail : null;
  }
}

/** The identity header, only when a token is held: never sent empty (wire-constants.json). */
function identity(options: CallOptions): Record<string, string> {
  const token = options.identityToken;
  if (token === undefined || token === null) return {};
  if (typeof token !== 'string' || token.trim() === '') {
    throw new BlindAIError('identityToken must be a non-empty string, or omitted');
  }
  return { [IDENTITY_HEADER]: token };
}

function parseTokenGrant(body: unknown): TokenGrant {
  const b = body as { tokens?: unknown; expires_in?: unknown } | null;
  if (!b || typeof b.tokens !== 'object' || b.tokens === null || Array.isArray(b.tokens)) {
    throw new ContractError("not a token grant: missing 'tokens'");
  }
  const tokens = b.tokens as Record<string, unknown>;
  if (!Object.values(tokens).every((v) => typeof v === 'string')) {
    throw new ContractError("not a token grant: 'tokens' must map agent ids to strings");
  }
  if (typeof b.expires_in !== 'number' || !Number.isInteger(b.expires_in)) {
    throw new ContractError("not a token grant: 'expires_in' is not an integer");
  }
  return { tokens: { ...(tokens as Record<string, string>) }, expiresIn: b.expires_in };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
