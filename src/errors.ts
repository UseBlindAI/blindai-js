/**
 * Errors are thrown, never turned into a decision.
 *
 * There is no code path in this SDK that converts a failure into an allow.
 * If you need a fallback, catch the error and make that choice explicitly in
 * your own code, where it is visible in review.
 */

export class BlindAIError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The request never completed: network failure, abort, timeout. */
export class TransportError extends BlindAIError {
  readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

/** The request timed out. */
export class TimeoutError extends TransportError {}

/** Non-2xx response. */
export class ApiError extends BlindAIError {
  readonly status: number;
  readonly retryable: boolean;
  constructor(message: string, status: number, retryable: boolean) {
    super(message);
    this.status = status;
    this.retryable = retryable;
  }
}

/** 401 / 403. */
export class AuthError extends ApiError {
  constructor(message: string, status: number) {
    super(message, status, false);
  }
}

/**
 * 422 from FastAPI validation.
 *
 * A 422 `detail` entry carries an `input` field that echoes the submitted
 * body, which on a real call contains the caller's `input_text`. Messages are
 * built from `loc` and `msg` only, with the leading "body" segment of `loc`
 * stripped: it names where the field lives, which the caller already knows.
 * `input` is never read, stored or logged.
 */
export class ValidationError extends ApiError {
  readonly fields: string[];
  constructor(message: string, fields: string[]) {
    super(message, 422, false);
    this.fields = fields;
  }
}

/**
 * 503 from a preset whose server-side dependency is unavailable
 * (for example a preset requiring ANTHROPIC_API_KEY).
 *
 * Surfaced rather than retried: retrying will not provision the key, and the
 * server does not downgrade the preset.
 */
export class PresetUnavailableError extends ApiError {
  constructor(message: string) {
    super(message, 503, false);
  }
}

/**
 * The response did not carry a usable decision.
 *
 * Thrown when neither `blocked` nor `allowed` is present, or when either is
 * present but is not a boolean. This is the rule that makes contract drift
 * loud instead of a silent bypass.
 */
export class ContractError extends BlindAIError {}

interface ValidationDetailEntry {
  loc?: unknown;
  msg?: unknown;
}

/** Build a 422 message from `loc` and `msg` only. */
export function formatValidationError(body: unknown): ValidationError {
  const detail = (body as { detail?: unknown } | null)?.detail;
  const fields: string[] = [];
  const parts: string[] = [];

  if (Array.isArray(detail)) {
    for (const entry of detail as ValidationDetailEntry[]) {
      if (!entry || typeof entry !== 'object') continue;
      const segments = Array.isArray(entry.loc)
        ? entry.loc.filter((p) => typeof p === 'string' || typeof p === 'number')
        : [];
      if (segments[0] === 'body') segments.shift();
      const loc = segments.length ? segments.join('.') : undefined;
      const msg = typeof entry.msg === 'string' ? entry.msg : undefined;
      if (loc) fields.push(loc);
      if (loc && msg) parts.push(`${loc}: ${msg}`);
      else if (msg) parts.push(msg);
      else if (loc) parts.push(loc);
    }
  }

  const summary = parts.length
    ? `Request validation failed (${parts.join('; ')})`
    : 'Request validation failed';
  return new ValidationError(summary, fields);
}
