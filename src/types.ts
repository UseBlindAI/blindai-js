/**
 * Wire types for POST /v1/authorize and POST /v1/scan.
 *
 * These mirror the server models exactly. Do not add fields that the server
 * does not accept: there is no `metadata` field on the request.
 */

/**
 * Roles the server recognises. Lowercase on the wire.
 *
 * Anything the server does not recognise is enforced as `guest` (no
 * permissions), which is fail-closed and deliberate. In particular the Python
 * SDK's POWER_USER has no server equivalent and is sent as the literal
 * "power_user"; do not map it to `admin`.
 */
export type Role = 'admin' | 'user' | 'viewer' | 'guest' | 'foreign';

/**
 * Presets the server recognises.
 *
 * Note: presets that require an ANTHROPIC_API_KEY on the server answer 503
 * rather than silently downgrading. That 503 is surfaced, not retried.
 */
export type Preset = 'strict' | 'balanced' | 'permissive';

export interface AuthorizeRequest {
  /** The only required field. */
  input_text: string;
  /** Server default: "anonymous". */
  user_id?: string;
  /** Server default: "query". */
  action?: string;
  agent_id?: string | null;
  /** Server default: "user". Lowercase. See {@link Role}. */
  role?: Role | string;
  tool?: string | null;
  /** Server default: "balanced". */
  preset?: Preset | string;
  session_id?: string | null;
  parameters?: Record<string, unknown>;
  /** Control plane only. */
  target_space_id?: string | null;
}

export interface ThreatDetail {
  type: string;
  confidence: number;
  severity?: string | null;
}

export interface AuthorizeResponse {
  allowed: boolean;
  blocked: boolean;
  latency_ms: number;
  reason?: string | null;
  threat_level?: string | null;
  /** Defaults to [] server-side. */
  threats: ThreatDetail[];
  preset?: Preset | string | null;
}

/**
 * The normalised decision the SDK hands back.
 *
 * `action` is derived, never read from an `action` field on the response:
 * `blocked` wins when present, else `!allowed`.
 */
export interface Decision {
  /** true when the call must not proceed. */
  blocked: boolean;
  action: 'allow' | 'block';
  /** blocked || threats.length > 0 */
  isThreat: boolean;
  /** Max confidence across threats; 0 when there are none. */
  confidence: number;
  threats: ThreatDetail[];
  /** Never null: "none" with no threats, the server's value, else "medium". */
  threatLevel: string;
  reason: string | null;
  latencyMs: number;
  preset: string | null;
  /** The unmodified parsed body, for callers that need more. */
  raw: AuthorizeResponse;
}

export interface ClientOptions {
  apiKey: string;
  /** No production default. The caller states where to send decisions. */
  baseUrl: string;
  /** Per-request timeout in ms. Default 10_000. */
  timeoutMs?: number;
  /** Retries for 5xx, 408 and 429 only. Default 2. */
  maxRetries?: number;
  /** Base delay for exponential backoff in ms. Default 200. */
  retryBaseMs?: number;
  /** 'bearer' (default) or 'x-api-key'. Both are accepted by the server. */
  authStyle?: 'bearer' | 'x-api-key';
  fetch?: typeof globalThis.fetch;
}

/** POST /v1/rag/scan */
export interface RAGDocument {
  content: string;
  metadata?: Record<string, unknown> | null;
}

export interface RAGScanRequest {
  documents: RAGDocument[];
  threshold?: number | null;
}

export interface RAGScanResponse {
  threats_found: boolean;
  total_documents: number;
  safe_count: number;
  unsafe_count: number;
  flagged_indices: number[];
}
