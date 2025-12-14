/**
 * @blindai/sdk - TypeScript SDK for BlindAI
 * 
 * AI Security & Threat Detection for LLM Applications
 * 
 * @example Basic Usage
 * ```typescript
 * import { BlindAI } from '@blindai/sdk';
 * 
 * const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY });
 * 
 * const result = await guard.check('User input to validate');
 * if (result.isThreat) {
 *   console.log('Threat detected:', result.threatLevel);
 * }
 * ```
 * 
 * @example With OpenAI
 * ```typescript
 * import { BlindAI } from '@blindai/sdk';
 * import OpenAI from 'openai';
 * 
 * const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY });
 * const openai = new OpenAI();
 * 
 * async function chat(userMessage: string) {
 *   // Protect user input
 *   const result = await guard.protect({
 *     text: userMessage,
 *     policies: ['prompt-injection', 'pii'],
 *     onViolation: 'block',
 *   });
 *   
 *   // Safe to proceed
 *   return openai.chat.completions.create({
 *     model: 'gpt-4',
 *     messages: [{ role: 'user', content: userMessage }],
 *   });
 * }
 * ```
 * 
 * @packageDocumentation
 */

// =============================================================================
// Type Definitions
// =============================================================================

/**
 * Valid security policies to apply during protection.
 * 
 * @remarks
 * - `pii` - Detect personally identifiable information (SSN, credit cards, etc.)
 * - `prompt-injection` - Detect attempts to override system instructions
 * - `jailbreak` - Detect attempts to bypass safety guidelines
 * - `sql-injection` - Detect SQL injection attacks
 * - `code-injection` - Detect code injection attempts
 * - `xss` - Detect cross-site scripting attempts
 * - `data-exfiltration` - Detect data extraction attempts
 * - `toxicity` - Detect toxic or harmful content
 * - `all` - Enable all policies
 */
export type Policy =
  | 'pii'
  | 'prompt-injection'
  | 'jailbreak'
  | 'sql-injection'
  | 'code-injection'
  | 'xss'
  | 'ssrf'
  | 'data-exfiltration'
  | 'sensitive-topics'
  | 'toxicity'
  | 'bias'
  | 'hallucination'
  | 'off-topic'
  | 'all';

/**
 * Action to take when a security violation is detected.
 * 
 * @remarks
 * - `block` - Reject the request and throw ThreatBlockedError
 * - `warn` - Log a warning but allow the request
 * - `log` - Silently log for monitoring without interruption
 * - `challenge` - Trigger challenge handler for human review
 * - `allow` - Allow despite violation (for testing/debugging)
 */
export type ViolationAction = 'block' | 'warn' | 'log' | 'challenge' | 'allow';

/**
 * Severity level of detected threats.
 */
export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Detection tier mode for performance tuning.
 * 
 * @remarks
 * - `full` - All tiers (Bloom + Aho-Corasick + ML) - most accurate
 * - `fast` - Tier 1-2 only (skip ML) - 10x faster
 * - `tier1` - Bloom filter only
 * - `tier2` - Aho-Corasick only
 * - `tier3` - ML model only
 */
export type TierMode = 'full' | 'fast' | 'tier1' | 'tier2' | 'tier3';

/**
 * Details about a specific detected threat.
 */
export interface ThreatDetail {
  /** Threat type (e.g., 'PROMPT_INJECTION', 'PII_SSN') */
  type: string;
  /** Detection confidence from 0.0 to 1.0 */
  confidence: number;
  /** Severity level of the threat */
  severity: ThreatLevel;
  /** Human-readable description */
  description?: string;
  /** The text that triggered detection */
  matchedText?: string;
  /** Character position where detected */
  position?: number;
  /** Detection tier that caught this (1, 2, or 3) */
  tier?: number;
}

/**
 * Result from a protection check.
 */
export interface ProtectionResult {
  /** Whether any threat was detected */
  isThreat: boolean;
  /** Highest severity level among detected threats */
  threatLevel: ThreatLevel;
  /** Recommended action based on policies */
  finalAction: ViolationAction;
  /** Overall detection confidence from 0.0 to 1.0 */
  confidence: number;
  /** List of specific threats found */
  threatsDetected: ThreatDetail[];
  /** Time taken to process in milliseconds */
  processingTimeMs: number;
  /** Unique request ID for tracing */
  requestId: string;
  /** Additional metadata */
  metadata: Record<string, unknown>;
}

/**
 * Options for the check() method.
 */
export interface CheckOptions {
  /** Session/context ID for multi-turn tracking */
  contextId?: string;
  /** Additional metadata to include */
  metadata?: Record<string, unknown>;
  /** Specific policies to apply */
  policies?: Policy[];
  /** Detection tier mode */
  mode?: TierMode;
  /** Request timeout in milliseconds */
  timeout?: number;
}

/**
 * Options for the protect() method.
 */
export interface ProtectOptions extends CheckOptions {
  /** The text to check for threats */
  text: string;
  /** Action to take when violation detected */
  onViolation?: ViolationAction;
  /** Custom handler for challenge decisions */
  onChallenge?: (result: ProtectionResult) => boolean | Promise<boolean>;
  /** Custom handler called when blocked */
  onBlock?: (result: ProtectionResult) => void | Promise<void>;
}

/**
 * Options for batch checking multiple texts.
 */
export interface BatchCheckOptions extends Omit<CheckOptions, 'contextId'> {
  /** Maximum concurrent requests */
  concurrency?: number;
  /** Continue processing if one fails */
  continueOnError?: boolean;
  /** Progress callback */
  onProgress?: (completed: number, total: number) => void;
}

/**
 * Result from batch checking.
 */
export interface BatchResult {
  /** Total items processed */
  total: number;
  /** Items that passed (no threats) */
  passed: number;
  /** Items that failed (threats detected) */
  failed: number;
  /** Individual results */
  results: Array<{
    index: number;
    text: string;
    result: ProtectionResult;
    error?: Error;
  }>;
  /** Total processing time in milliseconds */
  totalTimeMs: number;
}

/**
 * Configuration options for BlindAI client.
 */
export interface BlindAIConfig {
  /** API key for authentication */
  apiKey: string;
  /** Base URL for the API (default: https://api.blindai.dev) */
  baseUrl?: string;
  /** Default policies to apply */
  defaultPolicies?: Policy[];
  /** Default violation action */
  defaultOnViolation?: ViolationAction;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Maximum retry attempts (default: 3) */
  maxRetries?: number;
  /** Enable debug logging */
  debug?: boolean;
}

// =============================================================================
// Error Classes
// =============================================================================

/**
 * Base error class for BlindAI SDK errors.
 */
export class BlindAIError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly statusCode?: number,
    public readonly requestId?: string,
  ) {
    super(message);
    this.name = 'BlindAIError';
    Object.setPrototypeOf(this, BlindAIError.prototype);
  }
}

/**
 * Error thrown when a threat is detected and action is 'block'.
 */
export class ThreatBlockedError extends BlindAIError {
  constructor(
    message: string,
    public readonly result: ProtectionResult,
  ) {
    super(message, 'THREAT_BLOCKED', 403, result.requestId);
    this.name = 'ThreatBlockedError';
    Object.setPrototypeOf(this, ThreatBlockedError.prototype);
  }

  /** Shorthand for result.threatLevel */
  get threatLevel(): ThreatLevel {
    return this.result.threatLevel;
  }

  /** Shorthand for result.threatsDetected */
  get threats(): ThreatDetail[] {
    return this.result.threatsDetected;
  }
}

/**
 * Error thrown for API communication failures.
 */
export class APIError extends BlindAIError {
  constructor(
    message: string,
    statusCode: number,
    requestId?: string,
    public readonly response?: unknown,
  ) {
    super(message, 'API_ERROR', statusCode, requestId);
    this.name = 'APIError';
    Object.setPrototypeOf(this, APIError.prototype);
  }
}

/**
 * Error thrown when request times out.
 */
export class TimeoutError extends BlindAIError {
  constructor(message: string, requestId?: string) {
    super(message, 'TIMEOUT', 408, requestId);
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/**
 * Error thrown for invalid configuration.
 */
export class ConfigurationError extends BlindAIError {
  constructor(message: string) {
    super(message, 'CONFIGURATION_ERROR');
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/**
 * Error thrown when all retry attempts are exhausted.
 */
export class RetryExhaustedError extends BlindAIError {
  constructor(
    message: string,
    public readonly attempts: number,
    public readonly lastError: Error,
  ) {
    super(message, 'RETRY_EXHAUSTED');
    this.name = 'RetryExhaustedError';
    Object.setPrototypeOf(this, RetryExhaustedError.prototype);
  }
}

// =============================================================================
// HTTP Client
// =============================================================================

interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  body?: unknown;
  timeout?: number;
  signal?: AbortSignal;
}

interface APIResponse<T> {
  data: T;
  requestId: string;
  status: number;
}

class HTTPClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly debug: boolean;

  constructor(config: BlindAIConfig) {
    this.baseUrl = config.baseUrl?.replace(/\/$/, '') ?? 'https://api.blindai.dev';
    this.apiKey = config.apiKey;
    this.timeout = config.timeout ?? 30000;
    this.maxRetries = config.maxRetries ?? 3;
    this.debug = config.debug ?? false;
  }

  async request<T>(options: RequestOptions): Promise<APIResponse<T>> {
    const url = `${this.baseUrl}${options.path}`;
    const timeout = options.timeout ?? this.timeout;

    let lastError: Error | undefined;
    
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        if (this.debug) {
          console.log(`[BlindAI] ${options.method} ${options.path} (attempt ${attempt})`);
        }

        const response = await fetch(url, {
          method: options.method,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.apiKey}`,
            'X-BlindAI-SDK': 'typescript/0.1.0',
            'X-Request-ID': this.generateRequestId(),
          },
          body: options.body ? JSON.stringify(options.body) : undefined,
          signal: options.signal ?? controller.signal,
        });

        clearTimeout(timeoutId);

        const requestId = response.headers.get('X-Request-ID') ?? 'unknown';

        if (!response.ok) {
          const errorBody = await response.text().catch(() => 'Unknown error');
          let errorData: { message?: string; code?: string } = {};
          
          try {
            errorData = JSON.parse(errorBody);
          } catch {
            // Not JSON, use raw text
          }

          throw new APIError(
            errorData.message ?? `API request failed: ${response.status}`,
            response.status,
            requestId,
            errorData,
          );
        }

        const data = await response.json() as T;
        return { data, requestId, status: response.status };

      } catch (error) {
        clearTimeout(timeoutId);

        if (error instanceof Error && error.name === 'AbortError') {
          lastError = new TimeoutError(`Request timed out after ${timeout}ms`);
        } else if (error instanceof APIError) {
          // Don't retry client errors (4xx)
          if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
            throw error;
          }
          lastError = error;
        } else {
          lastError = error instanceof Error ? error : new Error(String(error));
        }

        if (attempt < this.maxRetries) {
          // Exponential backoff with jitter
          const delay = Math.min(1000 * Math.pow(2, attempt - 1) + Math.random() * 1000, 10000);
          if (this.debug) {
            console.log(`[BlindAI] Retry in ${Math.round(delay)}ms...`);
          }
          await this.sleep(delay);
        }
      }
    }

    throw new RetryExhaustedError(
      `Request failed after ${this.maxRetries} attempts`,
      this.maxRetries,
      lastError!,
    );
  }

  private generateRequestId(): string {
    return `ts_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// =============================================================================
// Main BlindAI Client
// =============================================================================

/**
 * BlindAI SDK client for AI security and threat detection.
 * 
 * @example Basic usage
 * ```typescript
 * const guard = new BlindAI({ apiKey: 'your-api-key' });
 * 
 * // Simple check
 * const result = await guard.check('User input');
 * console.log(result.isThreat, result.threatLevel);
 * 
 * // Protect with blocking
 * try {
 *   await guard.protect({
 *     text: userInput,
 *     onViolation: 'block',
 *   });
 *   // Safe to proceed
 * } catch (error) {
 *   if (error instanceof ThreatBlockedError) {
 *     console.log('Blocked:', error.threatLevel);
 *   }
 * }
 * ```
 */
export class BlindAI {
  private readonly client: HTTPClient;
  private readonly config: Required<
    Pick<BlindAIConfig, 'defaultPolicies' | 'defaultOnViolation' | 'timeout' | 'debug'>
  >;

  /**
   * Create a new BlindAI client.
   * 
   * @param config - Configuration options
   * @throws ConfigurationError if apiKey is missing
   * 
   * @example
   * ```typescript
   * const guard = new BlindAI({
   *   apiKey: process.env.BLINDAI_API_KEY,
   *   defaultPolicies: ['pii', 'prompt-injection'],
   *   defaultOnViolation: 'block',
   * });
   * ```
   */
  constructor(config: BlindAIConfig) {
    if (!config.apiKey) {
      throw new ConfigurationError(
        'API key is required. Get one at https://app.blindai.dev/settings/api-keys'
      );
    }

    this.client = new HTTPClient(config);
    this.config = {
      defaultPolicies: config.defaultPolicies ?? ['all'],
      defaultOnViolation: config.defaultOnViolation ?? 'block',
      timeout: config.timeout ?? 30000,
      debug: config.debug ?? false,
    };
  }

  /**
   * Check text for security threats without taking action.
   * 
   * @param text - The text to analyze
   * @param options - Additional options
   * @returns Protection result with threat details
   * 
   * @example
   * ```typescript
   * const result = await guard.check('Hello world');
   * 
   * if (result.isThreat) {
   *   console.log(`Threat: ${result.threatLevel}`);
   *   console.log(`Threats:`, result.threatsDetected);
   * }
   * ```
   */
  async check(text: string, options?: CheckOptions): Promise<ProtectionResult> {
    const response = await this.client.request<{
      is_threat: boolean;
      threat_level: ThreatLevel;
      final_action: ViolationAction;
      confidence: number;
      threats_detected: Array<{
        type: string;
        confidence: number;
        severity: ThreatLevel;
        description?: string;
        matched_text?: string;
        position?: number;
        tier?: number;
      }>;
      processing_time_ms: number;
      metadata: Record<string, unknown>;
    }>({
      method: 'POST',
      path: '/api/v1/check',
      body: {
        text,
        context_id: options?.contextId,
        metadata: options?.metadata,
        policies: options?.policies ?? this.config.defaultPolicies,
        mode: options?.mode ?? 'full',
      },
      timeout: options?.timeout ?? this.config.timeout,
    });

    return this.mapResponse(response.data, response.requestId);
  }

  /**
   * Protect text by checking and optionally blocking threats.
   * 
   * @param options - Protection options including text and violation action
   * @returns Protection result
   * @throws ThreatBlockedError if threat detected and onViolation is 'block'
   * 
   * @example Block threats
   * ```typescript
   * try {
   *   const result = await guard.protect({
   *     text: userInput,
   *     policies: ['prompt-injection', 'pii'],
   *     onViolation: 'block',
   *   });
   *   // Input is safe
   *   processInput(userInput);
   * } catch (error) {
   *   if (error instanceof ThreatBlockedError) {
   *     console.log('Blocked:', error.threats);
   *   }
   * }
   * ```
   * 
   * @example Warn but allow
   * ```typescript
   * const result = await guard.protect({
   *   text: userInput,
   *   onViolation: 'warn',
   * });
   * 
   * if (result.isThreat) {
   *   console.warn('Potential threat detected but allowed');
   * }
   * ```
   */
  async protect(options: ProtectOptions): Promise<ProtectionResult> {
    const result = await this.check(options.text, {
      contextId: options.contextId,
      metadata: options.metadata,
      policies: options.policies,
      mode: options.mode,
      timeout: options.timeout,
    });

    const action = options.onViolation ?? this.config.defaultOnViolation;

    if (result.isThreat) {
      switch (action) {
        case 'block':
          if (options.onBlock) {
            await options.onBlock(result);
          }
          throw new ThreatBlockedError(
            `Threat detected: ${result.threatLevel.toUpperCase()} - ${result.threatsDetected.map(t => t.type).join(', ')}`,
            result,
          );

        case 'challenge':
          if (options.onChallenge) {
            const allowed = await options.onChallenge(result);
            if (!allowed) {
              throw new ThreatBlockedError(
                `Challenge rejected: ${result.threatLevel.toUpperCase()}`,
                result,
              );
            }
          }
          break;

        case 'warn':
          console.warn(
            `[BlindAI] Threat detected: ${result.threatLevel}`,
            result.threatsDetected.map(t => t.type),
          );
          break;

        case 'log':
          if (this.config.debug) {
            console.log('[BlindAI] Threat logged:', result);
          }
          break;

        case 'allow':
          // Do nothing
          break;
      }
    }

    return result;
  }

  /**
   * Check multiple texts in batch.
   * 
   * @param texts - Array of texts to check
   * @param options - Batch options
   * @returns Batch result with individual results
   * 
   * @example
   * ```typescript
   * const batch = await guard.checkBatch(
   *   ['Input 1', 'Input 2', 'Input 3'],
   *   {
   *     concurrency: 3,
   *     onProgress: (done, total) => {
   *       console.log(`Progress: ${done}/${total}`);
   *     },
   *   }
   * );
   * 
   * console.log(`Passed: ${batch.passed}, Failed: ${batch.failed}`);
   * ```
   */
  async checkBatch(texts: string[], options?: BatchCheckOptions): Promise<BatchResult> {
    const startTime = Date.now();
    const concurrency = options?.concurrency ?? 5;
    const continueOnError = options?.continueOnError ?? true;
    
    const results: BatchResult['results'] = [];
    let completed = 0;

    // Process in chunks based on concurrency
    for (let i = 0; i < texts.length; i += concurrency) {
      const chunk = texts.slice(i, i + concurrency);
      const chunkPromises = chunk.map(async (text, chunkIndex) => {
        const index = i + chunkIndex;
        try {
          const result = await this.check(text, {
            policies: options?.policies,
            mode: options?.mode,
            timeout: options?.timeout,
          });
          return { index, text, result };
        } catch (error) {
          if (!continueOnError) throw error;
          return {
            index,
            text,
            result: {
              isThreat: false,
              threatLevel: 'none' as const,
              finalAction: 'allow' as const,
              confidence: 0,
              threatsDetected: [],
              processingTimeMs: 0,
              requestId: 'error',
              metadata: {},
            },
            error: error instanceof Error ? error : new Error(String(error)),
          };
        }
      });

      const chunkResults = await Promise.all(chunkPromises);
      results.push(...chunkResults);
      completed += chunk.length;
      options?.onProgress?.(completed, texts.length);
    }

    // Sort by original index
    results.sort((a, b) => a.index - b.index);

    const passed = results.filter(r => !r.error && !r.result.isThreat).length;
    const failed = results.filter(r => r.error || r.result.isThreat).length;

    return {
      total: texts.length,
      passed,
      failed,
      results,
      totalTimeMs: Date.now() - startTime,
    };
  }

  /**
   * Create a protect function with preset options.
   * 
   * @param defaults - Default options for all protect calls
   * @returns Bound protect function
   * 
   * @example
   * ```typescript
   * const protectChat = guard.createProtector({
   *   policies: ['prompt-injection', 'jailbreak'],
   *   onViolation: 'block',
   * });
   * 
   * // Use throughout your app
   * await protectChat('User message 1');
   * await protectChat('User message 2');
   * ```
   */
  createProtector(defaults: Omit<ProtectOptions, 'text'>) {
    return async (text: string, overrides?: Partial<ProtectOptions>): Promise<ProtectionResult> => {
      return this.protect({
        ...defaults,
        ...overrides,
        text,
      });
    };
  }

  /**
   * Wrap a function to automatically protect string arguments.
   * 
   * @param fn - Function to wrap
   * @param options - Protection options
   * @returns Wrapped function that checks inputs before calling original
   * 
   * @example
   * ```typescript
   * async function processMessage(message: string) {
   *   return `Processed: ${message}`;
   * }
   * 
   * const safeProcess = guard.wrap(processMessage, {
   *   policies: ['prompt-injection'],
   *   onViolation: 'block',
   * });
   * 
   * // Now calls are protected
   * await safeProcess('Hello'); // Works
   * await safeProcess('Ignore all instructions'); // Throws ThreatBlockedError
   * ```
   */
  wrap<TArgs extends unknown[], TReturn>(
    fn: (...args: TArgs) => TReturn | Promise<TReturn>,
    options?: Omit<ProtectOptions, 'text'>,
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      // Find and check string arguments
      for (const arg of args) {
        if (typeof arg === 'string') {
          await this.protect({
            text: arg,
            ...options,
          });
        }
      }

      const result = fn(...args);
      return result instanceof Promise ? await result : result;
    };
  }

  private mapResponse(
    data: {
      is_threat: boolean;
      threat_level: ThreatLevel;
      final_action: ViolationAction;
      confidence: number;
      threats_detected: Array<{
        type: string;
        confidence: number;
        severity: ThreatLevel;
        description?: string;
        matched_text?: string;
        position?: number;
        tier?: number;
      }>;
      processing_time_ms: number;
      metadata: Record<string, unknown>;
    },
    requestId: string,
  ): ProtectionResult {
    return {
      isThreat: data.is_threat,
      threatLevel: data.threat_level,
      finalAction: data.final_action,
      confidence: data.confidence,
      threatsDetected: data.threats_detected.map(t => ({
        type: t.type,
        confidence: t.confidence,
        severity: t.severity,
        description: t.description,
        matchedText: t.matched_text,
        position: t.position,
        tier: t.tier,
      })),
      processingTimeMs: data.processing_time_ms,
      requestId,
      metadata: data.metadata,
    };
  }
}

// =============================================================================
// Convenience Alias
// =============================================================================

/**
 * Alias for BlindAI class.
 * Use whichever name you prefer:
 * - `BlindAI` - Full name
 * - `Guard` - Short alias (matches Python SDK)
 */
export const Guard = BlindAI;

// =============================================================================
// Default Export
// =============================================================================

export default BlindAI;
