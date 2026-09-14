import { ContractError } from './errors.js';
import type { AuthorizeResponse, Decision, ThreatDetail } from './types.js';

/**
 * Parse a 2xx body into a Decision.
 *
 * The contract, in order:
 *   1. If the body has neither `blocked` nor `allowed`, throw.
 *   2. If either is present but is not a boolean, throw rather than coerce.
 *   3. `blocked` wins when present, else `!allowed`.
 *   4. isThreat = blocked || threats.length > 0
 *   5. confidence = max across threats, 0 when there are none.
 *   6. threat_level falls back to "none" with no threats, "medium" with some.
 *
 * There is no branch here that returns an allow on malformed input.
 */
export function parseDecision(body: unknown): Decision {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ContractError(
      `Response body is not an object (got ${describe(body)}); refusing to infer a decision`,
    );
  }

  const obj = body as Record<string, unknown>;
  const hasBlocked = Object.prototype.hasOwnProperty.call(obj, 'blocked') && obj.blocked !== null;
  const hasAllowed = Object.prototype.hasOwnProperty.call(obj, 'allowed') && obj.allowed !== null;

  if (!hasBlocked && !hasAllowed) {
    throw new ContractError(
      'Response carried neither "blocked" nor "allowed"; refusing to infer a decision',
    );
  }
  if (hasBlocked && typeof obj.blocked !== 'boolean') {
    throw new ContractError(
      `Response field "blocked" is ${describe(obj.blocked)}, not a boolean; refusing to coerce`,
    );
  }
  if (hasAllowed && typeof obj.allowed !== 'boolean') {
    throw new ContractError(
      `Response field "allowed" is ${describe(obj.allowed)}, not a boolean; refusing to coerce`,
    );
  }

  const blocked = hasBlocked ? (obj.blocked as boolean) : !(obj.allowed as boolean);
  const threats = parseThreats(obj.threats);
  const confidence = threats.length ? Math.max(...threats.map((t) => t.confidence)) : 0;

  return {
    blocked,
    action: blocked ? 'block' : 'allow',
    isThreat: blocked || threats.length > 0,
    confidence,
    threats,
    threatLevel:
      typeof obj.threat_level === 'string' && obj.threat_level.length > 0
        ? obj.threat_level
        : threats.length > 0
          ? 'medium'
          : 'none',
    reason: typeof obj.reason === 'string' ? obj.reason : null,
    latencyMs: typeof obj.latency_ms === 'number' ? obj.latency_ms : 0,
    preset: typeof obj.preset === 'string' ? obj.preset : null,
    raw: obj as unknown as AuthorizeResponse,
  };
}

function parseThreats(value: unknown): ThreatDetail[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new ContractError(
      `Response field "threats" is ${describe(value)}, not an array; refusing to coerce`,
    );
  }
  return value.map((entry, i) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new ContractError(`threats[${i}] is ${describe(entry)}, not an object`);
    }
    const t = entry as Record<string, unknown>;
    if (typeof t.type !== 'string') {
      throw new ContractError(`threats[${i}].type is ${describe(t.type)}, not a string`);
    }
    if (typeof t.confidence !== 'number' || Number.isNaN(t.confidence)) {
      throw new ContractError(
        `threats[${i}].confidence is ${describe(t.confidence)}, not a number`,
      );
    }
    return {
      type: t.type,
      confidence: t.confidence,
      severity: typeof t.severity === 'string' ? t.severity : null,
    };
  });
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'an array';
  return `of type ${typeof v}`;
}
