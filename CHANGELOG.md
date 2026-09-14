# Changelog

All notable changes to the BlindAI TypeScript SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-14

Rewritten against the server's actual wire contract. The previous code in this repository was
never published and should not be used.

### Fixed
- The client posted to `/api/v1/check`, a route that has never existed on the API. It now posts
  `AuthorizeRequest` to `/v1/authorize`.
- The client read `is_threat` and `final_action` from responses — fields the server has never
  sent — so every lookup defaulted permissive and a genuine block parsed as an allow. It now reads
  `blocked`/`allowed` and throws on a response that is not an `AuthorizeResponse`.
- `checkBatch` defaulted `continueOnError` to true and turned any error into
  `{ isThreat: false, finalAction: 'allow' }`. Batch now returns a discriminated
  `{ ok: true, decision } | { ok: false, error }` per item; a failed item carries no decision and
  cannot be misread as an allow.
- A 4xx that cannot succeed is no longer retried. Only 5xx, 408 and 429 are.
- Errors carry the server's own explanation; a 422 names the field that was wrong.

### Changed
- **No error path in this SDK produces an allow.** There is no `continueOnError`, no fail-open
  option, and no collapsed batch verdict. If your application needs a fallback when authorization
  is unavailable, catch the error and make that decision in your own code, where a reviewer can
  see it.
- `baseUrl` is required. There is no production default: a client that guesses where to send
  authorization requests is a client that can be pointed somewhere else.
- Roles are sent in the server's vocabulary (`admin | user | viewer | guest | foreign`, lowercase).
  `POWER_USER` has no server equivalent and is not mapped to anything; the server enforces an
  unrecognised role as `guest`, which is fail-closed.
- `./testing` replaced: a scripted `stubFetch` that fails an unscripted call rather than inventing
  a response, with `decision.allow()`, `.block()`, `.flagged()`, `.malformed()`, `.status()` and
  `.down()`.
- Tests run on `node:test`; the package has no runtime dependencies.

### Security
- Two invariants are required checks on the release workflow, so neither can be skipped for a
  publish. A static check that the client may produce an allow-shaped value in exactly one place,
  the response parser; and a behavioural test that every public call either makes exactly one
  request or raises, with the decision built from the body served for that request, proven by a
  per-response nonce. The second exists because the first structurally cannot see a call that
  never asked or an answer that was reused.
- The release workflow also requires the contract tests to pass against a real deployment. A
  missing secret fails the job rather than skipping it, so nothing is published that has not been
  run against a server at least once.

## [0.1.0] - 2024-12-14

### Added
- **Core Client**
  - `BlindAI` class as primary entry point
  - `check()` method for threat detection
  - `protect()` method with blocking support
  - `checkBatch()` for concurrent batch processing
  - `wrap()` to protect any function
  - `createProtector()` for reusable protection

- **Threat Detection**
  - Prompt injection detection
  - PII detection
  - SQL injection detection
  - XSS detection
  - Jailbreak attempt detection
  - Data exfiltration detection

- **Developer Experience**
  - Full TypeScript support with complete type definitions
  - IDE autocomplete for all options
  - Zero dependencies (native `fetch`)
  - ESM and CommonJS support

- **Resilience**
  - Automatic retry with exponential backoff
  - Configurable timeouts
  - Request abort support

- **Testing Utilities**
  - `MockBlindAI` for unit testing
  - `MockConfig` presets
  - `createTestFixtures()` helper
  - Pattern-based mock responses
  - Call history tracking

- **Error Handling**
  - `ThreatBlockedError` with threat details
  - `APIError` for API failures
  - `TimeoutError` for request timeouts
  - `ConfigurationError` for invalid config
  - `RetryExhaustedError` after max retries

### Security
- API key validation
- SSL/TLS by default
- No sensitive data in error messages

---

[Unreleased]: https://github.com/UseBlindAI/blindai-js/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/UseBlindAI/blindai-js/releases/tag/v0.1.0
