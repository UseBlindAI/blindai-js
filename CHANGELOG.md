# Changelog

All notable changes to the BlindAI TypeScript SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
