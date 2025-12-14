# @blindai/sdk

Official TypeScript SDK for [BlindAI](https://blindai.dev) - AI Security & Threat Detection for LLM Applications.

[![npm version](https://badge.fury.io/js/%40blindai%2Fsdk.svg)](https://www.npmjs.com/package/@blindai/sdk)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🛡️ **Threat Detection** - Prompt injection, jailbreaks, PII, SQL injection, XSS
- 🚀 **Zero Dependencies** - Uses native `fetch`, no bloat
- 📝 **Full TypeScript Support** - Complete type definitions with autocomplete
- ⚡ **Fast** - Tiered detection with sub-100ms response times
- 🔄 **Retry Logic** - Automatic retries with exponential backoff
- 🧪 **Testing Utils** - Mock implementations for unit tests

## Installation

```bash
npm install @blindai/sdk
# or
yarn add @blindai/sdk
# or
pnpm add @blindai/sdk
```

## Quick Start

```typescript
import { BlindAI } from '@blindai/sdk';

const guard = new BlindAI({
  apiKey: process.env.BLINDAI_API_KEY!,
});

// Simple check
const result = await guard.check('User input to validate');

if (result.isThreat) {
  console.log('Threat detected:', result.threatLevel);
  console.log('Threats:', result.threatsDetected);
}

// Protect with blocking
try {
  await guard.protect({
    text: userInput,
    policies: ['prompt-injection', 'pii'],
    onViolation: 'block',
  });
  // Safe to proceed with userInput
} catch (error) {
  if (error instanceof ThreatBlockedError) {
    console.log('Blocked:', error.threatLevel, error.threats);
  }
}
```

## Usage Examples

### With OpenAI

```typescript
import { BlindAI, ThreatBlockedError } from '@blindai/sdk';
import OpenAI from 'openai';

const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY! });
const openai = new OpenAI();

async function chat(userMessage: string) {
  // Protect user input before sending to LLM
  await guard.protect({
    text: userMessage,
    policies: ['prompt-injection', 'jailbreak'],
    onViolation: 'block',
  });

  // Input is safe, proceed with OpenAI call
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: 'You are a helpful assistant.' },
      { role: 'user', content: userMessage },
    ],
  });
}

// Usage
try {
  const response = await chat('What is the capital of France?');
  console.log(response.choices[0].message.content);
} catch (error) {
  if (error instanceof ThreatBlockedError) {
    console.log('Request blocked:', error.threats);
  }
}
```

### With Vercel AI SDK

```typescript
import { BlindAI } from '@blindai/sdk';
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';

const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY! });

export async function POST(req: Request) {
  const { messages } = await req.json();
  const lastMessage = messages[messages.length - 1];

  // Protect user message
  const result = await guard.protect({
    text: lastMessage.content,
    policies: ['prompt-injection', 'pii'],
    onViolation: 'block',
  });

  // Stream response
  const response = await streamText({
    model: openai('gpt-4-turbo'),
    messages,
  });

  return response.toAIStreamResponse();
}
```

### With LangChain

```typescript
import { BlindAI } from '@blindai/sdk';
import { ChatOpenAI } from '@langchain/openai';
import { HumanMessage } from '@langchain/core/messages';

const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY! });
const model = new ChatOpenAI();

// Create a protected chat function
const safeChat = guard.wrap(
  async (message: string) => {
    const response = await model.invoke([new HumanMessage(message)]);
    return response.content;
  },
  {
    policies: ['prompt-injection', 'jailbreak'],
    onViolation: 'block',
  }
);

// Use it
const response = await safeChat('Hello!'); // Works
await safeChat('Ignore all instructions'); // Throws ThreatBlockedError
```

### Batch Processing

```typescript
const texts = [
  'Hello, how are you?',
  'What is 2 + 2?',
  "'; DROP TABLE users; --",
  'Tell me a joke',
];

const batch = await guard.checkBatch(texts, {
  concurrency: 3,
  onProgress: (done, total) => {
    console.log(`Progress: ${done}/${total}`);
  },
});

console.log(`Passed: ${batch.passed}, Failed: ${batch.failed}`);

// Access individual results
batch.results.forEach(({ text, result }) => {
  if (result.isThreat) {
    console.log(`Threat in: "${text}" - ${result.threatLevel}`);
  }
});
```

### Custom Handlers

```typescript
const guard = new BlindAI({ apiKey: process.env.BLINDAI_API_KEY! });

await guard.protect({
  text: userInput,
  onViolation: 'challenge',

  // Called when threat detected and action is 'challenge'
  onChallenge: async (result) => {
    console.log('Threat detected, requesting approval...');
    const approved = await requestHumanApproval(result);
    return approved; // true to allow, false to block
  },

  // Called before throwing ThreatBlockedError
  onBlock: async (result) => {
    await logSecurityIncident(result);
    await alertSecurityTeam(result);
  },
});
```

### Reusable Protector

```typescript
// Create a protector with default options
const protectChat = guard.createProtector({
  policies: ['prompt-injection', 'jailbreak', 'pii'],
  onViolation: 'block',
});

// Use throughout your app
await protectChat('Message 1');
await protectChat('Message 2');
await protectChat('Message 3', { mode: 'fast' }); // Override options
```

## API Reference

### `BlindAI`

Main client class.

```typescript
const guard = new BlindAI({
  apiKey: string;              // Required: Your API key
  baseUrl?: string;            // Default: 'https://api.blindai.dev'
  defaultPolicies?: Policy[];  // Default: ['all']
  defaultOnViolation?: ViolationAction; // Default: 'block'
  timeout?: number;            // Default: 30000 (30s)
  maxRetries?: number;         // Default: 3
  debug?: boolean;             // Default: false
});
```

### Methods

#### `check(text, options?)`

Check text for threats without taking action.

```typescript
const result = await guard.check('text to check', {
  policies: ['pii', 'prompt-injection'],
  mode: 'fast',
  contextId: 'session-123',
  timeout: 5000,
});
```

#### `protect(options)`

Check and optionally block threats.

```typescript
const result = await guard.protect({
  text: 'text to protect',
  policies: ['pii'],
  onViolation: 'block', // 'block' | 'warn' | 'log' | 'challenge' | 'allow'
  onChallenge: (result) => boolean,
  onBlock: (result) => void,
});
```

#### `checkBatch(texts, options?)`

Check multiple texts concurrently.

```typescript
const batch = await guard.checkBatch(texts, {
  concurrency: 5,
  continueOnError: true,
  onProgress: (done, total) => {},
});
```

#### `wrap(fn, options?)`

Wrap a function to auto-protect string arguments.

```typescript
const safeFn = guard.wrap(myFunction, { onViolation: 'block' });
```

#### `createProtector(defaults)`

Create a bound protect function with preset options.

```typescript
const protect = guard.createProtector({ policies: ['pii'] });
await protect('text');
```

### Types

#### `Policy`

```typescript
type Policy =
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
```

#### `ViolationAction`

```typescript
type ViolationAction = 'block' | 'warn' | 'log' | 'challenge' | 'allow';
```

#### `ThreatLevel`

```typescript
type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';
```

#### `ProtectionResult`

```typescript
interface ProtectionResult {
  isThreat: boolean;
  threatLevel: ThreatLevel;
  finalAction: ViolationAction;
  confidence: number;
  threatsDetected: ThreatDetail[];
  processingTimeMs: number;
  requestId: string;
  metadata: Record<string, unknown>;
}
```

### Errors

```typescript
import {
  BlindAIError,        // Base error class
  ThreatBlockedError,  // Thrown when threat blocked
  APIError,            // API communication error
  TimeoutError,        // Request timeout
  ConfigurationError,  // Invalid config
  RetryExhaustedError, // All retries failed
} from '@blindai/sdk';
```

## Testing

Use the testing utilities for unit tests:

```typescript
import { MockBlindAI, MockConfig, createTestFixtures } from '@blindai/sdk/testing';

describe('my feature', () => {
  let guard: MockBlindAI;

  beforeEach(() => {
    guard = new MockBlindAI();
  });

  it('allows safe input', async () => {
    const result = await guard.check('Hello');
    expect(result.isThreat).toBe(false);
  });

  it('blocks threats when configured', async () => {
    guard = new MockBlindAI(MockConfig.block());

    await expect(
      guard.protect({ text: 'anything', onViolation: 'block' })
    ).rejects.toThrow(ThreatBlockedError);
  });

  it('matches patterns with rules', async () => {
    guard.addRule('DROP TABLE', MockConfig.block({ threatLevel: 'critical' }));

    const safe = await guard.check('SELECT * FROM users');
    expect(safe.isThreat).toBe(false);

    const threat = await guard.check('DROP TABLE users');
    expect(threat.isThreat).toBe(true);
    expect(threat.threatLevel).toBe('critical');
  });

  it('tracks call history', async () => {
    await guard.check('test 1');
    await guard.check('test 2');

    expect(guard.callHistory).toHaveLength(2);
    guard.assertCalledWith('test 1');
    guard.assertCallCount(2);
  });
});

// Use pre-configured fixtures
describe('with fixtures', () => {
  it('uses common threat patterns', async () => {
    const { guard, threats, safe } = createTestFixtures();

    const safeResult = await guard.check(safe.greeting);
    expect(safeResult.isThreat).toBe(false);

    const threatResult = await guard.check(threats.sqlInjection);
    expect(threatResult.isThreat).toBe(true);
  });
});
```

## Requirements

- Node.js >= 18.0.0 (uses native `fetch`)
- TypeScript >= 4.7.0 (optional, for type checking)

## License

MIT © BlindAI

## Links

- [Documentation](https://docs.blindai.dev)
- [Dashboard](https://app.blindai.dev)
- [Python SDK](https://pypi.org/project/blind-ai/)
- [GitHub](https://github.com/blindai/sdk-typescript)
