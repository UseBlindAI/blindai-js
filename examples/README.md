# BlindAI TypeScript SDK Examples

This folder contains runnable examples demonstrating BlindAI SDK features.

## Quick Start

```bash
# Install dependencies
npm install @blindai/sdk

# Set your API key
export BLINDAI_API_KEY="your-api-key"

# Run an example
npx tsx examples/quickstart.ts
```

## Examples

| File | Description |
|------|-------------|
| [quickstart.ts](quickstart.ts) | Basic usage: check, protect, batch, wrap |
| [with-openai.ts](with-openai.ts) | Integration with OpenAI SDK |
| [testing.ts](testing.ts) | MockBlindAI and testing utilities |

## Running Examples

All examples use [tsx](https://github.com/esbuild-kit/tsx) for TypeScript execution:

```bash
npx tsx examples/quickstart.ts
npx tsx examples/with-openai.ts
npx tsx examples/testing.ts
```

## Environment Setup

Set your API key before running examples:

```bash
export BLINDAI_API_KEY="your-api-key"
```

Or in your code:

```typescript
import { BlindAI } from '@blindai/sdk';

const guard = new BlindAI({
  apiKey: 'your-api-key',
});
```
