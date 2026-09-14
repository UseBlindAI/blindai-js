# Contributing to BlindAI TypeScript SDK

Thank you for your interest in contributing to BlindAI! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/blindai-js.git
   cd blindai-js
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/UseBlindAI/blindai-js.git
   ```

## Development Setup

### Prerequisites

- Node.js >= 18.0.0
- pnpm (recommended) or npm

### Install Dependencies

```bash
# Using pnpm (recommended)
pnpm install

# Or using npm
npm install
```

### Build

```bash
pnpm build
```

### Verify Setup

```bash
# Run tests
npm test

# Type checking
pnpm typecheck

# Linting
pnpm lint
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feat/add-batch-processing` - New features
- `fix/timeout-handling` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/simplify-client` - Code refactoring
- `test/add-mock-tests` - Test additions

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add batch processing support
fix: handle timeout errors gracefully
docs: update installation instructions
test: add tests for mock client
refactor: simplify error handling logic
chore: update dependencies
```

### Making Your Changes

1. **Create a branch**:
   ```bash
   git checkout -b feat/your-feature
   ```

2. **Make changes** and commit frequently:
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

3. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

## Pull Request Process

1. **Ensure tests pass**:
   ```bash
   npm test
   pnpm typecheck
   pnpm lint
   ```

2. **Update documentation** if needed

3. **Push your branch**:
   ```bash
   git push origin feat/your-feature
   ```

4. **Open a Pull Request** on GitHub with:
   - Clear title following conventional commits
   - Description of changes
   - Link to related issues (if any)

5. **Address review feedback** promptly

### PR Checklist

- [ ] Tests pass locally
- [ ] Types are correct (no `any` unless necessary)
- [ ] JSDoc comments for public APIs
- [ ] CHANGELOG.md updated (for notable changes)
- [ ] No breaking changes (or clearly documented)

## Coding Standards

### TypeScript Style

- Use strict TypeScript (`strict: true`)
- Prefer `interface` over `type` for object shapes
- Use `const` assertions where appropriate
- No `any` types unless absolutely necessary

### Code Style

```typescript
// ✅ Good - explicit return type
export function check(text: string): Promise<ProtectionResult> {
  // ...
}

// ❌ Bad - implicit any
export function check(text) {
  // ...
}
```

### Error Handling

- Use custom error classes from `src/errors.ts`
- Never expose sensitive data in error messages
- Provide actionable error messages

```typescript
// ✅ Good
throw new ConfigurationError('Invalid timeout: must be positive number');

// ❌ Bad
throw new Error('bad config');
```

## Testing

### Running Tests

```bash
# All tests
npm test

# Watch mode
npm run test:contract

# Coverage
npm run check
```

### Writing Tests

- Place tests in `src/__tests__/` directory
- Use descriptive test names
- Use the `MockBlindAI` for unit tests

```typescript
import { describe, it, expect } from 'vitest';
import { MockBlindAI, MockConfig } from '../testing';

describe('BlindAI', () => {
  it('should detect threats', async () => {
    const guard = new MockBlindAI(MockConfig.block());
    
    await expect(
      guard.protect({ text: 'test', onViolation: 'block' })
    ).rejects.toThrow(ThreatBlockedError);
  });
});
```

## Questions?

- Open a [GitHub Discussion](https://github.com/UseBlindAI/blindai-js/discussions)
- Check existing [Issues](https://github.com/UseBlindAI/blindai-js/issues)

Thank you for contributing! 🎉
