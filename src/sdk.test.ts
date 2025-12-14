import { describe, it, expect, beforeEach } from 'vitest';
import {
  MockBlindAI,
  MockConfig,
  createTestFixtures,
  ThreatBlockedError,
  type ProtectionResult,
} from './testing/index';

describe('MockBlindAI', () => {
  let guard: MockBlindAI;

  beforeEach(() => {
    guard = new MockBlindAI();
  });

  describe('check()', () => {
    it('allows by default', async () => {
      const result = await guard.check('Hello world');
      
      expect(result.isThreat).toBe(false);
      expect(result.threatLevel).toBe('none');
      expect(result.finalAction).toBe('allow');
    });

    it('can be configured to block', async () => {
      guard = new MockBlindAI(MockConfig.block());
      
      const result = await guard.check('anything');
      
      expect(result.isThreat).toBe(true);
      expect(result.threatLevel).toBe('high');
    });

    it('matches rules by pattern', async () => {
      guard.addRule('drop table', MockConfig.block({ threatLevel: 'critical' }));
      guard.addRule('select', MockConfig.allow());
      
      const safe = await guard.check('SELECT * FROM users');
      expect(safe.isThreat).toBe(false);
      
      const threat = await guard.check('DROP TABLE users');
      expect(threat.isThreat).toBe(true);
      expect(threat.threatLevel).toBe('critical');
    });

    it('records call history', async () => {
      await guard.check('test 1');
      await guard.check('test 2');
      
      expect(guard.callHistory).toHaveLength(2);
      expect(guard.callHistory[0]?.text).toBe('test 1');
      expect(guard.callHistory[1]?.text).toBe('test 2');
    });
  });

  describe('protect()', () => {
    it('allows safe input', async () => {
      const result = await guard.protect({
        text: 'Hello',
        onViolation: 'block',
      });
      
      expect(result.isThreat).toBe(false);
    });

    it('throws ThreatBlockedError when blocking', async () => {
      guard = new MockBlindAI(MockConfig.block());
      
      await expect(
        guard.protect({
          text: 'malicious',
          onViolation: 'block',
        })
      ).rejects.toThrow(ThreatBlockedError);
    });

    it('calls onBlock handler before throwing', async () => {
      guard = new MockBlindAI(MockConfig.block());
      let handlerCalled = false;
      
      await expect(
        guard.protect({
          text: 'test',
          onViolation: 'block',
          onBlock: () => {
            handlerCalled = true;
          },
        })
      ).rejects.toThrow(ThreatBlockedError);
      
      expect(handlerCalled).toBe(true);
    });

    it('allows when onViolation is warn', async () => {
      guard = new MockBlindAI(MockConfig.block());
      
      const result = await guard.protect({
        text: 'test',
        onViolation: 'warn',
      });
      
      expect(result.isThreat).toBe(true);
      // Should not throw
    });

    it('supports challenge handler', async () => {
      guard = new MockBlindAI(MockConfig.challenge());
      
      // Allow via challenge
      const allowedResult = await guard.protect({
        text: 'test',
        onViolation: 'challenge',
        onChallenge: () => true,
      });
      expect(allowedResult.isThreat).toBe(true);
      
      // Block via challenge
      await expect(
        guard.protect({
          text: 'test',
          onViolation: 'challenge',
          onChallenge: () => false,
        })
      ).rejects.toThrow(ThreatBlockedError);
    });
  });

  describe('checkBatch()', () => {
    it('checks multiple texts', async () => {
      const result = await guard.checkBatch(['text 1', 'text 2', 'text 3']);
      
      expect(result.total).toBe(3);
      expect(result.passed).toBe(3);
      expect(result.failed).toBe(0);
      expect(result.results).toHaveLength(3);
    });

    it('reports failures', async () => {
      guard.addRule('bad', MockConfig.block());
      
      const result = await guard.checkBatch(['good', 'bad', 'good']);
      
      expect(result.passed).toBe(2);
      expect(result.failed).toBe(1);
    });

    it('calls progress callback', async () => {
      const progress: Array<[number, number]> = [];
      
      await guard.checkBatch(['a', 'b', 'c'], {
        onProgress: (done, total) => progress.push([done, total]),
      });
      
      expect(progress).toEqual([[1, 3], [2, 3], [3, 3]]);
    });
  });

  describe('assertions', () => {
    it('assertCalled passes when called', async () => {
      await guard.check('test');
      expect(() => guard.assertCalled()).not.toThrow();
    });

    it('assertCalled fails when not called', () => {
      expect(() => guard.assertCalled()).toThrow();
    });

    it('assertCalledWith checks text', async () => {
      await guard.check('specific text');
      expect(() => guard.assertCalledWith('specific text')).not.toThrow();
      expect(() => guard.assertCalledWith('other text')).toThrow();
    });

    it('assertCallCount checks count', async () => {
      await guard.check('1');
      await guard.check('2');
      
      expect(() => guard.assertCallCount(2)).not.toThrow();
      expect(() => guard.assertCallCount(1)).toThrow();
    });

    it('assertNotCalled passes when not called', () => {
      expect(() => guard.assertNotCalled()).not.toThrow();
    });
  });

  describe('wrap()', () => {
    it('wraps functions and checks string args', async () => {
      const fn = (msg: string) => `Echo: ${msg}`;
      const wrapped = guard.wrap(fn);
      
      const result = await wrapped('Hello');
      expect(result).toBe('Echo: Hello');
      guard.assertCalledWith('Hello');
    });

    it('blocks threats in wrapped functions', async () => {
      guard = new MockBlindAI(MockConfig.block());
      
      const fn = (msg: string) => msg;
      const wrapped = guard.wrap(fn, { onViolation: 'block' });
      
      await expect(wrapped('test')).rejects.toThrow(ThreatBlockedError);
    });
  });

  describe('createProtector()', () => {
    it('creates reusable protector', async () => {
      const protect = guard.createProtector({
        policies: ['pii'],
        onViolation: 'block',
      });
      
      await protect('safe text');
      guard.assertCalledWith('safe text');
    });
  });

  describe('reset()', () => {
    it('resets all state', async () => {
      guard.addRule('test', MockConfig.block());
      await guard.check('something');
      
      guard.reset();
      
      expect(guard.callHistory).toHaveLength(0);
      
      // Rule should be cleared
      const result = await guard.check('test');
      expect(result.isThreat).toBe(false);
    });
  });
});

describe('createTestFixtures()', () => {
  it('provides pre-configured guard', async () => {
    const { guard, threats, safe } = createTestFixtures();
    
    const safeResult = await guard.check(safe.greeting);
    expect(safeResult.isThreat).toBe(false);
    
    const threatResult = await guard.check(threats.sqlInjection);
    expect(threatResult.isThreat).toBe(true);
  });

  it('detects SQL injection', async () => {
    const { guard, threats } = createTestFixtures();
    
    const result = await guard.check(threats.sqlInjection);
    expect(result.isThreat).toBe(true);
  });

  it('detects prompt injection', async () => {
    const { guard, threats } = createTestFixtures();
    
    const result = await guard.check(threats.promptInjection);
    expect(result.isThreat).toBe(true);
  });

  it('detects jailbreak attempts', async () => {
    const { guard, threats } = createTestFixtures();
    
    const result = await guard.check(threats.jailbreak);
    expect(result.isThreat).toBe(true);
  });

  it('detects PII', async () => {
    const { guard, threats } = createTestFixtures();
    
    const ssnResult = await guard.check(threats.piiSsn);
    expect(ssnResult.isThreat).toBe(true);
    
    const ccResult = await guard.check(threats.piiCreditCard);
    expect(ccResult.isThreat).toBe(true);
  });

  it('detects XSS', async () => {
    const { guard, threats } = createTestFixtures();
    
    const result = await guard.check(threats.xss);
    expect(result.isThreat).toBe(true);
  });
});

describe('ThreatBlockedError', () => {
  it('has correct properties', async () => {
    const guard = new MockBlindAI(MockConfig.block({ threatLevel: 'critical' }));
    
    try {
      await guard.protect({ text: 'test', onViolation: 'block' });
      expect.fail('Should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ThreatBlockedError);
      
      const e = error as ThreatBlockedError;
      expect(e.threatLevel).toBe('critical');
      expect(e.threats).toHaveLength(1);
      expect(e.result).toBeDefined();
      expect(e.code).toBe('THREAT_BLOCKED');
    }
  });
});

describe('MockConfig', () => {
  it('allow() creates allow config', () => {
    const config = MockConfig.allow();
    expect(config.isThreat).toBe(false);
    expect(config.finalAction).toBe('allow');
  });

  it('block() creates block config', () => {
    const config = MockConfig.block();
    expect(config.isThreat).toBe(true);
    expect(config.finalAction).toBe('block');
    expect(config.threatLevel).toBe('high');
  });

  it('block() accepts options', () => {
    const config = MockConfig.block({ threatLevel: 'critical' });
    expect(config.threatLevel).toBe('critical');
  });

  it('challenge() creates challenge config', () => {
    const config = MockConfig.challenge();
    expect(config.isThreat).toBe(true);
    expect(config.finalAction).toBe('challenge');
    expect(config.threatLevel).toBe('medium');
  });

  it('error() creates error config', () => {
    const error = new Error('Test error');
    const config = MockConfig.error(error);
    expect(config.throwError).toBe(error);
  });
});

// =============================================================================
// Priority 1: Challenge Handler Tests
// =============================================================================

describe('Challenge handler', () => {
  it('allows when handler returns true', async () => {
    const guard = new MockBlindAI(MockConfig.challenge({ threatLevel: 'medium' }));
    
    const result = await guard.protect({
      text: 'Suspicious input',
      onViolation: 'challenge',
      onChallenge: () => true,  // Approve
    });
    
    // Should pass through (isThreat reflects detection, not final decision)
    expect(result.threatLevel).toBe('medium');
  });

  it('blocks when handler returns false', async () => {
    const guard = new MockBlindAI(MockConfig.challenge({ threatLevel: 'medium' }));
    
    await expect(guard.protect({
      text: 'Suspicious input',
      onViolation: 'challenge',
      onChallenge: () => false,  // Reject
    })).rejects.toThrow(ThreatBlockedError);
  });

  it('receives ProtectionResult with correct threatLevel', async () => {
    let receivedResult: ProtectionResult | null = null;
    
    const guard = new MockBlindAI(MockConfig.challenge({ threatLevel: 'high' }));
    
    await guard.protect({
      text: 'Input',
      onViolation: 'challenge',
      onChallenge: (result) => {
        receivedResult = result;
        return true;
      },
    });
    
    expect(receivedResult).not.toBeNull();
    expect(receivedResult?.threatLevel).toBe('high');
    expect(receivedResult?.isThreat).toBe(true);
  });

  it('supports async challenge handlers', async () => {
    const guard = new MockBlindAI(MockConfig.challenge({ threatLevel: 'medium' }));
    
    const result = await guard.protect({
      text: 'Test',
      onViolation: 'challenge',
      onChallenge: async (result) => {
        // Simulate async approval process (e.g., database lookup)
        await new Promise(resolve => setTimeout(resolve, 10));
        return result.threatLevel !== 'critical';  // Approve non-critical
      },
    });
    
    expect(result.threatLevel).toBe('medium');
  });

  it('blocks when async handler returns false', async () => {
    const guard = new MockBlindAI(MockConfig.challenge({ threatLevel: 'critical' }));
    
    await expect(guard.protect({
      text: 'Test',
      onViolation: 'challenge',
      onChallenge: async (result) => {
        await new Promise(resolve => setTimeout(resolve, 10));
        return result.threatLevel !== 'critical';  // Reject critical
      },
    })).rejects.toThrow(ThreatBlockedError);
  });
});

// =============================================================================
// Priority 1: Block Handler (onBlock) Tests
// =============================================================================

describe('Block handler (onBlock)', () => {
  it('calls onBlock handler before throwing', async () => {
    const guard = new MockBlindAI(MockConfig.block({ threatLevel: 'high' }));
    let handlerCalled = false;
    
    await expect(
      guard.protect({
        text: 'malicious input',
        onViolation: 'block',
        onBlock: () => {
          handlerCalled = true;
        },
      })
    ).rejects.toThrow(ThreatBlockedError);
    
    expect(handlerCalled).toBe(true);
  });

  it('receives ProtectionResult with threat details', async () => {
    const guard = new MockBlindAI(MockConfig.block({ threatLevel: 'critical' }));
    let receivedResult: ProtectionResult | null = null;
    
    try {
      await guard.protect({
        text: 'malicious',
        onViolation: 'block',
        onBlock: (result) => {
          receivedResult = result;
        },
      });
    } catch {
      // Expected to throw
    }
    
    expect(receivedResult).not.toBeNull();
    expect(receivedResult?.isThreat).toBe(true);
    expect(receivedResult?.threatLevel).toBe('critical');
    expect(receivedResult?.threatsDetected.length).toBeGreaterThan(0);
  });

  it('supports async onBlock handlers', async () => {
    const guard = new MockBlindAI(MockConfig.block());
    const logs: string[] = [];
    
    await expect(
      guard.protect({
        text: 'test',
        onViolation: 'block',
        onBlock: async (result) => {
          // Simulate async logging/alerting
          await new Promise(resolve => setTimeout(resolve, 10));
          logs.push(`Blocked: ${result.threatLevel}`);
        },
      })
    ).rejects.toThrow(ThreatBlockedError);
    
    expect(logs).toContain('Blocked: high');
  });

  it('still throws even if onBlock handler fails', async () => {
    const guard = new MockBlindAI(MockConfig.block());
    
    // Handler throws but block error should still propagate
    await expect(
      guard.protect({
        text: 'test',
        onViolation: 'block',
        onBlock: () => {
          throw new Error('Handler failed');
        },
      })
    ).rejects.toThrow();  // Should throw something
  });

  it('does not call onBlock when no threat detected', async () => {
    const guard = new MockBlindAI(MockConfig.allow());
    let handlerCalled = false;
    
    await guard.protect({
      text: 'safe input',
      onViolation: 'block',
      onBlock: () => {
        handlerCalled = true;
      },
    });
    
    expect(handlerCalled).toBe(false);
  });
});

// =============================================================================
// Priority 2: Batch Progress Callback Tests
// =============================================================================

describe('Batch progress callback', () => {
  it('calls onProgress for each completed item', async () => {
    const guard = new MockBlindAI();
    const progressEvents: Array<{ completed: number; total: number }> = [];
    
    await guard.checkBatch(['a', 'b', 'c', 'd', 'e'], {
      concurrency: 2,
      onProgress: (completed, total) => {
        progressEvents.push({ completed, total });
      },
    });
    
    // Should have 5 progress events (one per item)
    expect(progressEvents.length).toBe(5);
    expect(progressEvents[progressEvents.length - 1]).toEqual({ completed: 5, total: 5 });
  });

  it('provides accurate progress with mixed results', async () => {
    const guard = new MockBlindAI();
    guard.addRule('bad', MockConfig.block());
    
    const progressEvents: Array<{ completed: number; total: number }> = [];
    
    const result = await guard.checkBatch(['good1', 'bad', 'good2'], {
      continueOnError: true,
      onProgress: (completed, total) => {
        progressEvents.push({ completed, total });
      },
    });
    
    expect(result.total).toBe(3);
    expect(progressEvents.length).toBe(3);
    // Final progress should be 3/3
    expect(progressEvents[2]).toEqual({ completed: 3, total: 3 });
  });

  it('completes progress even with errors', async () => {
    const guard = new MockBlindAI(MockConfig.error(new Error('API Error')));
    const progressEvents: number[] = [];
    
    await guard.checkBatch(['a', 'b', 'c'], {
      continueOnError: true,
      onProgress: (completed) => {
        progressEvents.push(completed);
      },
    });
    
    // All 3 should complete even with errors
    expect(progressEvents).toEqual([1, 2, 3]);
  });

  it('respects concurrency limit', async () => {
    const guard = new MockBlindAI();
    let maxConcurrent = 0;
    let currentConcurrent = 0;
    
    // Track concurrent executions via progress
    const originalCheck = guard.check.bind(guard);
    guard.check = async (text, options) => {
      currentConcurrent++;
      maxConcurrent = Math.max(maxConcurrent, currentConcurrent);
      await new Promise(resolve => setTimeout(resolve, 50));
      currentConcurrent--;
      return originalCheck(text, options);
    };
    
    await guard.checkBatch(['1', '2', '3', '4', '5', '6'], {
      concurrency: 2,
    });
    
    // With concurrency 2, should never exceed 2 concurrent
    expect(maxConcurrent).toBeLessThanOrEqual(2);
  });
});
