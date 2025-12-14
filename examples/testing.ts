/**
 * BlindAI SDK Testing Utilities Example
 * 
 * Run with: npx tsx examples/testing.ts
 */

import { 
  MockBlindAI, 
  MockConfig, 
  createTestFixtures,
  ThreatBlockedError 
} from '@blindai/sdk/testing';

async function main() {
  console.log('='.repeat(50));
  console.log('BlindAI Testing Utilities');
  console.log('='.repeat(50));

  // Example 1: Default safe mock
  console.log('\n1. Default Safe Mock');
  console.log('-'.repeat(30));

  const safeMock = new MockBlindAI();
  const safeResult = await safeMock.check('any input');
  console.log(`Is threat: ${safeResult.isThreat}`); // false

  // Example 2: Always block mock
  console.log('\n2. Always Block Mock');
  console.log('-'.repeat(30));

  const blockMock = new MockBlindAI(MockConfig.block());
  const blockResult = await blockMock.check('any input');
  console.log(`Is threat: ${blockResult.isThreat}`); // true
  console.log(`Threat level: ${blockResult.threatLevel}`);

  // Example 3: Pattern-based rules
  console.log('\n3. Pattern-Based Rules');
  console.log('-'.repeat(30));

  const patternMock = new MockBlindAI();
  
  // Add rule: SQL injection pattern
  patternMock.addRule('DROP TABLE', MockConfig.block({
    threatLevel: 'critical',
    threats: ['sql-injection'],
  }));

  // Add rule: PII pattern
  patternMock.addRule(/\d{3}-\d{2}-\d{4}/, MockConfig.block({
    threatLevel: 'high',
    threats: ['pii'],
  }));

  const normalResult = await patternMock.check('Hello world');
  console.log(`"Hello world" - Is threat: ${normalResult.isThreat}`);

  const sqlResult = await patternMock.check('DROP TABLE users');
  console.log(`"DROP TABLE" - Is threat: ${sqlResult.isThreat}, level: ${sqlResult.threatLevel}`);

  const piiResult = await patternMock.check('SSN: 123-45-6789');
  console.log(`"SSN: xxx" - Is threat: ${piiResult.isThreat}, level: ${piiResult.threatLevel}`);

  // Example 4: Protect with mock
  console.log('\n4. Protect with Mock');
  console.log('-'.repeat(30));

  const protectMock = new MockBlindAI(MockConfig.block());

  try {
    await protectMock.protect({
      text: 'test input',
      onViolation: 'block',
    });
    console.log('Should not reach here');
  } catch (error) {
    if (error instanceof ThreatBlockedError) {
      console.log(`✅ Correctly threw ThreatBlockedError`);
      console.log(`  Threat level: ${error.threatLevel}`);
    }
  }

  // Example 5: Call history tracking
  console.log('\n5. Call History');
  console.log('-'.repeat(30));

  const historyMock = new MockBlindAI();
  await historyMock.check('first call');
  await historyMock.check('second call');
  await historyMock.check('third call');

  console.log(`Total calls: ${historyMock.callHistory.length}`);
  historyMock.assertCallCount(3);
  historyMock.assertCalledWith('first call');
  console.log('✅ All assertions passed');

  // Example 6: Test fixtures
  console.log('\n6. Test Fixtures');
  console.log('-'.repeat(30));

  const { guard, threats, safe } = createTestFixtures();

  const safeGreeting = await guard.check(safe.greeting);
  console.log(`Safe greeting - Is threat: ${safeGreeting.isThreat}`);

  const sqlInjection = await guard.check(threats.sqlInjection);
  console.log(`SQL injection - Is threat: ${sqlInjection.isThreat}`);

  console.log('\n✅ Done!');
}

main().catch(console.error);
