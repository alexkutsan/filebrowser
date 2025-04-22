import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
// Other setup and teardown logic from the test skeleton

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test case for POST /api/share/sample-url

test('POST /api/share/sample-url', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'business_constraint_bypass', 'xss', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/share/sample-url`,
      headers: { 'Content-Type': 'application/json' },
      body: {}
    });
});
