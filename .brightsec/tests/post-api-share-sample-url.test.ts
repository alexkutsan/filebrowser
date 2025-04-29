import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /api/share/sample-url', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'date_manipulation', 'xss', 'unvalidated_redirect'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.QUERY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .skipStaticParams(false) // Only for date_manipulation
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/share/sample-url`,
      body: {
        password: "examplePassword",
        expires: "2023-12-31T23:59:59",
        unit: "hours"
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
