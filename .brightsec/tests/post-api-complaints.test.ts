import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/Complaints', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'file_upload',
        'bopla',
        'xss',
        'sqli'
      ],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        "code_source": "anton7c3/juice-shop:master",
        "databases": ["SQLite"],
        "user_roles": ["customer", "deluxe", "accounting", "admin"]
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Complaints`,
      body: {
        UserId: 123,
        message: "I have a complaint about the service.",
        file: "optional-file-path.jpg"
      },
      headers: {
        'X-Recruiting': 'We are hiring! Visit our careers page for more information.'
      }
    });
});