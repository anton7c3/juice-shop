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

test('GET /rest/admin/application-configuration', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'improper_asset_management',
        'full_path_disclosure',
        'secret_tokens',
        'csrf'
      ],
      attackParamLocations: [AttackParamLocation.HEADER],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/rest/admin/application-configuration`,
      headers: { 'X-Recruiting': 'We are hiring! Visit our careers page for more information.' }
    });
});