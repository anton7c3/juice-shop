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

test('POST /rest/2fa/verify', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['jwt', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY],
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
      url: `${baseUrl}/rest/2fa/verify`,
      body: {
        tmpToken: "eyJhbGciOnt7IGVudHJ5cG9pbnQucGFyYW1zLmJvZHlfdG1wdG9rZW5fX2FsZyB9fSwidHlwIjp7eyBlbnRyeXBvaW50LnBhcmFtcy5ib2R5X3RtcHRva2VuX190eXAgfX19.eyJ1c2VySWQiOnt7IGVudHJ5cG9pbnQucGFyYW1zLmJvZHlfdG1wdG9rZW5fX3VzZXJpZCB9fSwidHlwZSI6e3sgZW50cnlwb2ludC5wYXJhbXMuYm9keV90bXB0b2tlbl9fdHlwZSB9fX0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        totpToken: "123456"
      },
      headers: { 'Content-Type': 'application/json' }
    });
});