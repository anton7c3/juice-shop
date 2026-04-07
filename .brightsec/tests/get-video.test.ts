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

test('GET /video', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xss', 'lfi', 'ssrf', 'file_upload'],
      attackParamLocations: [AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'anton7c3/juice-shop:master',
        databases: ['SQLite'],
        user_roles: ['customer', 'deluxe', 'accounting', 'admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.GET,
      url: `${baseUrl}/video`,
      headers: {
        'Accept-Ranges': 'bytes',
        'Content-Length': '1024',
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Range': 'bytes 0-1023/1048576',
        'Content-Type': 'video/mp4'
      }
    });
});