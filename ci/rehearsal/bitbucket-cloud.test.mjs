import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

function rehearse(mode) {
  const directory = mkdtempSync(join(tmpdir(), '0-bitbucket-rehearsal-test-'));
  try {
    const stub = (name, source) => writeFileSync(join(directory, name), source, { mode: 0o700 });
    stub('0security', '#!/bin/sh\nexit 0\n');
    stub('sleep', '#!/bin/sh\nexit 0\n');
    stub('curl', `#!${process.execPath}
const fs = require('node:fs');
const counter = process.env.TEST_COUNTER;
const url = process.argv.at(-1);
if (!url.includes('/annotations')) {
  console.log(JSON.stringify({result:'FAILED', report_type:'SECURITY'}));
} else {
  const reads = Number(fs.existsSync(counter) ? fs.readFileSync(counter, 'utf8') : 0) + 1;
  fs.writeFileSync(counter, String(reads));
  const count = process.env.TEST_MODE === 'duplicates' ? 6 : process.env.TEST_MODE === 'delayed' && reads === 1 ? 0 : 3;
  console.log(JSON.stringify({values:Array.from({length:count}, (_,i)=>({external_id:'finding-'+i, report:{external_id:'report'}}))}));
}
`);
    return spawnSync('sh', [fileURLToPath(new URL('./bitbucket-cloud.sh', import.meta.url))], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, BITBUCKET_TOKEN: 'test-token', REHEARSAL_REPO: 'workspace/repository', REHEARSAL_COMMIT: 'a'.repeat(40), TEST_COUNTER: join(directory, 'reads'), TEST_MODE: mode },
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('counts annotations without counting embedded report IDs', () => {
  const result = rehearse('normal');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Automatic checks: 5 passed, 0 failed/);
});

test('waits for annotations to become visible after publishing', () => {
  const result = rehearse('delayed');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /still 3 annotations after the second upload/);
});

test('fails the rehearsal for actual duplicate annotations', () => {
  const result = rehearse('duplicates');
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stdout, /expected 3 annotations, found 6/);
  assert.match(result.stdout, /Automatic checks: 3 passed, 2 failed/);
});
