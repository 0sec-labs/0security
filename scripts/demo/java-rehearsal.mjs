#!/usr/bin/env node
// Real CLI/model rehearsal in a disposable copy. Never writes to the operator's database.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
const options = { run: false, model: 'gpt-6-luna', budget: 0.5, timeout: 240 };
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--run') options.run = true;
  else if (['--model', '--budget', '--timeout'].includes(args[i])) {
    const key = args[i].slice(2), value = args[++i];
    if (!value) throw new Error(`${key} needs a value`);
    options[key] = key === 'model' ? value : Number(value);
  } else throw new Error(`Unknown option ${args[i]}`);
}
assert.ok(Number.isFinite(options.budget) && options.budget > 0);
assert.ok(Number.isInteger(options.timeout) && options.timeout > 0);
const cache = join(root, '.cache'); mkdirSync(cache, { recursive: true });
const directory = mkdtempSync(join(cache, 'java-demo-'));
const repo = join(directory, 'app'), home = join(directory, 'home');
mkdirSync(home);
const cli = join(root, 'packages/cli/dist/index.js');
const fixture = join(root, 'scripts/bench/fix-cases/java-path-traversal');
cpSync(join(fixture, 'repo'), repo, { recursive: true });
const env = { ...process.env, HOME: home, USERPROFILE: home,
  XDG_CONFIG_HOME: join(home, 'config'), XDG_DATA_HOME: join(home, 'data'), XDG_CACHE_HOME: join(home, 'cache'),
  DO_NOT_TRACK: '1', ZERO_TEAM_CONFIG: '', ZERO_DISABLE_MEMORY: '1',
  ZERO_CODEX_AUTH_JSON_PATH: process.env.ZERO_CODEX_AUTH_JSON_PATH || join(homedir(), '.codex/auth.json'),
  ZERO_FOXGUARD_PATH: process.env.ZERO_FOXGUARD_PATH || join(homedir(), '.0/bin/foxguard') };
mkdirSync(join(home, '.0'), { recursive: true });
writeFileSync(join(home, '.0/tui-settings.json'), JSON.stringify({ analyticsLevel: 'off', updatePolicy: 'off', executionProfile: 'host-local' }));
const receipt = { startedAt: new Date().toISOString(), source: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim(),
  directory, model: options.model, perStageBudget: options.budget, checks: [],
  limits: ['Small planted Java case; no enterprise accuracy or scale claim.', 'No live Bitbucket, identity provider or cloud deployment is implied.'] };
function run(name, command, argv, { cwd = repo, accepted = [0], timeout = 60000 } = {}) {
  console.log(`${name} ...`);
  const result = spawnSync(command, argv, { cwd, env, encoding: 'utf8', timeout, maxBuffer: 16 * 1024 * 1024 });
  // Raw model/CLI logs remain local in the ignored cache.
  writeFileSync(join(directory, `${name}.stdout.log`), result.stdout || '', { mode: 0o600 });
  writeFileSync(join(directory, `${name}.stderr.log`), result.stderr || '', { mode: 0o600 });
  assert.ok(!result.error && accepted.includes(result.status), `${name}: exit ${result.status}; see ${directory}/${name}.stderr.log`);
  receipt.checks.push({ name, exit: result.status });
  return result.stdout;
}
const command = (name, argv, extra) => run(name, process.execPath, [cli, ...argv], { cwd: directory, ...extra });
const modelArgs = ['--model', options.model, '--budget', String(options.budget), '--timeout', String(options.timeout)];
const json = file => JSON.parse(readFileSync(join(directory, file), 'utf8'));
function exploit(name, expected) {
  const out = join(directory, `${name}-classes`); mkdirSync(out);
  run(`${name}-compile`, 'javac', ['-d', out, join(repo, 'src/app/DocumentStore.java'), join(fixture, 'pov/Pov.java')]);
  run(name, 'java', ['-cp', out, 'Pov'], { accepted: [expected] });
}
try {
  run('git-init', 'git', ['init', '-q', '-b', 'main']);
  run('git-add', 'git', ['add', '.']);
  run('git-base', 'git', ['-c', 'user.name=Demo', '-c', 'user.email=demo@example.test', 'commit', '-qm', 'Vulnerable document service']);
  run('baseline-tests', 'sh', ['run-tests.sh']);
  exploit('baseline-exploit', 1);
  const context = join(directory, 'business-context.json');
  writeFileSync(context, JSON.stringify({ entries: [{ match: 'src/**', tags: ['internet-facing', 'personal-data'], note: 'Demo declaration: document download handles customer data.' }] }, null, 2));
  if (options.run) {
    assert.ok(existsSync(cli), 'Run pnpm build first');
    command('scan', ['scan', repo, '--prepass', 'off', '--batches', 'off', '--business-context', context, '--format', 'json', '-o', join(directory, 'scan.json'), ...modelArgs], { timeout: (options.timeout + 120) * 1000 });
    const scan = json('scan.json');
    assert.equal(scan.status, 'complete','Model scan did not complete successfully');
    assert.ok(scan.findings.some(f => f.category === 'path-traversal'), 'Scan missed traversal');
    const list = JSON.parse(command('findings-before', ['findings', 'list', '--format', 'json']));
    const finding = list.findings.find(f => f.category === 'path-traversal');
    assert.ok(finding?.id, 'Scanned finding not persisted');
    receipt.findingId = finding.id;
    receipt.scanCostUsd = scan.costUsd ?? null;
    command('verify', ['findings', 'verify', finding.id, '--folder', repo, '--format', 'json', '--per-finding', String(options.budget), ...modelArgs], { timeout: (options.timeout + 120) * 1000 });
    const fix = JSON.parse(command('fix', ['findings', 'fix', finding.id, '--repo', repo, '--test', 'sh run-tests.sh', '--no-pr', '--format', 'json', ...modelArgs], { timeout: (options.timeout + 180) * 1000 }));
    assert.equal(fix.committed, true, 'Fix did not produce a commit');
    assert.ok(fix.branch?.startsWith('0/fix-'));
    receipt.fix = { branch: fix.branch, costUsd: fix.costUsd ?? null };
    run('checkout-fix', 'git', ['checkout', '-q', fix.branch]);
    // Restore the original regression tests so modifying the tests cannot produce a pass.
    run('restore-tests', 'git', ['checkout', 'main', '--', 'run-tests.sh', 'test']);
    run('fixed-tests', 'sh', ['run-tests.sh']);
    exploit('fixed-exploit', 0);
    run('fix-diff', 'git', ['diff', 'main', fix.branch, '--', 'src']);
    command('findings-after', ['findings', 'list', '--format', 'json']);
    receipt.outcome = 'passed';
  } else receipt.outcome = 'prepared; model stages not run';
  const launcher = `#!/bin/sh\nset -eu\nexport HOME='${home.replaceAll("'", "'\\''")}'\nexport USERPROFILE="$HOME" XDG_CONFIG_HOME="$HOME/config" XDG_DATA_HOME="$HOME/data" XDG_CACHE_HOME="$HOME/cache"\nexport DO_NOT_TRACK=1 ZERO_TEAM_CONFIG=''\ncd '${repo.replaceAll("'", "'\\''")}'\nexec '${process.execPath}' '${cli}' --port 0 --no-open --ready-json --asset-dir '${join(root, 'packages/web/dist')}'\n`;
  writeFileSync(join(directory, 'console.sh'), launcher, { mode: 0o700 });
} catch (error) {
  receipt.outcome = 'failed'; receipt.error = error.message; process.exitCode = 1;
} finally {
  receipt.completedAt = new Date().toISOString();
  writeFileSync(join(directory, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(receipt, null, 2));
}
