import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
const root = new URL('..', import.meta.url).pathname;
const pipe = join(root, 'ci/bitbucket-pipe/pipe.sh');
const read = path => readFileSync(join(root, path), 'utf8');
const { parse } = createRequire(join(root, 'packages/cli/package.json'))('yaml');
const version = JSON.parse(read('packages/cli/package.json')).version;
// Tests inherit only tool-location/OS settings, never real provider or service credentials.
const env = { PATH: process.env.PATH, HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_TERMINAL_PROMPT: '0' };
const git = (cwd, ...args) => execFileSync('git', ['-c', 'user.name=Qualification', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' }).trim();
function setup(t, scanExit = 0) {
  const dir = mkdtempSync(join(tmpdir(), '0-ci-package-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin'); mkdirSync(bin);
  const work = join(dir, 'work'); git(dir, 'init', '-q', '-b', 'main', 'origin');
  writeFileSync(join(dir, 'origin/base'), 'base'); git(join(dir, 'origin'), 'add', '.'); git(join(dir, 'origin'), 'commit', '-qm', 'base');
  git(dir, 'clone', '-q', join(dir, 'origin'), work); git(work, 'checkout', '-qb', 'feature'); writeFileSync(join(work, 'changed'), 'feature'); git(work, 'add', '.'); git(work, 'commit', '-qm', 'feature');
  const log = join(dir, 'log');
  writeFileSync(join(bin, '0security'), `#!/bin/sh\nprintf 'cwd=%s token=%s model=%s node=%s args=%s\\n' "$PWD" "$(if [ -n \"\${BITBUCKET_TOKEN:-}\" ]; then printf present; else printf none; fi)" "$(if [ -n \"\${OPENAI_API_KEY:-}\" ]; then printf present; else printf none; fi)" "\${NODE_OPTIONS:-none}" "$*" >> '${log}'\nif [ "$1" = scan ]; then while [ $# -gt 0 ]; do if [ "$1" = -o ]; then printf '%s\\n' '{"findings":[]}' > "$2"; fi; shift; done; exit ${scanExit}; fi\n`);
  chmodSync(join(bin, '0security'), 0o755);
  const run = extra => spawnSync('sh', [pipe], { cwd: work, env: { ...env, PATH: `${bin}:${env.PATH}`, BITBUCKET_CLONE_DIR: work, ZEROCI_BASE_BRANCH: 'main', BITBUCKET_TOKEN: '', OPENAI_API_KEY: '', ANTHROPIC_API_KEY: '', GOOGLE_API_KEY: '', ...extra }, encoding: 'utf8' });
  return { dir, work, log, run, output: join(work, '.zero-ci') };
}
test('Pipe runs the canonical scan and isolated publisher with separate credentials and preserves finding failure', t => {
  const c = setup(t, 1);
  const scan = c.run({ OPENAI_API_KEY: 'model-only', NODE_OPTIONS: '--require=/untrusted/script.js' });
  assert.equal(scan.status, 0, scan.stderr);
  assert.equal(readFileSync(join(c.output, 'scan.commit'), 'utf8').trim(), git(c.work, 'rev-parse', 'HEAD'));
  assert.equal(readFileSync(join(c.output, 'scan.exit'), 'utf8').trim(), '1');
  const publish = c.run({ MODE: 'publish', OPENAI_API_KEY: 'must-not-reach-publisher', BITBUCKET_TOKEN: 'publisher-only', ZEROCI_REPO: 'team/repo' });
  assert.equal(publish.status, 1, publish.stderr);
  const [first, second] = readFileSync(c.log, 'utf8').trim().split('\n');
  assert.match(first, /token=none model=present node=none args=scan/);
  assert.match(second, /token=present model=none node=none args=findings upload/);
  assert.ok(!second.startsWith(`cwd=${c.work}`));
  assert.match(second, /--repo team\/repo/);
});
test('Pipe scan refuses a publisher token and an unknown mode without running any CLI', t => {
  const c = setup(t);
  assert.equal(c.run({ BITBUCKET_TOKEN: 'must-not-scan' }).status, 2);
  assert.equal(c.run({ MODE: 'scan-and-publish' }).status, 2);
  assert.equal(existsSync(c.log), false);
});
test('Pipe publisher refuses file/directory symlinks and escaping artifact paths', t => {
  const c = setup(t); assert.equal(c.run({}).status, 0);
  rmSync(join(c.output, 'scan.json')); symlinkSync(join(c.output, 'scan.exit'), join(c.output, 'scan.json'));
  assert.equal(c.run({ MODE: 'publish' }).status, 2);
  rmSync(c.output, { recursive: true }); mkdirSync(join(c.dir, 'outside')); symlinkSync(join(c.dir, 'outside'), c.output);
  assert.equal(c.run({ MODE: 'publish' }).status, 2);
  assert.equal(c.run({ MODE: 'publish', ZEROCI_OUT_DIR: '../outside' }).status, 2);
});
test('Pipe preserves partial scan artifacts and no-token publishing makes no request', t => {
  const c = setup(t, 3); assert.equal(c.run({}).status, 0);
  assert.equal(c.run({ MODE: 'publish' }).status, 0);
  assert.equal(readFileSync(c.log, 'utf8').trim().split('\n').length, 1);
});
test('Pipe scan step passes the provider pin, model and AWS settings, and the publisher gets none of them', t => {
  const c = setup(t, 0);
  const dump = join(c.dir, 'env.txt');
  writeFileSync(join(c.dir, 'bin', '0security'), `#!/bin/sh\nenv > '${dump}'\nwhile [ $# -gt 0 ]; do if [ "$1" = -o ]; then printf '%s\\n' '{"findings":[]}' > "$2"; fi; shift; done\n`);
  chmodSync(join(c.dir, 'bin', '0security'), 0o755);
  const settings = { ZERO_SELECTED_PROVIDER: 'bedrock', ZERO_MODEL: 'eu.model.example', AWS_REGION: 'eu-central-1', AWS_ROLE_ARN: 'arn:aws:iam::123456789012:role/scan', AWS_WEB_IDENTITY_TOKEN_FILE: '/tmp/token' };
  assert.equal(c.run(settings).status, 0);
  const seen = readFileSync(dump, 'utf8');
  for (const [name, value] of Object.entries(settings)) assert.match(seen, new RegExp(`^${name}=${value.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&')}$`, 'm'));
  assert.doesNotMatch(seen, /^(?:OPENAI_API_KEY|AWS_ACCESS_KEY_ID)=/m);
  rmSync(dump);
  c.run({ MODE: 'publish', BITBUCKET_TOKEN: 'publisher-only', ZEROCI_REPO: 'team/repo', ...settings });
  assert.ok(!existsSync(dump) || !/^(?:ZERO_SELECTED_PROVIDER|ZERO_MODEL|AWS_REGION)=/m.test(readFileSync(dump, 'utf8')));
});
test('Jenkins library export creates standard layout and exactly copies canonical trusted scripts', t => {
  const dir = mkdtempSync(join(tmpdir(), '0-jenkins-package-')); t.after(() => rmSync(dir, { recursive: true, force: true })); const out = join(dir, 'export');
  execFileSync('sh', [join(root, 'ci/packaging/package-jenkins-library.sh'), out]);
  assert.equal(readFileSync(join(out, 'resources/0security/VERSION'), 'utf8').trim(), version);
  for (const file of ['install.sh', '0-ci-scan.sh', '0-ci-publish.sh']) assert.equal(readFileSync(join(out, 'resources/0security', file), 'utf8'), read(file === 'install.sh' ? file : `ci/scripts/${file}`));
  assert.equal(readFileSync(join(out, 'vars/zeroSecurity.groovy'), 'utf8'), read('ci/jenkins-library/vars/zeroSecurity.groovy'));
  assert.equal(readFileSync(`${out}.tar.gz.sha256`, 'utf8').trim().split(/\s+/)[0], createHash('sha256').update(readFileSync(`${out}.tar.gz`)).digest('hex'));
  assert.notEqual(spawnSync('sh', [join(root, 'ci/packaging/package-jenkins-library.sh'), out]).status, 0);
});
test('package metadata and qualification pipelines use explicit pins and isolated publisher', () => {
  const metadata = parse(read('ci/bitbucket-pipe/pipe.yml'));
  assert.equal(metadata.image, `ghcr.io/0sec-labs/0security-pipe:${version}`);
  const example = parse(read('ci/bitbucket-pipe/bitbucket-pipelines.yml'));
  const [scan, publish] = example.pipelines['pull-requests']['**'].map(value => value.step);
  assert.ok(!JSON.stringify(scan).includes('BITBUCKET_TOKEN'));
  assert.equal(publish.deployment, 'security-report'); assert.equal(publish.clone.enabled, false);
  assert.ok(!JSON.stringify(publish).includes('OPENAI_API_KEY'));
  const docker = read('ci/bitbucket-pipe/Dockerfile'); assert.ok(docker.includes(`ARG VERSION=${version}`)); assert.match(docker, /RELEASE_BASE_URL=.*releases\/download\/v\$\{VERSION\}/);
  assert.match(docker, /sh \/opt\/zero\/install.sh/); assert.ok(!docker.includes('latest/download'));
  assert.match(read('ci/bitbucket-pipe/qualification-pipelines.yml'), /qualify-pipe\.sh/);
  const library = read('ci/jenkins-library/vars/zeroSecurity.groovy');
  assert.match(library, /env.NODE_NAME == scanNode/); assert.match(library, /finally \{ deleteDir\(\) \}/);
  assert.ok(library.indexOf("node(config.publishLabel)") < library.indexOf('credentialsId: config.bitbucketCredential'));
});
test('packaging shell entrypoints parse as POSIX sh', () => {
  for (const file of ['ci/bitbucket-pipe/pipe.sh', 'ci/packaging/package-jenkins-library.sh', 'ci/packaging/qualify-pipe.sh']) assert.equal(spawnSync('sh', ['-n', join(root, file)]).status, 0, file);
});

test('scanner-only packaging mode supplies an operator-owned prepass tier and no model key', t => {
  const c = setup(t);
  const result = c.run({ ZEROCI_PREPASS_ONLY: '1' });
  assert.equal(result.status, 0, result.stderr);
  const log = readFileSync(c.log, 'utf8');
  assert.match(log, /model=none/); assert.match(log, /--tiers \/[^\s]+/);
  assert.equal(c.run({ ZEROCI_PREPASS_ONLY: 'invalid' }).status, 2);
});
