// Roles in a real browser. Starts the built CLI in team mode with a throwaway license (key made here, never the
// production key), a fresh HOME and a temp database, then signs in as each role in headless Chromium and checks
// what the page shows and what the server refuses. Set ZERO_E2E_SCREENSHOT_DIR to keep a screenshot of each step.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { chromium } = createRequire(join(root, 'packages/engine/package.json'))('playwright');
const { hashTeamPassword } = await import(pathToFileURL(join(root, 'packages/cli/dist/web/team-auth.js')).href);
const { osecDB } = await import(pathToFileURL(join(root, 'packages/engine/dist/storage/index.js')).href);

const shots = process.env.ZERO_E2E_SCREENSHOT_DIR;
if (shots) await mkdir(shots, { recursive: true });
const base = await mkdtemp(join(tmpdir(), 'zero-rbac-browser-'));
const home = join(base, 'home');
await mkdir(home, { recursive: true });
const PASSWORD = 'browser-test-password';
const wait = ms => new Promise(done => setTimeout(done, ms));

// A license signed with a key that exists only for this run.
const { publicKey, privateKey } = generateKeyPair();
function generateKeyPair() { return generateKeyPairSync('ed25519'); }
const payload = Buffer.from(JSON.stringify({ v: 1, id: 'lic_browser', customer: 'test', seats: 10, features: ['rbac'], issuedAt: new Date(Date.now() - 864e5).toISOString().replace(/\.\d+Z$/, 'Z'), expires: new Date(Date.now() + 30 * 864e5).toISOString().replace(/\.\d+Z$/, 'Z'), kid: 'b1' }));
const license = `${payload.toString('base64url')}.${sign(null, payload, privateKey).toString('base64url')}`;
const publicKeys = { b1: publicKey.export({ format: 'der', type: 'spki' }).toString('base64') };
// The server trusts the throwaway key through a loader hook written next to this run's files. The product has no
// setting that adds a trusted license key.
const enterpriseEntry = pathToFileURL(join(root, 'enterprise/dist/index.js')).href;
await mkdir(join(base, 'shim'), { recursive: true });
await writeFile(join(base, 'shim/shim.mjs'), `import * as real from ${JSON.stringify(enterpriseEntry)};
const extra = ${JSON.stringify(publicKeys)};
const merged = () => ({ ...real.PRODUCTION_PUBLIC_KEYS, ...extra });
export * from ${JSON.stringify(enterpriseEntry)};
export const hasFeature = (n, e, t, k) => real.hasFeature(n, e, t, k ?? merged());
export const featureMode = (n, e, t, k) => real.featureMode(n, e, t, k ?? merged());
export const requireFeature = (n, e, t, k) => real.requireFeature(n, e, t, k ?? merged());
export const licenseStatus = (e, t, k) => real.licenseStatus(e, t, k ?? merged());
export const loadLicense = (e, t, k) => real.loadLicense(e, t, k ?? merged());
`);
await writeFile(join(base, 'shim/hooks.mjs'), `export async function resolve(s, c, next) { if (s === '@0/enterprise') return { url: ${JSON.stringify(pathToFileURL(join(base, 'shim/shim.mjs')).href)}, shortCircuit: true }; return next(s, c); }\n`);
await writeFile(join(base, 'shim/register.mjs'), `import { register } from 'node:module'; register(${JSON.stringify(pathToFileURL(join(base, 'shim/hooks.mjs')).href)});\n`);

const hash = await hashTeamPassword(PASSWORD);
const people = [['owner', 'owner'], ['viewer', 'viewer'], ['triager', 'triager'], ['auditor', 'auditor'], ['scoped', 'payments-triager']];
const teamConfig = join(base, 'team.json');
await writeFile(teamConfig, JSON.stringify({
  workspace: { id: 'rbac-browser', name: 'Browser team' },
  users: people.map(([id, role]) => ({ id, name: id[0].toUpperCase() + id.slice(1), role, passwordHash: hash })),
  roles: { 'payments-triager': { permissions: ['findings.read', 'findings.triage'], scope: { businessUnits: ['payments'] } } },
  businessUnits: { payments: ['acme/pay-*'] },
}), { mode: 0o600 });
const dbPath = join(base, 'data.db');
const db = new osecDB(dbPath);
for (const target of ['https://github.com/acme/pay-api', 'https://github.com/acme/web']) {
  const scanId = db.createScan({ target, depth: 'full' });
  db.saveFinding(scanId, { id: `f-${target.split('/').pop()}`, templateId: 't', title: `Issue in ${target.split('/').pop()}`, description: 'd', severity: 'high', category: 'denial-of-service', status: 'discovered', evidence: { request: 'a', response: 'b' }, timestamp: Date.now() });
}
db.close();

let child, browser, output = '';
const results = [];
const ok = name => { results.push(name); console.log(`ok  ${name}`); };
try {
  child = spawn(process.execPath, ['--import', join(base, 'shim/register.mjs'), join(root, 'packages/cli/dist/index.js'), 'web', '--host', '127.0.0.1', '--port', '0', '--no-open', '--ready-json', '--team-config', teamConfig, '--db-path', dbPath, '--asset-dir', join(root, 'packages/web/dist')],
    { cwd: base, env: { PATH: process.env.PATH, HOME: home, NO_COLOR: '1', DO_NOT_TRACK: '1', ZERO_SKIP_UPDATE_CHECK: '1', ZERO_LICENSE: license }, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', data => { output = (output + data).slice(-32000); });
  child.stderr.on('data', data => { output = (output + data).slice(-32000); });
  let origin;
  for (let i = 0; i < 1200 && !origin; i++) { const ready = /ZERO_DASHBOARD_READY (\{[^\n]+\})/.exec(output); if (ready) origin = JSON.parse(ready[1]).url; else await wait(50); }
  assert.ok(origin, `server did not become ready: ${output}`);
  browser = await chromium.launch({ headless: true });

  async function signIn(user) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const page = await context.newPage();
    const refused = [];
    page.on('response', response => { if (response.url().includes('/api/') && response.status() === 403) refused.push(`${response.request().method()} ${new URL(response.url()).pathname}`); });
    await page.goto(origin, { waitUntil: 'domcontentloaded' });
    await page.getByLabel('Account').fill(user);
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in' }).click();
    // A first-run release-notes dialog can cover the page; close it.
    await page.getByRole('button', { name: 'Got it' }).click({ timeout: 8000 }).catch(() => {});
    try { await page.getByRole('button', { name: /^Account:/ }).waitFor({ timeout: 30000 }); }
    catch (error) { if (shots) await page.screenshot({ path: join(shots, `failed-sign-in-${user}.png`) }); console.error(`403s seen for ${user}: ${refused.join(', ')}`); throw error; }
    return { page, context, refused };
  }
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: join(shots, `${name}.png`), fullPage: false }); };
  // The page calls the API with the control token from its own HTML; do the same for checks that need a status code.
  const api = (page, path, init = {}) => page.evaluate(async ([p, i]) => {
    const token = document.querySelector('meta[name="0-control-token"]')?.content ?? '';
    const response = await fetch(p, { method: i.method ?? 'GET', headers: { 'x-0-control-token': token, ...(i.body ? { 'content-type': 'application/json' } : {}) }, body: i.body ? JSON.stringify(i.body) : undefined });
    return { status: response.status, text: await response.text() };
  }, [path, init]);

  // 1. The owner changes a role from the Members page.
  const owner = await signIn('owner');
  await owner.page.goto(`${origin}/team`, { waitUntil: 'domcontentloaded' });
  await owner.page.getByText('Members').first().waitFor({ timeout: 20000 });
  const viewerRole = owner.page.getByRole('combobox', { name: 'Role of Viewer' });
  await viewerRole.waitFor({ timeout: 20000 });
  await shot(owner.page, '01-owner-members');
  await viewerRole.click();
  await owner.page.getByRole('option').first().waitFor({ timeout: 10000 });
  const options = await owner.page.getByRole('option').allTextContents();
  assert.deepEqual(options.map(text => text.trim()).sort(), ['Auditor', 'Editor', 'Owner', 'Payments-triager', 'Triager', 'Viewer']);
  await shot(owner.page, '02-owner-role-options');
  await owner.page.getByRole('option', { name: 'Triager', exact: true }).click();
  await owner.page.getByText('Role changed.').waitFor({ timeout: 20000 });
  await shot(owner.page, '03-owner-role-changed');
  ok('the owner sees every role and changes the viewer to triager on the Members page');
  const log = await api(owner.page, '/api/console/audit-log?q=user.role_changed');
  assert.equal(log.status, 200);
  assert.ok(JSON.parse(log.text).events.some(event => event.action === 'user.role_changed' && event.subject === 'viewer' && event.detail.new === 'triager'), log.text);
  ok('the change is in the audit log');

  // 2. The changed account can now triage and still cannot run threads.
  const viewer = await signIn('viewer');
  assert.notEqual((await api(viewer.page, '/api/finding-family/none/triage', { method: 'POST', body: { triageStatus: 'accepted' } })).status, 403);
  assert.equal((await api(viewer.page, '/api/console/sessions', { method: 'POST', body: {} })).status, 403);
  await viewer.page.goto(`${origin}/team`, { waitUntil: 'domcontentloaded' });
  await viewer.page.getByText('Members').first().waitFor({ timeout: 20000 });
  assert.equal(await viewer.page.getByRole('combobox', { name: /Role of/ }).count(), 0, 'a triager must not get role controls');
  await shot(viewer.page, '04-changed-account-members');
  ok('a role change applies at once: the account can triage, cannot run threads, has no role controls');

  // 3. The auditor reads findings and the audit log, nothing else.
  const auditor = await signIn('auditor');
  assert.equal((await api(auditor.page, '/api/console/audit-log')).status, 200);
  assert.equal((await api(auditor.page, '/api/dashboard')).status, 200);
  for (const path of ['/api/console/sessions', '/api/console/settings', '/api/skills']) assert.equal((await api(auditor.page, path)).status, 403, path);
  await auditor.page.goto(`${origin}/findings`, { waitUntil: 'domcontentloaded' });
  await auditor.page.getByText('Issue in pay-api').first().waitFor({ timeout: 30000 });
  await shot(auditor.page, '05-auditor-findings');
  ok('the auditor sees both findings in the browser and is refused threads, settings and skills by the server');

  // 4. The scoped account sees only its business unit.
  const scoped = await signIn('scoped');
  await scoped.page.goto(`${origin}/findings`, { waitUntil: 'domcontentloaded' });
  await scoped.page.getByText('Issue in pay-api').first().waitFor({ timeout: 30000 });
  await wait(1500);
  assert.equal(await scoped.page.getByText('Issue in web').count(), 0, 'the scoped account must not see the other repository');
  await shot(scoped.page, '06-scoped-findings');
  ok('the scoped account sees only acme/pay-api in the browser');

  // 5. A route nobody wrote a rule for is refused for the owner too.
  const unknown = await api(owner.page, '/api/brand-new-route');
  assert.equal(unknown.status, 403); assert.match(unknown.text, /no permission rule/);
  ok('a route without a permission rule is refused');
  for (const session of [owner, viewer, auditor, scoped]) await session.context.close();
  console.log(`\n${results.length} browser checks passed`);
} catch (error) {
  console.error(output.slice(-4000));
  throw error;
} finally {
  await browser?.close().catch(() => {});
  child?.kill('SIGKILL');
}
