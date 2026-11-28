import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { ALLOWED_BRIDGES, FREE_FEATURES_FILE, checkEnterpriseBoundary, checkFreeFeatures, gateNames, moduleSpecifiers, xmldomLines } from "./check-enterprise-boundary.mjs";

const HEADER = "// Licensed under the 0security Enterprise License. See enterprise/LICENSE.\n";

function fixture(files) {
  const root = mkdtempSync(join(tmpdir(), "ent-boundary-"));
  const base = {
    "enterprise/LICENSE": "license text",
    "enterprise/package.json": JSON.stringify({ name: "@0/enterprise", private: true, license: "SEE LICENSE IN LICENSE" }),
    "enterprise/src/a.ts": `${HEADER}export const a = 1;\n`,
    "package.json": JSON.stringify({ name: "root", private: true }),
    "LICENSE-MIT": "MIT",
    "LICENSE-APACHE": "Apache",
  };
  for (const [rel, text] of Object.entries({ ...base, ...files })) {
    if (text === null) continue;
    const full = join(root, rel);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, text);
  }
  return root;
}

test("a clean layout passes", () => {
  assert.deepEqual(checkEnterpriseBoundary(fixture({}), []), []);
});

test("the shipped allow list names only existing bridge files", () => {
  assert.deepEqual(ALLOWED_BRIDGES, ["packages/cli/src/enterprise-bridge.ts", "packages/cli/vitest.setup.ts", "packages/cli/src/enterprise-bridge.test.ts", "packages/cli/src/findings-server-bridge.ts", "packages/cli/src/ha-bridge.ts"]);
});

test("moduleSpecifiers finds static, dynamic and require forms", () => {
  assert.deepEqual(moduleSpecifiers(`import a from "x"; export {b} from 'y'; await import("z"); require("w");`), ["x", "y", "z", "w"]);
});

test("an import by package name outside enterprise fails with a clear message", () => {
  const errors = checkEnterpriseBoundary(fixture({ "packages/cli/src/x.ts": 'import { hasFeature } from "@0/enterprise";\n' }), []);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /packages\/cli\/src\/x\.ts: imports "@0\/enterprise"/);
  assert.match(errors[0], /ALLOWED_BRIDGES/);
});

test("a relative import into enterprise fails", () => {
  const errors = checkEnterpriseBoundary(fixture({ "packages/web/src/y.ts": 'import { a } from "../../../enterprise/src/a.js";\n' }), []);
  assert.equal(errors.length, 1);
});

test("an allow-listed bridge may import", () => {
  const root = fixture({ "packages/cli/src/bridge.ts": 'import { a } from "@0/enterprise";\n' });
  assert.deepEqual(checkEnterpriseBoundary(root, ["packages/cli/src/bridge.ts"]), []);
});

test("a stale allow-list entry fails", () => {
  assert.match(checkEnterpriseBoundary(fixture({}), ["packages/cli/src/gone.ts"])[0], /does not exist/);
});

test("a missing header fails, also after a shebang", () => {
  const e1 = checkEnterpriseBoundary(fixture({ "enterprise/src/b.ts": "export const b = 2;\n" }), []);
  assert.match(e1[0], /enterprise\/src\/b\.ts: first line/);
  const e2 = checkEnterpriseBoundary(fixture({ "enterprise/tools/t.mjs": "#!/usr/bin/env node\nconsole.log(1);\n" }), []);
  assert.match(e2[0], /enterprise\/tools\/t\.mjs/);
  assert.deepEqual(checkEnterpriseBoundary(fixture({ "enterprise/tools/t.mjs": `#!/usr/bin/env node\n${HEADER}console.log(1);\n` }), []), []);
});

test("a wrong license field, a public package or publish settings fail", () => {
  const bad = (pkg) => checkEnterpriseBoundary(fixture({ "enterprise/package.json": JSON.stringify(pkg) }), []);
  assert.match(bad({ private: true, license: "MIT" })[0], /"license" must be/);
  assert.match(bad({ license: "SEE LICENSE IN LICENSE" })[0], /private/);
  assert.match(bad({ private: true, license: "SEE LICENSE IN LICENSE", files: ["src"] })[0], /npm publishing/);
});

test("a package manifest that would ship enterprise in an npm tarball fails", () => {
  const root = fixture({ "packages/cli/package.json": JSON.stringify({ name: "@0/cli", files: ["dist", "enterprise/dist"] }) });
  const errors = checkEnterpriseBoundary(root, []);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /excluded from the npm tarball/);
});

test("the root license files must not mention enterprise", () => {
  const errors = checkEnterpriseBoundary(fixture({ "LICENSE-MIT": "MIT except the enterprise directory" }), []);
  assert.match(errors[0], /LICENSE-MIT/);
});

test("the real repository passes", async () => {
  const { join: j } = await import("node:path");
  assert.deepEqual(checkEnterpriseBoundary(j(import.meta.dirname, "..")), []);
});

test("an environment variable that could add a trusted license key fails", () => {
  for (const name of ["ZERO_LICENSE_TEST_PUBLIC_KEYS", "ZERO_LICENSE_PUBLIC_KEY", "ZERO_TRUST_ANCHORS", "ZERO_TRUSTED_KEYS_LICENSE"]) {
    const root = fixture({ "packages/cli/src/x.ts": `const keys = process.env.${name};\n` });
    assert.ok(checkEnterpriseBoundary(root, []).some((e) => e.includes(name)), name);
    const bracket = fixture({ "packages/cli/src/y.ts": `const keys = env["${name}"];\n` });
    assert.ok(checkEnterpriseBoundary(bracket, []).some((e) => e.includes(name)), `${name} (brackets)`);
  }
});

test("the license code may read only ZERO_LICENSE and ZERO_LICENSE_FILE", () => {
  const root = fixture({ "enterprise/src/license.ts": `// Licensed under the 0security Enterprise License. See enterprise/LICENSE.\nexport const a = env.ZERO_LICENSE; export const b = env.ZERO_LICENSE_FILE; export const c = env.ZERO_EXTRA_ANCHORS;\n` });
  const errors = checkEnterpriseBoundary(root, []);
  assert.ok(errors.some((e) => e.includes("ZERO_EXTRA_ANCHORS")));
  assert.ok(!errors.some((e) => e.includes("reads ZERO_LICENSE_FILE") || e.includes("reads ZERO_LICENSE.")));
});

test("tests and fixtures may name such variables", () => {
  const root = fixture({ "packages/cli/src/a.test.ts": "process.env.ZERO_LICENSE_TEST_PUBLIC_KEYS;\n" });
  assert.deepEqual(checkEnterpriseBoundary(root, []), []);
});

const lockWith = (...versions) => versions.map(v => `  '@xmldom/xmldom@${v}':\n    resolution: {integrity: x}\n`).join("\n") + versions.map(v => `      '@xmldom/xmldom': ${v}\n`).join("");

test("xmldomLines reads package keys and dependency lines", () => {
  assert.deepEqual(xmldomLines(lockWith("0.8.15")), ["0.8"]);
  assert.deepEqual(xmldomLines(lockWith("0.8.15", "0.9.12")), ["0.8", "0.9"]);
  assert.deepEqual(xmldomLines("nothing here"), []);
});

test("one xmldom line in the lockfile passes", () => {
  assert.deepEqual(checkEnterpriseBoundary(fixture({ "pnpm-lock.yaml": lockWith("0.8.15") }), []), []);
  assert.deepEqual(checkEnterpriseBoundary(fixture({ "pnpm-lock.yaml": lockWith("0.8.15", "0.8.16") }), []), []);
});

test("two xmldom lines in the lockfile fail, so the SAML guard and verifier cannot split", () => {
  const errors = checkEnterpriseBoundary(fixture({ "pnpm-lock.yaml": lockWith("0.8.15", "0.9.12") }), []);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /@xmldom\/xmldom resolves to more than one line \(0\.8, 0\.9\)/);
});

const BRIDGE = "packages/cli/src/bridge.ts";
const bridgeSrc = 'import { hasFeature } from "@0/enterprise";\nexport function signRefusal() {\n  return hasFeature("x") ? null : "no";\n}\nexport function plain() {\n  return 1;\n}\n';
const freeList = (extra = {}) => JSON.stringify({ features: [{ id: "demo", paths: ["packages/cli/src/free.ts", "packages/cli/src/freedir"], ...extra }] });
const guarded = (files, extra) => fixture({ [BRIDGE]: bridgeSrc, [FREE_FEATURES_FILE]: freeList(extra), "packages/cli/src/free.ts": "export const ok = 1;\n", "packages/cli/src/freedir/a.ts": "export const a = 1;\n", ...files });

test("gateNames finds bridge wrappers that call a base gate, not plain functions", () => {
  const names = gateNames(guarded({}), [BRIDGE]);
  assert.ok(names.has("signRefusal") && names.has("hasFeature") && names.has("requireFeature"));
  assert.ok(!names.has("plain"));
});

test("an ungated free feature passes", () => {
  assert.deepEqual(checkEnterpriseBoundary(guarded({}), [BRIDGE]), []);
});

test("a free feature that calls hasFeature or requireFeature fails", () => {
  for (const call of ['hasFeature("rbac")', 'requireFeature("saml")', 'assertFeature("ha")', 'featureMode("ha")']) {
    const errors = checkEnterpriseBoundary(guarded({ "packages/cli/src/free.ts": `import { x } from "./bridge.js";\nexport const ok = ${call};\n` }), [BRIDGE]);
    assert.equal(errors.length, 1, call);
    assert.match(errors[0], /packages\/cli\/src\/free\.ts: calls the license gate \w+, but demo is a released free feature/);
  }
});

test("a gate called inside a listed directory fails, through a bridge wrapper too", () => {
  const errors = checkEnterpriseBoundary(guarded({ "packages/cli/src/freedir/deep/b.ts": "export const b = signRefusal();\n" }), [BRIDGE]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /freedir\/deep\/b\.ts: calls the license gate signRefusal/);
});

test("comments and test files may mention a gate", () => {
  const files = { "packages/cli/src/free.ts": '// never call hasFeature here\n/* requireFeature */\nexport const ok = 1;\n', "packages/cli/src/freedir/a.test.ts": 'hasFeature("x");\n' };
  assert.deepEqual(checkEnterpriseBoundary(guarded(files), [BRIDGE]), []);
});

test("allowedGates exempts only the named gates", () => {
  const files = { "packages/cli/src/free.ts": "signRefusal(); hasFeature('x');\n" };
  const errors = checkEnterpriseBoundary(guarded(files, { allowedGates: ["signRefusal"] }), [BRIDGE]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /hasFeature/);
});

test("a listed path that no longer exists fails", () => {
  const errors = checkEnterpriseBoundary(guarded({}, { paths: ["packages/cli/src/gone.ts"] }), [BRIDGE]);
  assert.match(errors[0], /gone\.ts, which does not exist/);
});

test("a malformed list fails", () => {
  assert.match(checkFreeFeatures(guarded({ [FREE_FEATURES_FILE]: "{" }))[0], /not valid JSON/);
  assert.match(checkFreeFeatures(guarded({ [FREE_FEATURES_FILE]: '{"features":[]}' }))[0], /non-empty/);
  assert.match(checkFreeFeatures(guarded({ [FREE_FEATURES_FILE]: '{"features":[{"id":"x"}]}' }))[0], /paths/);
});

test("the real list exists, is non-trivial and lists only existing, ungated files", async () => {
  const { join: j } = await import("node:path");
  const root = j(import.meta.dirname, "..");
  const list = JSON.parse((await import("node:fs")).readFileSync(j(root, FREE_FEATURES_FILE), "utf8"));
  assert.ok(list.features.length >= 10);
  assert.deepEqual(checkFreeFeatures(root), []);
  assert.ok(gateNames(root).has("evidenceSigningRefusal"));
});

test("the real list never mentions prices or plans", async () => {
  const { join: j } = await import("node:path");
  const text = (await import("node:fs")).readFileSync(j(import.meta.dirname, "..", FREE_FEATURES_FILE), "utf8");
  assert.doesNotMatch(text, /\b(price|pricing|plans?|tier|subscription|paid|enterprise)\b/i);
});
