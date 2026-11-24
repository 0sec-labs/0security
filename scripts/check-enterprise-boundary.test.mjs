import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { ALLOWED_BRIDGES, checkEnterpriseBoundary, moduleSpecifiers } from "./check-enterprise-boundary.mjs";

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
  assert.deepEqual(ALLOWED_BRIDGES, ["packages/cli/src/enterprise-bridge.ts", "packages/cli/vitest.setup.ts", "packages/cli/src/enterprise-bridge.test.ts", "packages/cli/src/findings-server-bridge.ts"]);
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
