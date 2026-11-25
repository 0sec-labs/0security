import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { afterEach, describe, expect, it } from "vitest";
import { generateSbom } from "./index.js";

// The official CycloneDX 1.6 JSON schema (Apache-2.0), vendored so this check needs no network.
const schemas = join(import.meta.dirname, "..", "..", "test-fixtures", "cyclonedx");
const load = (name: string) => JSON.parse(readFileSync(join(schemas, name), "utf8"));
const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
addFormats(ajv);
ajv.addSchema(load("spdx.schema.json")); ajv.addSchema(load("jsf-0.82.schema.json"));
const validate = ajv.compile(load("bom-1.6.schema.json"));

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const folder = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-cdx-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
const problems = () => (validate.errors ?? []).slice(0, 5).map(error => `${error.instancePath} ${error.message}`);

describe("the SBOM is valid CycloneDX 1.6", () => {
  it("for libraries from every supported lockfile", () => {
    const dir = folder({
      "package-lock.json": JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.20" }, "node_modules/@babel/core": { version: "7.1.0", dev: true } } }),
      "pnpm-lock.yaml": "packages:\n  '@scope/name@1.2.3':\n    resolution: {integrity: x}\n",
      "yarn.lock": 'lodash@^4.17.0:\n  version "4.17.21"\n',
      "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
      "go.mod": "module x\nrequire github.com/gin-gonic/gin v1.9.1\n",
      "poetry.lock": '[[package]]\nname = "Django"\nversion = "4.2.7"\n',
      "requirements.txt": "flask==2.3.2\n",
      "Gemfile.lock": "GEM\n  specs:\n    rack (3.0.8)\n",
      "composer.lock": JSON.stringify({ packages: [{ name: "monolog/monolog", version: "3.5.0" }] }),
      "packages.lock.json": JSON.stringify({ dependencies: { "net8.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.3" } } } }),
      "gradle.lockfile": "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\n",
      "pubspec.lock": "packages:\n  http:\n    source: hosted\n    version: \"1.1.0\"\n",
      "mix.lock": '%{\n  "plug": {:hex, :plug, "1.15.2", "x"},\n}\n',
    });
    expect(validate(generateSbom(dir, { toolVersion: "0.0.0" }).bom), problems().join("; ")).toBe(true);
  });
  it("with hashes, a dependency graph and licenses (id, expression, name, several)", () => {
    const sri = `sha512-${Buffer.alloc(64, 3).toString("base64")}`;
    const dir = folder({
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/a": { version: "1.0.0", integrity: sri, license: "MIT", dependencies: { b: "1" } }, "node_modules/b": { version: "2.0.0", license: "(MIT OR Apache-2.0)" }, "node_modules/c": { version: "3.0.0", license: "SEE LICENSE IN X" } } }),
      "composer.lock": JSON.stringify({ packages: [{ name: "x/y", version: "1.0.0", dist: { shasum: "b".repeat(40) }, require: { "x/z": "1" }, license: ["MIT", "Custom"] }, { name: "x/z", version: "1.0.0" }] }),
      "Cargo.lock": `[[package]]\nname = "serde"\nversion = "1.0.190"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${"a".repeat(64)}"\ndependencies = [\n "serde_derive",\n]\n\n[[package]]\nname = "serde_derive"\nversion = "1.0.190"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
    });
    const { bom } = generateSbom(dir, { toolVersion: "0.0.0" });
    expect(bom.dependencies?.length).toBeGreaterThan(3);
    expect(bom.components.filter(component => component.type === "library" && component.hashes).length).toBe(3);
    expect(validate(bom), problems().join("; ")).toBe(true);
  });
  it("and the validator is real for the new fields: a malformed hash is rejected", () => {
    const { bom } = generateSbom(folder({ "package-lock.json": JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0" } } }) }), { toolVersion: "0" });
    expect(validate({ ...bom, components: [{ ...bom.components[0], hashes: [{ alg: "SHA-512", content: "zz" }] }] })).toBe(false);
  });
  it("with the AI inventory: models and datasets as components, MCP servers as services", () => {
    const dir = folder({ "app.py": 'AutoModel.from_pretrained("org/model")\nload_dataset("imdb")\n', "w/m.safetensors": "x", "w/n.pt": "x", ".mcp.json": JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "srv"] }, remote: { url: "https://mcp.example.com/sse" } } }) });
    const { bom } = generateSbom(dir, { toolVersion: "0.0.0", ai: true });
    expect(bom.services).toHaveLength(2);
    expect(validate(bom), problems().join("; ")).toBe(true);
  });
  it("with a full ML-BOM: model files with headers and hashes, Hub references, datasets, licences and a model card", () => {
    const dir = folder({ ".mcp.json": "{}", "app.py": 'AutoModel.from_pretrained("org/model", revision="' + "a".repeat(40) + '")\nload_dataset("imdb")\n', "m/README.md": "---\nlicense: apache-2.0\npipeline_tag: text-generation\ndatasets:\n  - org/data\n---\n", "m/config.json": '{"architectures":["LlamaForCausalLM"],"model_type":"llama"}', "m/w.safetensors": "x", "data/train.csv": "a,b\n" });
    const { bom } = generateSbom(dir, { toolVersion: "0.0.0", ai: true });
    expect(bom.components.some(component => "modelCard" in component && component.modelCard)).toBe(true);
    expect(bom.components.some(component => "externalReferences" in component && component.externalReferences)).toBe(true);
    expect(validate(bom), problems().join("; ")).toBe(true);
  });
  it("and the validator is real for the model card: an unknown modelCard field is rejected", () => {
    const { bom } = generateSbom(folder({ "app.py": 'AutoModel.from_pretrained("org/model")\n' }), { toolVersion: "0", ai: true });
    expect(validate({ ...bom, components: [{ ...bom.components[0], modelCard: { modelParameters: { bogus: 1 } } }] })).toBe(false);
  });
  it("and the validator is real: a service listed as a component is rejected", () => {
    const { bom } = generateSbom(folder({ "package-lock.json": JSON.stringify({ packages: { "node_modules/a": { version: "1.0.0" } } }) }), { toolVersion: "0" });
    expect(validate({ ...bom, components: [...bom.components, { type: "service", name: "x", "bom-ref": "x" }] })).toBe(false);
  });
  it("and an empty one is valid too", () => {
    expect(validate(generateSbom(folder({ "readme.md": "x" }), { toolVersion: "0.0.0" }).bom), problems().join("; ")).toBe(true);
  });
});
