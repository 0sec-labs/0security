import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { detectAi, generateSbom } from "./index.js";

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const folder = (files: Record<string, string>) => { const dir = mkdtempSync(join(tmpdir(), "0-aibom-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
const prop = (component: { properties: Array<{ name: string; value: string }> }, name: string) => component.properties.find(item => item.name === name)?.value;

describe("AI inventory", () => {
  const dir = () => folder({
    "app/model.py": 'from transformers import AutoModel, pipeline\nm = AutoModel.from_pretrained("bert-base-uncased")\nt = pipeline("sentiment-analysis", model="distilbert/distilbert-base-uncased-finetuned-sst-2-english")\nds = load_dataset("imdb")\nhf_hub_download(repo_id="org/weights", filename="x")\n',
    "app/chat.ts": 'const r = await client.chat.completions.create({ model: "gpt-4o-mini", messages });\nconst c = { model: "claude-sonnet-4-6" };\nconst notAModel = { model: "my-custom-thing" };\n',
    "weights/a.safetensors": "x", "weights/b.pt": "x", "weights/c.gguf": "x",
    ".mcp.json": JSON.stringify({ mcpServers: { files: { command: "npx", args: ["-y", "some-mcp-server", "/home/me"] }, pinned: { command: "npx", args: ["-y", "other@1.2.3"] }, remote: { url: "https://mcp.example.com/sse" } } }),
    "node_modules/x/ignored.py": 'AutoModel.from_pretrained("ignored/model")',
  });
  it("lists models, datasets, hosted model ids, model files and MCP servers, each with where it was seen", () => {
    const { components: found, services } = detectAi(dir());
    const refs = [...found, ...services].map(component => component["bom-ref"]);
    expect(refs).toEqual(expect.arrayContaining(["hub-model:bert-base-uncased", "hub-model:distilbert/distilbert-base-uncased-finetuned-sst-2-english", "dataset:imdb", "hub-model:org/weights", "hosted-model:gpt-4o-mini", "hosted-model:claude-sonnet-4-6", "ml-file:weights/a.safetensors", "ml-file:weights/b.pt", "ml-file:weights/c.gguf", "mcp:.mcp.json:files", "mcp:.mcp.json:pinned", "mcp:.mcp.json:remote"]));
    expect(refs.some(ref => ref.includes("ignored") || ref.includes("my-custom-thing"))).toBe(false);
    const bert = found.find(component => component.name === "bert-base-uncased")!;
    expect(bert.type).toBe("machine-learning-model");
    expect(prop(bert, "0:source")).toBe("app/model.py:2");
    expect(found.find(component => component.name === "imdb")!.type).toBe("data");
    expect(prop(found.find(component => component.name === "gpt-4o-mini")!, "0:provider")).toBe("openai");
  });
  it("flags pickle-based model files and unpinned MCP launchers, and nothing else", () => {
    const { components: found, services } = detectAi(dir());
    const by = (ref: string) => [...found, ...services].find(component => component["bom-ref"] === ref)!;
    expect(prop(by("ml-file:weights/b.pt"), "0:risk")).toContain("pickle");
    expect(prop(by("ml-file:weights/a.safetensors"), "0:risk")).toBeUndefined();
    expect(prop(by("mcp:.mcp.json:files"), "0:risk")).toContain("pinned");
    expect(prop(by("mcp:.mcp.json:pinned"), "0:risk")).toBeUndefined();
    expect(prop(by("mcp:.mcp.json:remote"), "0:url")).toBe("https://mcp.example.com/sse");
    expect((by("mcp:.mcp.json:remote") as { endpoints?: string[] }).endpoints).toEqual(["https://mcp.example.com/sse"]);
  });
  it("is part of the SBOM only when asked for, and the same folder gives the same document", () => {
    const where = dir();
    expect(generateSbom(where, { toolVersion: "0" }).bom.components).toEqual([]);
    const one = generateSbom(where, { toolVersion: "0", ai: true, now: new Date(0) }); const two = generateSbom(where, { toolVersion: "0", ai: true, now: new Date(0) });
    expect(one.bom.components.length).toBeGreaterThan(6);
    expect(one.bom.services).toHaveLength(3);
    expect(JSON.stringify(one.bom)).toBe(JSON.stringify(two.bom));
  });
});

describe("AI inventory: pickle scan", () => {
  it("marks a model file with dangerous imports, and keeps the generic warning for the rest", () => {
    const dir = folder({ "m/evil.pkl": "cos\nsystem\n(S'echo x'\ntR.", "m/benign.pt": "\u0080\u0002ccollections\nOrderedDict\n)R.", "m/junk.ckpt": "x" });
    const { components } = detectAi(dir);
    const risks = (ref: string) => components.find(component => component["bom-ref"] === ref)!.properties.filter(item => item.name === "0:risk").map(item => item.value);
    expect(risks("ml-file:m/evil.pkl")).toEqual(["pickle-based format: loading can run code", expect.stringContaining("dangerous pickle imports found (loading runs code): os.system")]);
    expect(risks("ml-file:m/benign.pt")).toEqual(["pickle-based format: loading can run code"]);
    expect(risks("ml-file:m/junk.ckpt")).toEqual(["pickle-based format: loading can run code"]);
  });
});


describe("AI inventory: ML-BOM fields", () => {
  const sha = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");
  const safetensors = (header: object, body = Buffer.alloc(16)) => { const json = Buffer.from(JSON.stringify(header)); const len = Buffer.alloc(8); len.writeBigUInt64LE(BigInt(json.length)); return Buffer.concat([len, json, body]); };
  const gguf = () => {
    const parts: Buffer[] = []; const u32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); parts.push(b); }; const u64 = (n: number) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); parts.push(b); };
    const str = (s: string) => { u64(s.length); parts.push(Buffer.from(s)); };
    parts.push(Buffer.from("GGUF")); u32(3); u64(7); u64(3);
    str("general.architecture"); u32(8); str("llama"); str("general.name"); u32(8); str("Tiny"); str("llama.context_length"); u32(4); u32(2048);
    return Buffer.concat(parts);
  };
  const onnx = () => { const field = (tag: number, payload: Buffer) => Buffer.concat([Buffer.from([tag, payload.length]), payload]); return Buffer.concat([Buffer.from([0x08, 0x08]), field(0x12, Buffer.from("pytorch")), field(0x1a, Buffer.from("2.1")), field(0x42, Buffer.from([0x0a, 0x00, 0x10, 0x11])), field(0x3a, Buffer.alloc(40))]); };
  const bin = (files: Record<string, Buffer | string>) => { const dir = mkdtempSync(join(tmpdir(), "0-mlbom-")); dirs.push(dir); for (const [path, content] of Object.entries(files)) { mkdirSync(join(dir, path, ".."), { recursive: true }); writeFileSync(join(dir, path), content); } return dir; };
  const get = (dir: string, ref: string, options?: Parameters<typeof detectAi>[1]) => detectAi(dir, options).components.find(component => component["bom-ref"] === ref)!;

  it("hashes local model files and reads only the header of safetensors, GGUF and ONNX", () => {
    const st = safetensors({ __metadata__: { format: "pt" }, a: { dtype: "F32", shape: [2, 2], data_offsets: [0, 16] }, b: { dtype: "F16", shape: [3], data_offsets: [16, 22] } });
    const g = gguf(); const o = onnx();
    const dir = bin({ "m/a.safetensors": st, "m/b.gguf": g, "m/c.onnx": o, "m/d.pt": "not a pickle", "m/e.tflite": "x" });
    const a = get(dir, "ml-file:m/a.safetensors");
    expect(a.hashes).toEqual([{ alg: "SHA-256", content: sha(st) }]);
    expect(prop(a, "0:parameter-count")).toBe("7");
    expect(prop(a, "0:tensor-count")).toBe("2");
    expect(prop(a, "0:tensor-dtypes")).toBe("F16,F32");
    expect(prop(a, "0:size-bytes")).toBe(String(st.length));
    const b = get(dir, "ml-file:m/b.gguf");
    expect(b.modelCard?.modelParameters?.architectureFamily).toBe("llama");
    expect(prop(b, "0:context-length")).toBe("2048");
    expect(prop(b, "0:tensor-count")).toBe("7");
    const c = get(dir, "ml-file:m/c.onnx");
    expect(prop(c, "0:onnx-ir-version")).toBe("8");
    expect(prop(c, "0:onnx-producer")).toBe("pytorch");
    expect(prop(c, "0:onnx-opset")).toBe("17");
    expect(get(dir, "ml-file:m/d.pt").hashes?.[0]?.content).toBe(sha("not a pickle"));
    expect(prop(get(dir, "ml-file:m/d.pt"), "0:format")).toBe("pytorch");
    expect(get(dir, "ml-file:m/e.tflite").modelCard).toBeUndefined();
  });
  it("survives hostile headers without reading past them", () => {
    const huge = Buffer.alloc(16); huge.writeBigUInt64LE(2n ** 60n);
    const dir = bin({ "x/a.safetensors": huge, "x/b.safetensors": safetensors({ t: { dtype: "F32", shape: [-1], data_offsets: [0, 1] } }), "x/c.gguf": Buffer.concat([Buffer.from("GGUF"), Buffer.alloc(40, 0xff)]), "x/d.onnx": Buffer.alloc(64, 0xff), "x/__proto__.safetensors": safetensors({ __proto__: { dtype: "F32", shape: [1] } }) });
    for (const ref of ["a.safetensors", "b.safetensors", "c.gguf", "d.onnx", "__proto__.safetensors"]) expect(get(dir, `ml-file:x/${ref}`).hashes).toHaveLength(1);
    expect(prop(get(dir, "ml-file:x/a.safetensors"), "0:header")).toContain("not a readable");
    expect(prop(get(dir, "ml-file:x/b.safetensors"), "0:parameter-count")).toBeUndefined();
  });
  it("skips the hash of a file over the limit and says so, without reading it", () => {
    const dir = bin({ "m/small.gguf": gguf() });
    const big = join(dir, "m", "big.safetensors"); writeFileSync(big, ""); truncateSync(big, 2 * 1024 ** 3 + 1);
    const component = get(dir, "ml-file:m/big.safetensors");
    expect(component.hashes).toBeUndefined();
    expect(prop(component, "0:hash-skipped")).toMatch(/^too large: 2147483649 bytes is over the 2147483648 byte limit$/);
    expect(prop(get(dir, "ml-file:m/small.gguf", { maxModelHashBytes: 10 }), "0:hash-skipped")).toContain("too large");
  });
  it("never follows a symlink out of the folder and never opens a FIFO", () => {
    const outside = bin({ "secret.safetensors": "secret", "d/leak.csv": "a\n", "README.md": "---\nlicense: mit\n---\n" });
    const inside = bin({ "ok.gguf": gguf() });
    symlinkSync(join(outside, "secret.safetensors"), join(inside, "link.safetensors"));
    symlinkSync(join(outside, "d"), join(inside, "linked-dir"));
    symlinkSync(join(outside, "README.md"), join(inside, "README.md"));
    try { execFileSync("mkfifo", [join(inside, "pipe.pt")]); } catch { /* no mkfifo here */ }
    const refs = detectAi(inside).components.map(component => component["bom-ref"]);
    expect(refs).toEqual(["ml-file:ok.gguf"]);
    expect(get(inside, "ml-file:ok.gguf").licenses).toBeUndefined();
  });
  it("takes licences only from a model card or LICENSE file next to the model, and never guesses", () => {
    const mit = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY";
    const dir = bin({ "a/README.md": "---\nlicense: apache-2.0\npipeline_tag: text-generation\n---\n# Card\n", "a/m.safetensors": "x", "b/LICENSE": mit, "b/m.gguf": "x", "c/README.md": "---\nlicense: llama3\n---\n", "c/m.onnx": "x", "d/m.pt": "x", "d/NOTES.txt": "license: mit", "m.gguf": "x", "README.md": "no front matter, MIT mentioned" });
    expect(get(dir, "ml-file:a/m.safetensors").licenses).toEqual([{ license: { id: "Apache-2.0", acknowledgement: "declared" } }]);
    expect(get(dir, "ml-file:a/m.safetensors").modelCard?.modelParameters?.task).toBe("text-generation");
    expect(get(dir, "ml-file:b/m.gguf").licenses).toEqual([{ license: { id: "MIT", acknowledgement: "declared" } }]);
    expect(get(dir, "ml-file:c/m.onnx").licenses).toEqual([{ license: { name: "llama3", acknowledgement: "declared" } }]);
    expect(get(dir, "ml-file:d/m.pt").licenses).toBeUndefined();
    expect(get(dir, "ml-file:m.gguf").licenses).toBeUndefined();
  });
  it("links Hugging Face references to the Hub without a network call, and marks unpinned revisions", () => {
    const commit = "0123456789abcdef0123456789abcdef01234567";
    const dir = bin({ "app.py": `AutoModel.from_pretrained("org/pinned", revision="${commit}")\nAutoModel.from_pretrained("org/branch", revision="main")\nAutoModel.from_pretrained("org/floating")\nAutoModel.from_pretrained("./local-weights")\nload_dataset("csv", data_files="x.csv")\nload_dataset("org/data", revision="${commit}")\n` });
    const pinned = get(dir, "hub-model:org/pinned");
    expect(pinned.version).toBe(commit);
    expect(pinned.externalReferences).toEqual([expect.objectContaining({ type: "distribution", url: `https://huggingface.co/org/pinned/tree/${commit}` })]);
    expect(prop(pinned, "0:unpinned-revision")).toBeUndefined();
    expect(prop(get(dir, "hub-model:org/branch"), "0:unpinned-revision")).toContain("branch or tag");
    expect(prop(get(dir, "hub-model:org/floating"), "0:unpinned-revision")).toContain("no revision");
    expect(get(dir, "hub-model:org/floating").externalReferences?.[0]?.url).toBe("https://huggingface.co/org/floating");
    expect(get(dir, "hub-model:./local-weights").externalReferences).toBeUndefined();
    expect(get(dir, "dataset:csv").externalReferences).toBeUndefined();
    expect(get(dir, "dataset:org/data").data?.[0]?.contents?.url).toBe(`https://huggingface.co/datasets/org/data/tree/${commit}`);
    expect(get(dir, "hub-model:org/pinned").evidence?.occurrences).toEqual([{ location: "app.py", line: 1 }]);
  });
  it("lists local data files with hashes under the cap, and datasets named by a model card", () => {
    const dir = bin({ "data/train.csv": "a,b\n1,2\n", "data/big.parquet": "x", "m/README.md": "---\ndatasets:\n  - org/corpus\n---\n", "m/w.safetensors": "x" });
    const csv = get(dir, "data-file:data/train.csv");
    expect(csv.type).toBe("data");
    expect(csv.hashes).toEqual([{ alg: "SHA-256", content: sha("a,b\n1,2\n") }]);
    expect(prop(get(dir, "data-file:data/big.parquet", { maxDataHashBytes: 0 }), "0:hash-skipped")).toContain("too large");
    expect(get(dir, "ml-file:m/w.safetensors").modelCard?.modelParameters?.datasets).toEqual([{ ref: "dataset:org/corpus" }]);
  });
  it("fills modelCard only from facts, and treats a plain model file as having none", () => {
    const dir = bin({ "m/a.pt": "x", "n/config.json": '{"architectures":["BertModel"],"model_type":"bert"}', "n/w.safetensors": "x" });
    expect(get(dir, "ml-file:m/a.pt").modelCard).toBeUndefined();
    expect(get(dir, "ml-file:n/w.safetensors").modelCard).toEqual({ modelParameters: { architectureFamily: "bert", modelArchitecture: "BertModel" } });
  });
  it("gives the same document twice, and a new serial number when a model file changes", () => {
    const dir = bin({ "m/w.safetensors": safetensors({}) });
    const make = () => generateSbom(dir, { toolVersion: "0", ai: true, now: new Date(0) }).bom;
    expect(JSON.stringify(make())).toBe(JSON.stringify(make()));
    const before = make().serialNumber;
    writeFileSync(join(dir, "m", "w.safetensors"), safetensors({}, Buffer.alloc(32, 1)));
    expect(make().serialNumber).not.toBe(before);
  });
  it("reads .claude, .codex and .github MCP settings and no other hidden folder", () => {
    const mcp = JSON.stringify({ mcpServers: { s: { url: "https://mcp.example.com/sse" } } });
    const dir = bin({ ".claude/settings.json": mcp, ".github/mcp.json": mcp, ".codex/mcp.json": mcp, ".secret/mcp.json": mcp });
    expect(detectAi(dir).services.map(service => service["bom-ref"])).toEqual(["mcp:.claude/settings.json:s", "mcp:.codex/mcp.json:s", "mcp:.github/mcp.json:s"]);
  });
});

describe("AI inventory: bounds", () => {
  it("stops reading a folder at its entry limit and says so", () => {
    const dir = mkdtempSync(join(tmpdir(), "0-aibom-")); dirs.push(dir);
    for (let index = 0; index < 10050; index += 1) writeFileSync(join(dir, `f${index}.txt`), "");
    expect(detectAi(dir).notes.join(" ")).toContain("entries in one folder");
  });
  it("keeps the evidence for a model named many times bounded", () => {
    const body = Array.from({ length: 3000 }, () => 'AutoModel.from_pretrained("org/m")').join("\n");
    const dir = mkdtempSync(join(tmpdir(), "0-aibom-")); dirs.push(dir); writeFileSync(join(dir, "a.py"), body);
    const component = detectAi(dir).components[0]!;
    expect(component.evidence!.occurrences.length).toBeLessThanOrEqual(100);
  });
});
