import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateRawSync, gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { bufferBacking, classifyImport, listZip, modelScanToSarif, Reader, scanModelFile, scanModelPath, scanPickleStream } from "./index.js";

// ---- pickles, built byte by byte -------------------------------------------------------------------------------
const bytes = (...parts: Array<string | number[] | Buffer>): Buffer => Buffer.concat(parts.map(part => (typeof part === "string" ? Buffer.from(part, "latin1") : Buffer.from(part))));
const le = (value: number, width: number): Buffer => { const out = Buffer.alloc(width); if (width === 8) out.writeBigUInt64LE(BigInt(value)); else out.writeUIntLE(value, 0, width); return out; };
const PROTO = (n: number) => bytes([0x80, n]);
const FRAME = (n: number) => bytes([0x95], le(n, 8));
const SHORT_BINUNICODE = (text: string) => bytes([0x8c, text.length], text);
const MEMOIZE = bytes([0x94]);
const STACK_GLOBAL = bytes([0x93]);
const TUPLE1 = bytes([0x85]);
const REDUCE = bytes("R");
const STOP = bytes(".");
const GLOBAL = (module: string, name: string) => bytes(`c${module}\n${name}\n`);
const protocol0System = bytes("cos\nsystem\n(S'echo x'\ntR.");
const protocol4System = bytes(PROTO(4), FRAME(30), SHORT_BINUNICODE("os"), MEMOIZE, SHORT_BINUNICODE("system"), MEMOIZE, STACK_GLOBAL, MEMOIZE, SHORT_BINUNICODE("echo x"), MEMOIZE, TUPLE1, MEMOIZE, REDUCE, MEMOIZE, STOP);
/** A torch-style state dict: OrderedDict of one tensor, protocol 2, only expected imports. */
const benignTorch = bytes(PROTO(2), GLOBAL("collections", "OrderedDict"), ")R", "(X\x06\x00\x00\x00weight", GLOBAL("torch._utils", "_rebuild_tensor_v2"), "(", GLOBAL("torch", "FloatStorage"), "tRu.");

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => rmSync(dir, { recursive: true, force: true })));
const tmp = (): string => { const dir = mkdtempSync(join(tmpdir(), "0-modelscan-")); dirs.push(dir); return dir; };
const file = (name: string, content: Buffer | string): string => { const dir = tmp(); const path = join(dir, name); writeFileSync(path, content); return path; };

// ---- zip, built byte by byte -----------------------------------------------------------------------------------
interface Member { name: string; data: Buffer; deflate?: boolean; declaredSize?: number }
function makeZip(members: Member[], comment = ""): Buffer {
  const chunks: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const member of members) {
    const stored = member.deflate ? deflateRawSync(member.data) : member.data;
    const name = Buffer.from(member.name);
    const local = bytes(le(0x04034b50, 4), le(20, 2), le(0, 2), le(member.deflate ? 8 : 0, 2), le(0, 4), le(0, 4), le(stored.length, 4), le(member.declaredSize ?? member.data.length, 4), le(name.length, 2), le(0, 2), name, stored);
    central.push(bytes(le(0x02014b50, 4), le(20, 2), le(20, 2), le(0, 2), le(member.deflate ? 8 : 0, 2), le(0, 4), le(0, 4), le(stored.length, 4), le(member.declaredSize ?? member.data.length, 4), le(name.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), name));
    chunks.push(local);
    offset += local.length;
  }
  const directory = Buffer.concat(central);
  return bytes(...chunks, directory, le(0x06054b50, 4), le(0, 2), le(0, 2), le(members.length, 2), le(members.length, 2), le(directory.length, 4), le(offset, 4), le(comment.length, 2), comment);
}
// ---- numpy ----------------------------------------------------------------------------------------------------
function makeNpy(descr: string, payload: Buffer): Buffer {
  let header = `{'descr': '${descr}', 'fortran_order': False, 'shape': (1,), }`;
  while ((10 + header.length + 1) % 64) header += " ";
  header += "\n";
  return bytes([0x93], "NUMPY", [1, 0], le(header.length, 2), header, payload);
}

const qualified = (path: string) => scanModelFile(path).findings.map(item => `${item.risk}:${item.qualified}`);

describe("pickle opcode walker", () => {
  it("finds os.system in a protocol 0 payload and sees that it is called", () => {
    const scan = scanPickleStream(new Reader(bufferBacking(protocol0System)));
    expect(scan.imports).toEqual([{ module: "os", name: "system", opcodes: ["GLOBAL"], called: true, offset: 0 }]);
    expect(scan.pickles).toBe(1);
    expect(scan.stop).toBeUndefined();
  });
  it("resolves STACK_GLOBAL in protocol 4 from memoised strings", () => {
    const scan = scanPickleStream(new Reader(bufferBacking(protocol4System)));
    expect(scan.protocol).toBe(4);
    expect(scan.imports.map(item => `${item.module}.${item.name}:${item.opcodes}:${item.called}`)).toEqual(["os.system:STACK_GLOBAL:true"]);
  });
  it("resolves STACK_GLOBAL whose strings come back through BINGET", () => {
    // push 'builtins' and 'eval' (memo 0 and 1), pop both, fetch them again, then STACK_GLOBAL
    const payload = bytes(PROTO(4), SHORT_BINUNICODE("builtins"), MEMOIZE, SHORT_BINUNICODE("eval"), MEMOIZE, "00", [0x68, 0], [0x68, 1], STACK_GLOBAL, SHORT_BINUNICODE("1+1"), TUPLE1, REDUCE, STOP);
    expect(scanPickleStream(new Reader(bufferBacking(payload))).imports.map(item => `${item.module}.${item.name}`)).toEqual(["builtins.eval"]);
  });
  it("reports INST, OBJ and NEWOBJ", () => {
    const inst = bytes("(S'ls'\nios\nsystem\n.");
    expect(scanPickleStream(new Reader(bufferBacking(inst))).imports[0]).toMatchObject({ module: "os", name: "system", opcodes: ["INST"], called: true });
    const obj = bytes("(", GLOBAL("subprocess", "Popen"), "S'ls'\no.");
    expect(scanPickleStream(new Reader(bufferBacking(obj))).imports[0]).toMatchObject({ module: "subprocess", name: "Popen", called: true });
    const newobj = bytes(PROTO(2), GLOBAL("posix", "system"), ")", [0x81], STOP);
    expect(scanPickleStream(new Reader(bufferBacking(newobj))).imports[0]).toMatchObject({ module: "posix", name: "system", opcodes: ["GLOBAL"], called: true });
  });
  it("does not mistake a string that looks like an import for one", () => {
    const payload = bytes(PROTO(2), "X", le(20, 4), "cos\nsystem\n(S'x'\ntR", STOP);
    expect(scanPickleStream(new Reader(bufferBacking(payload))).imports).toEqual([]);
  });
  it("skips a long binary payload without reading it and still sees what follows", () => {
    const big = Buffer.alloc(40 * 1024 * 1024);
    const payload = bytes(PROTO(2), [0x42], le(big.length, 4), big, protocol0System);
    const scan = scanPickleStream(new Reader(bufferBacking(payload)));
    expect(scan.imports.map(item => item.name)).toEqual(["system"]);
  });
  it("walks several pickles in a row (old torch files) and tolerates raw data after them", () => {
    const payload = bytes(PROTO(2), "J", le(1, 4), STOP, benignTorch, Buffer.from([0xff, 0xfe, 0xfd, 0xfc]));
    const scan = scanPickleStream(new Reader(bufferBacking(payload)));
    expect(scan.pickles).toBe(2);
    expect(scan.stop).toBeUndefined();
    expect(scan.trailing).toMatch(/unknown opcode/);
  });
});

describe("classification", () => {
  it.each([
    ["os", "system"], ["posix", "system"], ["nt", "system"], ["subprocess", "check_output"], ["builtins", "eval"], ["builtins", "exec"], ["builtins", "compile"],
    ["builtins", "__import__"], ["builtins", "open"], ["__builtin__", "eval"], ["importlib", "import_module"], ["importlib.util", "spec_from_file_location"], ["socket", "socket"],
    ["shutil", "rmtree"], ["runpy", "run_path"], ["pty", "spawn"], ["webbrowser", "open"], ["requests", "get"], ["urllib.request", "urlopen"], ["http.client", "HTTPConnection"],
    ["ctypes", "CDLL"], ["pickle", "loads"], ["_pickle", "loads"], ["torch", "load"], ["torch.storage", "_load_from_bytes"], ["numpy", "load"], ["posixpath", "os"], ["sys", "modules"],
    ["builtins", "getattr"], ["operator", "attrgetter"], ["some.module", "eval"], ["numpy.testing._private.utils", "runstring"], ["joblib", "load"], ["torch.hub", "load"],
  ])("%s.%s is dangerous", (module, name) => { expect(classifyImport(module, name).risk).toBe("dangerous"); });
  it.each([
    ["torch._utils", "_rebuild_tensor_v2"], ["collections", "OrderedDict"], ["torch", "FloatStorage"], ["torch", "HalfStorage"], ["numpy.core.multiarray", "_reconstruct"],
    ["numpy", "dtype"], ["numpy", "ndarray"], ["numpy._core.multiarray", "scalar"], ["builtins", "set"], ["torch.nn.modules.linear", "Linear"], ["_codecs", "encode"], ["torch", "float32"],
    ["joblib.numpy_pickle", "NumpyArrayWrapper"],
  ])("%s.%s is expected", (module, name) => { expect(classifyImport(module, name).risk).toBe("expected"); });
  it.each([["sklearn.linear_model._base", "LinearRegression"], ["my_project.model", "Net"], ["base64", "b64decode"], ["builtins", "unheardof"]])("%s.%s is unrecognised", (module, name) => {
    expect(classifyImport(module, name).risk).toBe("unrecognised");
  });
  it("does not trust a module name only because it starts like a safe one", () => {
    expect(classifyImport("torch_evil", "x").risk).toBe("unrecognised");
    expect(classifyImport("os_helpers", "run").risk).toBe("unrecognised");
    expect(classifyImport("constructor", "x").risk).toBe("unrecognised");
  });
});

describe("model files", () => {
  it("flags a protocol 0 and a protocol 4 payload as dangerous", () => {
    for (const payload of [protocol0System, protocol4System]) {
      const result = scanModelFile(file("model.pkl", payload));
      expect(result.verdict).toBe("dangerous");
      expect(result.format).toBe("pickle");
      expect(result.findings[0]).toMatchObject({ risk: "dangerous", qualified: "os.system", called: true });
      expect(result.summary).toContain("os.system");
    }
  });
  it("says only that nothing dangerous was found for a benign checkpoint, and counts the expected imports", () => {
    const result = scanModelFile(file("weights.pt", benignTorch));
    expect(result).toMatchObject({ verdict: "none-found", expectedImports: 3, complete: true, protocol: 2 });
    expect(result.summary).toBe("no dangerous imports found");
    expect(result.summary).not.toMatch(/\bsafe\b/);
  });
  it("lists unrecognised imports at a lower severity", () => {
    const result = scanModelFile(file("clf.joblib", bytes(PROTO(2), GLOBAL("sklearn.linear_model._base", "LinearRegression"), ")\x81}b.")));
    expect(result.verdict).toBe("unrecognised");
    expect(result.findings).toMatchObject([{ risk: "unrecognised", qualified: "sklearn.linear_model._base.LinearRegression" }]);
  });
  it("reports an unresolvable STACK_GLOBAL as unrecognised, not as clean", () => {
    const result = scanModelFile(file("m.pkl", bytes(PROTO(4), [0x4b, 1], [0x4b, 2], STACK_GLOBAL, STOP)));
    expect(result.verdict).toBe("unrecognised");
    expect(result.findings[0]!.qualified).toBe("<unresolved STACK_GLOBAL>");
  });
  it("puts a dangerous import ahead of expected ones in a mixed file", () => {
    const result = scanModelFile(file("m.ckpt", bytes(PROTO(2), GLOBAL("collections", "OrderedDict"), GLOBAL("builtins", "eval"), GLOBAL("base64", "b64decode"), STOP)));
    expect(result.verdict).toBe("dangerous");
    expect(result.findings.map(item => item.qualified)).toEqual(["builtins.eval", "base64.b64decode"]);
  });

  describe("formats that are not pickle", () => {
    const header = Buffer.from('{"w":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}');
    const safetensors = bytes(le(header.length, 8), header, [0, 0, 0, 0]);
    it("safetensors: no code execution possible in this format", () => {
      const result = scanModelFile(file("model.safetensors", safetensors));
      expect(result).toMatchObject({ verdict: "not-pickle", format: "safetensors" });
      expect(result.summary).toContain("no code execution possible in this format");
    });
    it("gguf: not a pickle, but does not claim more than that", () => {
      const result = scanModelFile(file("m.gguf", bytes("GGUF", le(3, 4), le(0, 8), le(0, 8))));
      expect(result).toMatchObject({ verdict: "not-pickle", format: "gguf" });
      expect(result.summary).not.toContain("no code execution possible");
      expect(result.summary).toContain("not a pickle format");
    });
    it("onnx is recognised by extension, tflite by magic", () => {
      expect(scanModelFile(file("m.onnx", bytes([0x08, 0x07]))).verdict).toBe("not-pickle");
      expect(scanModelFile(file("m.tflite", bytes([0x1c, 0, 0, 0], "TFL3", [0, 0, 0, 0]))).verdict).toBe("not-pickle");
    });
    it("a .safetensors file with garbage in it is not vouched for", () => {
      const result = scanModelFile(file("bad.safetensors", bytes("not a safetensors header at all")));
      expect(result.verdict).toBe("not-scanned");
    });
    it("a pickle renamed .safetensors is scanned as a pickle and called out", () => {
      const result = scanModelFile(file("model.safetensors", protocol4System));
      expect(result.verdict).toBe("dangerous");
      expect(result.warnings.join(" ")).toContain("extension says safetensors but the content is pickle");
    });
    it("keras files are not scanned, with the reason", () => {
      const result = scanModelFile(file("m.h5", bytes("\x89HDF\r\n\x1a\n")));
      expect(result.verdict).toBe("not-scanned");
      expect(result.summary).toContain("Lambda");
    });
    it("an unrelated .bin is not scanned rather than called clean", () => {
      expect(scanModelFile(file("tokenizer.bin", bytes("just some bytes"))).verdict).toBe("not-scanned");
    });
  });

  describe("zip containers", () => {
    it("scans archive/data.pkl in a torch-style zip, stored or deflated", () => {
      for (const deflate of [false, true]) {
        const zip = makeZip([{ name: "archive/data.pkl", data: protocol4System, deflate }, { name: "archive/version", data: Buffer.from("3\n") }, { name: "archive/data/0", data: Buffer.alloc(64) }]);
        const result = scanModelFile(file("model.pt", zip));
        expect(result).toMatchObject({ verdict: "dangerous", format: "pytorch-zip" });
        expect(result.findings[0]).toMatchObject({ qualified: "os.system", member: "archive/data.pkl" });
      }
    });
    it("a benign torch zip comes back with nothing dangerous found", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: benignTorch, deflate: true }, { name: "archive/data/0", data: Buffer.alloc(16) }]);
      expect(scanModelFile(file("m.pth", zip))).toMatchObject({ verdict: "none-found", complete: true, expectedImports: 3 });
    });
    it("scans every entry with a pickle name, including a second one hidden in another folder", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: benignTorch }, { name: "extra/other.pkl", data: protocol0System }]);
      const result = scanModelFile(file("m.pt", zip));
      expect(result.verdict).toBe("dangerous");
      expect(result.findings[0]!.member).toBe("extra/other.pkl");
    });
    it("warns about member names that would escape a folder, and never extracts", () => {
      const zip = makeZip([{ name: "../../evil.pkl", data: benignTorch }, { name: "/etc/x.pkl", data: benignTorch }]);
      const result = scanModelFile(file("m.pt", zip));
      expect(result.warnings.filter(text => text.includes("would escape"))).toHaveLength(2);
      expect(result.verdict).toBe("none-found");
    });
    it("does not inflate a zip bomb past the limit", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: Buffer.alloc(8 * 1024 * 1024), deflate: true }]);
      const result = scanModelFile(file("bomb.pt", zip), { maxInflatedBytes: 1024 * 1024 });
      expect(result.verdict).toBe("not-scanned");
      expect(result.complete).toBe(false);
      expect(result.summary).toMatch(/limit|zip bomb/);
    });
    it("does not trust a declared size that is smaller than the real one", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: Buffer.alloc(8 * 1024 * 1024), deflate: true, declaredSize: 10 }]);
      expect(scanModelFile(file("liar.pt", zip), { maxInflatedBytes: 1024 * 1024 }).verdict).toBe("not-scanned");
    });
    it("stops at a total decompression budget across members", () => {
      const zip = makeZip([1, 2, 3].map(index => ({ name: `a${index}/data.pkl`, data: Buffer.concat([benignTorch, Buffer.alloc(600 * 1024)]), deflate: true })));
      const result = scanModelFile(file("m.pt", zip), { maxTotalInflatedBytes: 1024 * 1024 });
      expect(result.complete).toBe(false);
    });
    it("limits how many members are read", () => {
      const zip = makeZip(Array.from({ length: 5 }, (_, index) => ({ name: `d${index}/data.pkl`, data: benignTorch })));
      const result = scanModelFile(file("m.pt", zip), { maxMembers: 2 });
      expect(result.complete).toBe(false);
      expect(result.summary).toContain("more than 2");
    });
    it("handles a damaged zip without throwing", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: protocol0System }]);
      for (const cut of [4, 30, zip.length - 30, zip.length - 10, zip.length - 1]) {
        const result = scanModelFile(file("cut.pt", zip.subarray(0, cut)));
        expect(["not-scanned", "none-found", "dangerous"]).toContain(result.verdict);
      }
      expect(scanModelFile(file("noeocd.pt", bytes("PK\x03\x04", Buffer.alloc(100)))).verdict).toBe("not-scanned");
    });
    it("refuses a central directory that claims to be larger than the limit", () => {
      const zip = makeZip([{ name: "a.pkl", data: benignTorch }]);
      expect(() => listZip(bufferBacking(zip), { maxDirectoryBytes: 8 })).toThrow(/limit/);
    });
    it("a member whose local header is missing is reported, not followed", () => {
      const zip = makeZip([{ name: "archive/data.pkl", data: protocol0System }]);
      zip.writeUInt32LE(0, 0);
      const result = scanModelFile(file("m.pt", zip));
      expect(result.verdict).toBe("not-scanned");
    });
  });

  describe("numpy", () => {
    it("object arrays carry a pickle that is scanned", () => {
      const result = scanModelFile(file("a.npy", makeNpy("|O", protocol0System)));
      expect(result).toMatchObject({ verdict: "dangerous", format: "npy" });
    });
    it("numeric arrays have nothing to unpickle", () => {
      const result = scanModelFile(file("a.npy", makeNpy("<f4", Buffer.alloc(4))));
      expect(result.verdict).toBe("not-pickle");
      expect(result.summary).toContain("nothing is unpickled");
    });
    it("looks inside .npz members", () => {
      const zip = makeZip([{ name: "ok.npy", data: makeNpy("<f4", Buffer.alloc(4)) }, { name: "bad.npy", data: makeNpy("|O", protocol4System), deflate: true }]);
      const result = scanModelFile(file("bundle.npz", zip));
      expect(result).toMatchObject({ verdict: "dangerous", format: "npz" });
      expect(result.findings[0]!.member).toBe("bad.npy");
    });
    it("an .npz of numbers only is not a pickle", () => {
      expect(scanModelFile(file("n.npz", makeZip([{ name: "x.npy", data: makeNpy("<i8", Buffer.alloc(8)) }]))).verdict).toBe("not-pickle");
    });
  });

  it("scans gzip- and zlib-compressed pickles, within limits", () => {
    expect(scanModelFile(file("m.pkl", gzipSync(protocol0System))).verdict).toBe("dangerous");
    expect(scanModelFile(file("m.joblib", gzipSync(Buffer.alloc(4 * 1024 * 1024))), { maxInflatedBytes: 1024 * 1024 }).verdict).toBe("not-scanned");
  });

  describe("hostile and damaged input", () => {
    it("never throws on any prefix of a malicious or benign pickle", () => {
      for (const payload of [protocol0System, protocol4System, benignTorch]) {
        for (let cut = 0; cut <= payload.length; cut++) {
          const result = scanModelFile(file("t.pkl", payload.subarray(0, cut)));
          expect(["dangerous", "unrecognised", "none-found", "not-scanned"]).toContain(result.verdict);
        }
      }
    });
    it("reports a truncated pickle as incomplete and still returns what it saw", () => {
      const result = scanModelFile(file("t.pkl", protocol0System.subarray(0, protocol0System.length - 3)));
      expect(result.verdict).toBe("dangerous");
      expect(result.complete).toBe(false);
    });
    it("a clean prefix of a truncated file is incomplete, never a plain 'none found'", () => {
      const result = scanModelFile(file("t.pt", benignTorch.subarray(0, benignTorch.length - 6)));
      expect(result.complete).toBe(false);
      expect(result.summary).toContain("scan incomplete");
    });
    it("survives random bytes with every protocol header", () => {
      let seed = 12345;
      const random = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed & 0xff; };
      for (let round = 0; round < 300; round++) {
        const data = Buffer.from(Array.from({ length: 1 + (round % 200) }, random));
        if (round % 2) data[0] = 0x80;
        if (round % 4 === 1 && data.length > 1) data[1] = 2 + (round % 4);
        const result = scanModelFile(file("r.pkl", data));
        expect(result.verdict).toBeTruthy();
      }
    });
    it("a length field that claims exabytes is a truncation, not an allocation", () => {
      for (const payload of [bytes(PROTO(4), [0x8d], le(2 ** 52, 8), "x"), bytes(PROTO(4), [0x8e], Buffer.alloc(8, 0xff)), bytes(PROTO(2), [0x58], Buffer.alloc(4, 0xff), "x"), bytes(PROTO(2), [0x8b], Buffer.alloc(4, 0xff))]) {
        const scan = scanPickleStream(new Reader(bufferBacking(payload)));
        expect(scan.stop).toBeDefined();
      }
    });
    it("stops at the opcode limit and says so", () => {
      const payload = bytes(PROTO(2), Buffer.alloc(1000, 0x4e), STOP);
      const scan = scanPickleStream(new Reader(bufferBacking(payload)), { maxOpcodes: 100 });
      expect(scan.stop).toMatchObject({ kind: "limit" });
    });
    it("bounds the stack and the memo", () => {
      const deep = bytes(PROTO(2), Buffer.alloc(5000, 0x4e), STOP);
      expect(scanPickleStream(new Reader(bufferBacking(deep)), { maxStack: 100 }).stop).toMatchObject({ kind: "limit" });
      const memo = Buffer.concat(Array.from({ length: 500 }, (_, index) => bytes("N", [0x72], le(index, 4))));
      const scan = scanPickleStream(new Reader(bufferBacking(bytes(PROTO(2), memo, STOP))), { maxMemo: 10 });
      expect(scan.stop).toBeUndefined();
    });
    it("rejects import names that are not identifiers, so binary noise cannot pose as an import", () => {
      const scan = scanPickleStream(new Reader(bufferBacking(bytes(PROTO(2), "c\x00\xff\n\x01\n", STOP))));
      expect(scan.stop).toMatchObject({ kind: "malformed" });
      expect(scan.imports).toEqual([]);
    });
    it("rejects an unending text argument", () => {
      const scan = scanPickleStream(new Reader(bufferBacking(bytes(PROTO(2), "c", Buffer.alloc(100_000, 0x61)))));
      expect(scan.stop).toBeDefined();
    });
    it("handles an empty file, a directory and a missing file", () => {
      expect(scanModelFile(file("e.pkl", "")).verdict).toBe("not-scanned");
      expect(scanModelFile(tmp()).verdict).toBe("not-scanned");
      expect(scanModelFile(join(tmp(), "missing.pkl")).verdict).toBe("not-scanned");
    });
  });
});

describe("folders and SARIF", () => {
  const folder = () => {
    const dir = tmp();
    mkdirSync(join(dir, "models/sub"), { recursive: true });
    mkdirSync(join(dir, "node_modules/x"), { recursive: true });
    writeFileSync(join(dir, "models/bad.pkl"), protocol0System);
    writeFileSync(join(dir, "models/sub/good.pt"), benignTorch);
    writeFileSync(join(dir, "models/readme.txt"), "x");
    writeFileSync(join(dir, "node_modules/x/ignored.pkl"), protocol0System);
    symlinkSync(join(dir, "models/bad.pkl"), join(dir, "models/link.pkl"));
    return dir;
  };
  it("lists model files by relative path, skipping other files, node_modules and symlinks", () => {
    const report = scanModelPath(folder());
    expect(report.files.map(item => `${item.path}:${item.verdict}`)).toEqual(["models/bad.pkl:dangerous", "models/sub/good.pt:none-found"]);
    expect(report.skippedSymlinks).toBe(1);
  });
  it("emits one SARIF result per dangerous file", () => {
    const report = scanModelPath(folder());
    const sarif = modelScanToSarif(report.files, { toolVersion: "1.2.3" }) as { version: string; runs: Array<{ results: Array<{ ruleId: string; level: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }>; tool: { driver: { rules: Array<{ id: string }> } } }> };
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0]!.results).toHaveLength(1);
    expect(sarif.runs[0]!.results[0]).toMatchObject({ ruleId: "0/model-unsafe-deserialization", level: "error" });
    expect(sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe("models/bad.pkl");
    expect(sarif.runs[0]!.tool.driver.rules[0]!.id).toBe("0/model-unsafe-deserialization");
  });
});
