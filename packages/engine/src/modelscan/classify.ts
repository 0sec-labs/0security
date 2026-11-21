/**
 * Decides what a pickle's reference to `module.name` means. Importing a callable is what makes a pickle dangerous:
 * the unpickler then calls it with attacker-chosen arguments. Three answers: dangerous (a way to run commands, load
 * code, touch the network or the file system, or unpickle again), expected (what ML libraries write into checkpoints)
 * and unrecognised (not on either list: lower severity, because libraries such as scikit-learn legitimately pickle
 * their own classes, but nothing here vouches for it).
 */
export type ImportRisk = "dangerous" | "expected" | "unrecognised";
export interface Classification { risk: ImportRisk; reason: string }

const ROOT_REASONS: Record<string, string> = {
  os: "runs commands and edits the file system", posix: "runs commands (os.system)", nt: "runs commands (os.system)", subprocess: "runs commands",
  commands: "runs commands", popen2: "runs commands", pty: "spawns a shell", multiprocessing: "starts processes", asyncio: "can start subprocesses",
  shutil: "copies, moves and deletes files", socket: "opens network connections", requests: "makes network requests", urllib: "makes network requests",
  urllib2: "makes network requests", urllib3: "makes network requests", httplib: "makes network requests", ftplib: "makes network requests",
  smtplib: "sends network traffic", telnetlib: "opens network connections", socketserver: "opens network listeners", xmlrpc: "makes network requests",
  webbrowser: "opens a browser or URL", ctypes: "calls native code", importlib: "imports arbitrary modules", runpy: "runs a module or file as code",
  code: "compiles and runs code", codeop: "compiles code", types: "builds functions and code objects", marshal: "loads code objects", timeit: "runs code strings",
  pdb: "runs code strings", bdb: "runs code strings", cProfile: "runs code strings", profile: "runs code strings", trace: "runs code strings", pkgutil: "imports arbitrary modules",
  pydoc: "can run commands or import modules", platform: "can run commands", sys: "reaches the interpreter internals (sys.modules)", pip: "installs packages",
  setuptools: "runs build code", distutils: "runs build code", venv: "creates environments and runs code", ensurepip: "installs packages", shelve: "unpickles again",
  pickle: "unpickles again (nested deserialization)", _pickle: "unpickles again (nested deserialization)", cPickle: "unpickles again (nested deserialization)",
  dill: "unpickles code (nested deserialization)", cloudpickle: "unpickles code (nested deserialization)",
};
const BUILTIN_MODULES = new Set(["builtins", "__builtin__"]);
const DANGEROUS_BUILTINS = new Set(["eval", "exec", "compile", "__import__", "open", "getattr", "setattr", "delattr", "globals", "locals", "vars", "input", "breakpoint", "exit", "quit", "execfile", "reload", "file", "apply"]);
const SAFE_BUILTINS = new Set(["set", "frozenset", "list", "dict", "tuple", "int", "float", "complex", "bool", "str", "bytes", "bytearray", "slice", "range", "object", "long", "unicode", "type", "NoneType", "Ellipsis", "NotImplemented"]);
const DANGEROUS_EXACT = new Set([
  "torch.load", "torch.jit.load", "torch.serialization.load", "torch.storage._load_from_bytes", "torch.hub.load", "torch.hub.load_state_dict_from_url",
  "numpy.load", "numpy.lib.npyio.load", "numpy.testing._private.utils.runstring", "pandas.read_pickle", "pandas.eval", "pandas.core.computation.eval.eval",
  "joblib.load", "joblib.numpy_pickle.load", "sklearn.externals.joblib.load", "operator.attrgetter", "operator.methodcaller", "functools.reduce",
  "numpy.lib.utils.safe_eval", "keras.models.load_model", "tensorflow.keras.models.load_model", "tensorflow.python.keras.models.load_model",
]);
const DANGEROUS_PREFIXES = ["torch.hub.", "numpy.distutils.", "numpy.f2py.", "pandas.io.pickle.", "http.client", "http.server", "asyncio.subprocess"];
const DANGEROUS_ANYWHERE = new Set(["eval", "exec", "execfile", "system", "popen", "__import__"]);
/** `posixpath.os`, `pandas.io.common.sys` and the like reach a dangerous module through a re-export. */
const REEXPORTED_MODULES = new Set(["os", "sys", "subprocess", "builtins", "__builtin__", "importlib", "socket", "shutil", "ctypes", "posix", "nt", "runpy", "pty", "pickle", "marshal"]);
const DECODERS = new Set(["base64", "binascii", "codecs", "zlib", "bz2", "lzma", "gzip"]);

const EXPECTED_EXACT = new Set([
  "collections.OrderedDict", "collections.defaultdict", "collections.deque", "collections.Counter", "collections.namedtuple",
  "torch._utils._rebuild_tensor", "torch._utils._rebuild_tensor_v2", "torch._utils._rebuild_tensor_v3", "torch._utils._rebuild_parameter", "torch._utils._rebuild_parameter_with_state",
  "torch._utils._rebuild_qtensor", "torch._utils._rebuild_sparse_tensor", "torch._utils._rebuild_meta_tensor_no_storage", "torch._utils._rebuild_wrapper_subclass",
  "torch._tensor._rebuild_from_type_v2", "torch._utils._rebuild_device_tensor_from_numpy", "torch._utils._rebuild_xla_tensor", "torch.Size", "torch.device", "torch.Tensor",
  "torch.nn.parameter.Parameter", "torch.nn.parameter.UninitializedParameter", "torch.serialization._get_layout", "torch.storage.TypedStorage", "torch.storage.UntypedStorage",
  "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct", "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "numpy.ndarray", "numpy.dtype",
  "numpy.core.numeric._frombuffer", "numpy._core.numeric._frombuffer", "numpy.random.mtrand.RandomState",
  "numpy.random._pickle.__randomstate_ctor", "numpy.random._pickle.__generator_ctor", "numpy.random._pickle.__bit_generator_ctor", "numpy.random._mt19937.MT19937",
  "_codecs.encode", "copy_reg._reconstructor", "copyreg._reconstructor", "copyreg.__newobj__", "copy_reg.__newobj__", "datetime.datetime", "datetime.date", "datetime.timedelta",
  "decimal.Decimal", "fractions.Fraction", "joblib.numpy_pickle.NumpyArrayWrapper", "joblib.numpy_pickle.NDArrayWrapper", "joblib.numpy_pickle.ZNDArrayWrapper",
]);
const EXPECTED_PREFIXES = ["torch.nn.modules.", "torch.optim.", "torch.nn.init."];
const NUMPY_SCALARS = /^numpy\.(?:u?int(?:8|16|32|64)?|float(?:16|32|64)?|complex(?:64|128)?|bool_?|str_|bytes_|object_|longlong|ulonglong|intc|uintc|intp|uintp|double|single|half)$/;
const TORCH_STORAGE = /^torch\.(?:Float|Double|Half|BFloat16|Long|Int|Short|Char|Byte|Bool|ComplexFloat|ComplexDouble|QInt8|QUInt8|QInt32)Storage$/;
const TORCH_DTYPE = /^torch\.(?:float(?:16|32|64)?|double|half|bfloat16|int(?:8|16|32|64)?|uint8|long|short|bool|complex(?:64|128)|strided|contiguous_format|preserve_format|channels_last)$/;

export function classifyImport(moduleName: string, name: string): Classification {
  const module = moduleName.trim();
  const full = `${module}.${name}`;
  const root = module.split(".")[0]!;
  const firstName = name.split(".")[0]!;
  if (BUILTIN_MODULES.has(module)) {
    if (DANGEROUS_BUILTINS.has(firstName)) return { risk: "dangerous", reason: `${firstName} runs or loads arbitrary code` };
    if (SAFE_BUILTINS.has(firstName)) return { risk: "expected", reason: "plain built-in type" };
  }
  if (DANGEROUS_EXACT.has(full)) return { risk: "dangerous", reason: "loads or evaluates code or nested pickles" };
  if (DANGEROUS_PREFIXES.some(prefix => full.startsWith(prefix))) return { risk: "dangerous", reason: "runs code, builds, or touches the network" };
  const rootReason = Object.hasOwn(ROOT_REASONS, root) ? ROOT_REASONS[root] : undefined;
  if (rootReason && !(root === "types" && /^(?:NoneType|SimpleNamespace)$/.test(name))) return { risk: "dangerous", reason: rootReason };
  if (DANGEROUS_ANYWHERE.has(firstName)) return { risk: "dangerous", reason: `${firstName} runs code or commands` };
  if (name.split(".").some(part => REEXPORTED_MODULES.has(part)) && !REEXPORTED_MODULES.has(root)) return { risk: "dangerous", reason: "reaches a dangerous module through a re-export" };
  if (EXPECTED_EXACT.has(full) || EXPECTED_PREFIXES.some(prefix => full.startsWith(prefix)) || NUMPY_SCALARS.test(full) || TORCH_STORAGE.test(full) || TORCH_DTYPE.test(full)) {
    return { risk: "expected", reason: "common in ML checkpoints" };
  }
  if (DECODERS.has(root)) return { risk: "unrecognised", reason: "decodes data, which payloads use to hide what they run" };
  return { risk: "unrecognised", reason: "not on the list of imports ML libraries normally write" };
}
