import type { SinkCategory, SinkTag } from "./types.js";

/** Callee text patterns that end a source-to-sink walk. Name-based: a hint, not a proof. */
const SINKS: ReadonlyArray<{ category: SinkCategory; re: RegExp }> = [
  { category: "command", re: /(^|\.)(exec|execSync|execFile|execFileSync|spawn|spawnSync)$|^os\.(system|popen)$|^subprocess\.\w+$/ },
  { category: "code-eval", re: /^(eval|Function|exec|compile)$|^vm\.(runIn\w+|Script)$/ },
  { category: "sql", re: /(^|\.)(query|raw|queryRaw|\$queryRaw|\$executeRaw|execute|executemany|executescript)$/ },
  { category: "file", re: /(^|\.)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|sendFile|unlink|unlinkSync|rmSync|send_file|send_from_directory)$|^open$|^shutil\.\w+$|^os\.(remove|unlink|rename)$/ },
  { category: "network", re: /^(fetch|axios|got)$|(^|\.)(request|urlopen)$|^axios\.\w+$|^requests\.\w+$|^httpx\.\w+$/ },
  { category: "deserialize", re: /^pickle\.loads?$|^yaml\.(load|unsafe_load)$|^marshal\.loads?$|(^|\.)(unserialize|deserialize)$/ },
  { category: "template", re: /^render_template_string$|^(ejs|pug|handlebars)\.render$/ },
  { category: "redirect", re: /(^|\.)redirect$/ },
];

export function classifySink(calleeText: string): SinkTag | undefined {
  const text = calleeText.replace(/\s+/g, "");
  for (const { category, re } of SINKS) if (re.test(text)) return { category, text };
  return undefined;
}

/** Names that suggest an authentication, authorization or ownership check. */
export const AUTH_NAME = /auth|permission|owner|can[A-Z_]|may[A-Z_]|guard|require|login|session|verify|jwt|token|acl|policy|role|admin|belongs|is_?allowed|csrf|protect/i;
