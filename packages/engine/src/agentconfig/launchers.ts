/**
 * Finds commands that fetch code which can change between runs: npx, bunx, pnpm dlx, yarn dlx, uvx, pipx run, docker run, and
 * a download piped into a shell. The command is split into words and compared with patterns. Nothing is run or looked up.
 */
export interface LauncherIssue { launcher: string; spec: string; reason: string; severity: "medium" | "high" }

const EXACT_SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
const EXACT_PY = /^==\s*\d+(?:\.\d+)*(?:[a-z]+\d*|\.post\d+|\.dev\d+)?$/i;
const SHELLS = /^(?:ba|z|da|k|c)?sh$|^pwsh$|^powershell$/;

/** Splits on spaces, keeping quoted parts together and breaking at shell separators, so `sh -c "npx -y x && ls"` yields words and separators. */
export function words(command: string): string[] {
  const out: string[] = [];
  let current = "", quote = "";
  const push = (): void => { if (current) out.push(current); current = ""; };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    if (quote) { if (ch === quote) quote = ""; else current += ch; continue; }
    if (ch === "\"" || ch === "'") { quote = ch; continue; }
    if (/\s/.test(ch)) { push(); continue; }
    if (ch === "|" || ch === ";" || ch === "&" || ch === "(" || ch === ")") { push(); out.push(ch); continue; }
    current += ch;
  }
  push();
  return out;
}

const base = (word: string): string => (word.split(/[\\/]/).pop() ?? word).replace(/\.(?:cmd|exe|bat)$/i, "");

function npmSpec(rest: string[], flagsWithValue: readonly string[]): string | undefined {
  for (let i = 0; i < rest.length; i++) {
    const word = rest[i]!;
    if (word === "|" || word === ";" || word === "&" || word === "(" || word === ")") return undefined;
    if (word === "-p" || word === "--package") return rest[i + 1];
    if (word.startsWith("--package=")) return word.slice(10);
    if (flagsWithValue.includes(word)) { i++; continue; }
    if (word.startsWith("-")) continue;
    return word;
  }
  return undefined;
}

function npmPinned(spec: string): string | undefined {
  if (/^(?:\.{0,2}\/|~\/|file:|[a-zA-Z]:[\\/])/.test(spec)) return undefined; // a local path is not fetched
  if (/^(?:git\+|github:|gitlab:|bitbucket:|https?:|git:)/.test(spec) || /^[\w.-]+\/[\w.-]+(?:#|$)/.test(spec)) return /#[0-9a-f]{40}$/i.test(spec) ? undefined : "a git or URL source that is not pinned to a commit";
  const at = spec.lastIndexOf("@");
  if (at <= 0) return "no version, so the newest release runs";
  const version = spec.slice(at + 1);
  return EXACT_SEMVER.test(version) ? undefined : version === "latest" ? "the tag latest, so the newest release runs" : `version "${version}" is not an exact version`;
}

function pythonSpec(rest: string[], fromFlags: readonly string[]): string | undefined {
  for (let i = 0; i < rest.length; i++) {
    const word = rest[i]!;
    if (word === "|" || word === ";" || word === "&") return undefined;
    const flag = fromFlags.find(name => word === name || word.startsWith(`${name}=`));
    if (flag) return word.includes("=") && word.startsWith(`${flag}=`) ? word.slice(flag.length + 1) : rest[i + 1];
    if (word.startsWith("-")) { if (["--python", "-p", "--with", "--index", "--index-url", "-i", "--extra-index-url"].includes(word)) i++; continue; }
    return word;
  }
  return undefined;
}

function pythonPinned(spec: string): string | undefined {
  if (/^(?:\.{0,2}\/|~\/|file:)/.test(spec)) return undefined;
  if (/^(?:git\+|https?:)/.test(spec)) return /@[0-9a-f]{40}(?:#|$)/i.test(spec) ? undefined : "a git or URL source that is not pinned to a commit";
  const eq = /(==[^\s,;]+)$/.exec(spec.replace(/\[[^\]]*\]/, ""));
  if (eq && EXACT_PY.test(eq[1]!)) return undefined;
  const at = /@([^\s]+)$/.exec(spec);
  if (at && /^\d+(?:\.\d+)*$/.test(at[1]!)) return undefined;
  return at?.[1] === "latest" ? "the tag latest, so the newest release runs" : "no exact version (use package==1.2.3)";
}

function dockerImage(rest: string[]): string | undefined {
  const flat = new Set(["-i", "-t", "-it", "-ti", "-d", "--rm", "--init", "--privileged", "--read-only", "--interactive", "--tty", "--detach", "--sig-proxy", "--no-healthcheck", "--oom-kill-disable", "-P", "--publish-all"]);
  for (let i = 0; i < rest.length; i++) {
    const word = rest[i]!;
    if (word === "|" || word === ";" || word === "&") return undefined;
    if (word.startsWith("-")) { if (!word.includes("=") && !flat.has(word) && !/^-[a-zA-Z]*[itd]+$/.test(word)) i++; continue; }
    return word;
  }
  return undefined;
}

function dockerPinned(image: string): string | undefined {
  if (image.includes("@sha256:")) return undefined;
  const last = image.split("/").pop()!;
  const colon = last.indexOf(":");
  if (colon < 0) return "no tag, so the tag latest is used";
  return last.slice(colon + 1) === "latest" ? "the tag latest" : undefined;
}

/** Every launcher problem in one command (the program and its arguments joined). */
export function launcherIssues(command: string, depth = 0): LauncherIssue[] {
  const found: LauncherIssue[] = [];
  if (depth > 3) return found;
  const ws = words(command.slice(0, 4000));
  for (let i = 0; i < ws.length; i++) {
    if (ws[i]!.length > 1 && /[\s|;&]/.test(ws[i]!)) { found.push(...launcherIssues(ws[i]!, depth + 1)); continue; } // a quoted script, as in sh -c "..."
    const word = base(ws[i]!).toLowerCase();
    const rest = ws.slice(i + 1);
    const issue = (launcher: string, spec: string, reason: string, severity: "medium" | "high" = "medium"): void => { found.push({ launcher, spec, reason, severity }); };
    if (word === "npx" || word === "bunx") {
      const spec = npmSpec(rest, ["--registry", "-c", "--call", "--cache", "--userconfig"]);
      const why = spec ? npmPinned(spec) : undefined;
      if (spec && why) issue(word, spec, why);
    } else if ((word === "pnpm" || word === "yarn") && rest[0] === "dlx") {
      const spec = npmSpec(rest.slice(1), []); const why = spec ? npmPinned(spec) : undefined;
      if (spec && why) issue(`${word} dlx`, spec, why);
    } else if (word === "npm" && (rest[0] === "exec" || rest[0] === "x")) {
      const spec = npmSpec(rest.slice(1), ["--registry"]); const why = spec ? npmPinned(spec) : undefined;
      if (spec && why) issue("npm exec", spec, why);
    } else if (word === "bun" && rest[0] === "x") {
      const spec = npmSpec(rest.slice(1), []); const why = spec ? npmPinned(spec) : undefined;
      if (spec && why) issue("bun x", spec, why);
    } else if (word === "uvx" || (word === "uv" && rest[0] === "tool" && rest[1] === "run")) {
      const spec = pythonSpec(word === "uvx" ? rest : rest.slice(2), ["--from"]); const why = spec ? pythonPinned(spec) : undefined;
      if (spec && why) issue(word === "uvx" ? "uvx" : "uv tool run", spec, why);
    } else if (word === "pipx" && rest[0] === "run") {
      const spec = pythonSpec(rest.slice(1), ["--spec"]); const why = spec ? pythonPinned(spec) : undefined;
      if (spec && why) issue("pipx run", spec, why);
    } else if (word === "docker" || word === "podman") {
      const run = rest.indexOf("run");
      if (run >= 0 && rest.slice(0, run).every(item => item.startsWith("-"))) {
        const image = dockerImage(rest.slice(run + 1)); const why = image ? dockerPinned(image) : undefined;
        if (image && why) issue(`${word} run`, image, why);
      }
    } else if (word === "curl" || word === "wget") {
      let j = i + 1;
      while (j < ws.length && ws[j] !== "|" && ws[j] !== ";" && ws[j] !== "&") j++;
      if (ws[j] === "|") {
        let k = j + 1;
        if (base(ws[k] ?? "") === "sudo") k++;
        if (SHELLS.test(base(ws[k] ?? "").toLowerCase())) issue(`${word} | ${base(ws[k]!)}`, word, "a download is run as a script without being reviewed", "high");
      }
    }
    // bash <(curl ...) and sh -c "$(curl ...)" forms
    if (SHELLS.test(word) && /(?:<\(|\$\()\s*(?:curl|wget)\b/.test(command) && !found.some(item => item.severity === "high")) issue(word, word, "a download is run as a script without being reviewed", "high");
  }
  return found;
}

/** The first issue in a program and its arguments, as a short sentence; used by the SBOM inventory. */
export function unpinnedLauncher(parts: readonly string[]): string | undefined {
  const issue = launcherIssues(parts.join(" "))[0];
  return issue ? `${issue.launcher} ${issue.spec}: ${issue.reason}` : undefined;
}
