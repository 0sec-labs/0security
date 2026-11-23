/**
 * Linux bubblewrap (`bwrap`) arguments. The process starts in an empty root: only what is bound below exists for it, so
 * the user's home, ~/.0, ~/.ssh and other repositories are not hidden by a rule, they are absent. All namespaces are
 * unshared; the network namespace is shared back only when the policy allows the network.
 *
 * Without `process`, only the allowlisted program files and the system library folders are mounted, so nothing else can
 * be started. With `process`, the system program folders are mounted read-only.
 */
import fs from "node:fs";
import type { ResolvedSandbox } from "./policy.js";

/** What the generator needs to know about the host layout (top-level folders may be symlinks into /usr). */
export interface HostLayout { kind(path: string): "symlink" | "dir" | "file" | null; readlink(path: string): string | null }

export const hostLayout: HostLayout = {
  kind(p) { try { const s = fs.lstatSync(p); return s.isSymbolicLink() ? "symlink" : s.isDirectory() ? "dir" : "file"; } catch { return null; } },
  readlink(p) { try { return fs.readlinkSync(p); } catch { return null; } },
};

const TOP_PROGRAM_DIRS = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"];
const TOP_LIBRARY_DIRS = ["/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec", "/lib", "/lib32", "/lib64", "/libx32"];
const ETC_ALWAYS = ["/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/alternatives"];
const ETC_NETWORK = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl", "/etc/ca-certificates", "/etc/pki"];

export interface BwrapOptions { cwd: string; layout?: HostLayout }

/** Arguments for `bwrap` up to and including the `--` that precedes the program. */
export function bwrapArgs(policy: ResolvedSandbox, options: BwrapOptions): string[] {
  const layout = options.layout ?? hostLayout;
  const args = ["--die-with-parent", "--new-session", "--unshare-all", ...(policy.network ? ["--share-net"] : []), "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev"];
  const bound = new Set<string>();
  const ro = (p: string) => { if (!bound.has(`ro:${p}`)) { bound.add(`ro:${p}`); args.push("--ro-bind", p, p); } };
  const mountDir = (p: string) => {
    const kind = layout.kind(p);
    if (kind === "dir") ro(p);
    else if (kind === "symlink") { const target = layout.readlink(p); if (target) args.push("--symlink", target, p); }
  };

  for (const p of policy.process ? TOP_PROGRAM_DIRS : TOP_LIBRARY_DIRS) mountDir(p);
  for (const p of [...ETC_ALWAYS, ...(policy.network ? ETC_NETWORK : [])]) if (layout.kind(p) !== null) ro(p);
  if (!policy.process) for (const p of policy.execAllow) if (layout.kind(p) !== null) ro(p);

  ro(policy.extensionDir);
  for (const p of policy.readPaths) ro(p);
  args.push("--bind", policy.scratchDir, policy.scratchDir);
  for (const p of policy.writePaths) args.push("--bind", p, p);
  args.push("--chdir", options.cwd, "--");
  return args;
}
