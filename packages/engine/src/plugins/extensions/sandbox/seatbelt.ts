/**
 * macOS Seatbelt profile for `sandbox-exec`. Deny by default. Every path that comes from the policy is passed as a
 * `-D name=value` parameter and read in the profile with `(param "name")`, so a path can never change the profile text.
 *
 * Apple marks `sandbox-exec` deprecated. It still works and the system itself uses the same mechanism, but Apple can
 * remove it. This profile is a guard rail for extension code, not a container.
 */
import path from "node:path";
import type { ResolvedSandbox } from "./policy.js";

/** Read-only locations an interpreter needs to start, package-manager folders included (a Homebrew node loads its libraries from there). Constants, never taken from input. */
const SYSTEM_READ = ["/usr/lib", "/usr/share", "/System", "/Library/Frameworks", "/Library/Preferences/Logging", "/private/var/db/dyld", "/private/var/db/timezone", "/private/etc/ssl", "/opt/homebrew", "/usr/local"];
const SYSTEM_FILES = ["/", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/private/etc/hosts", "/private/etc/resolv.conf", "/private/etc/localtime", "/private/etc/shells", "/private/etc/protocols", "/private/etc/services"];
/** Granted only when the extension declares `process`: programs from the usual system and package-manager folders. */
const PROGRAM_DIRS = ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/libexec", "/opt/homebrew", "/usr/local"];
/** The macOS /bin/sh starts /bin/bash as its variant, so a shell interpreter needs both. */
const SHELL_VARIANTS = ["/bin/bash", "/bin/sh"];

export interface SeatbeltProfile { profile: string; params: Record<string, string> }

const q = (s: string): string => JSON.stringify(s);

export function seatbeltProfile(policy: ResolvedSandbox): SeatbeltProfile {
  const params: Record<string, string> = { EXT_DIR: policy.extensionDir, SCRATCH: policy.scratchDir };
  const named = (prefix: string, paths: readonly string[]): string[] => paths.map((p, i) => { const key = `${prefix}${i}`; params[key] = p; return `(subpath (param ${q(key)}))`; });
  const reads = named("READ", policy.readPaths);
  const writes = named("WRITE", policy.writePaths);
  const execs = policy.execAllow.map((p, i) => { const key = `EXEC${i}`; params[key] = p; return `(literal (param ${q(key)}))`; });

  // Metadata (stat) is allowed everywhere so path lookups work, except below the home folder: a process there could
  // otherwise learn which files exist (for example ~/.ssh/id_ed25519). The folders that lead to an allowed path stay visible.
  const homeRules: string[] = [];
  if (policy.home) {
    params.HOME = policy.home;
    homeRules.push('(deny file-read-metadata (subpath (param "HOME")))');
    const ancestors = new Set<string>();
    for (const p of [policy.extensionDir, policy.scratchDir, ...policy.readPaths, ...policy.writePaths, ...policy.execAllow]) {
      if (!(p === policy.home || p.startsWith(policy.home + path.sep))) continue;
      for (let a = path.dirname(p); a === policy.home || a.startsWith(policy.home + path.sep); a = path.dirname(a)) { ancestors.add(a); if (a === policy.home) break; }
    }
    [...ancestors].sort().forEach((a, i) => { params[`ANCESTOR${i}`] = a; homeRules.push(`(allow file-read-metadata (literal (param "ANCESTOR${i}")))`); });
  }

  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow signal (target self))",
    "(allow sysctl-read)",
    "(allow file-read-metadata)",
    ...homeRules,
    `(allow file-read* ${SYSTEM_READ.map(p => `(subpath ${q(p)})`).join(" ")} ${SYSTEM_FILES.map(p => `(literal ${q(p)})`).join(" ")})`,
    `(allow file-read* (subpath (param "EXT_DIR")) (subpath (param "SCRATCH")) ${[...reads, ...writes].join(" ")})`,
    `(allow file-write* (subpath (param "SCRATCH")) (literal "/dev/null") ${writes.join(" ")})`,
    '(allow mach-lookup (global-name "com.apple.system.logger") (global-name "com.apple.logd") (global-name "com.apple.system.notification_center") (global-name "com.apple.CoreServices.coreservicesd"))',
    '(allow process-exec (subpath (param "EXT_DIR")))',
  ];
  for (const shell of SHELL_VARIANTS) if (policy.execAllow.some(p => /(^|\/)(bash|sh|zsh)$/.test(p))) lines.push(`(allow process-exec (literal ${q(shell)})) (allow file-read* (literal ${q(shell)}))`);
  if (execs.length) lines.push(`(allow process-exec ${execs.join(" ")})`, `(allow file-read* ${execs.join(" ")})`);
  if (policy.process) lines.push(`(allow process-exec ${PROGRAM_DIRS.map(p => `(subpath ${q(p)})`).join(" ")})`, `(allow file-read* ${PROGRAM_DIRS.map(p => `(subpath ${q(p)})`).join(" ")})`);
  if (policy.network) lines.push('(allow network*)', '(allow mach-lookup (global-name "com.apple.dnssd.service") (global-name "com.apple.SystemConfiguration.configd") (global-name "com.apple.networkd") (global-name "com.apple.trustd") (global-name "com.apple.SecurityServer"))');
  return { profile: lines.join("\n") + "\n", params };
}

/** Arguments for `sandbox-exec` up to (not including) the program to run. */
export function seatbeltArgs(p: SeatbeltProfile): string[] {
  const args = ["-p", p.profile];
  for (const [k, v] of Object.entries(p.params)) args.push("-D", `${k}=${v}`);
  return args;
}
