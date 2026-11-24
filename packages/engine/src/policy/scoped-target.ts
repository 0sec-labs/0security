/**
 * Scope guard for a command that sends requests to a live target the operator names (`0security scan --target-url`).
 *
 * - Loopback and private networks (RFC 1918, unique-local IPv6, 100.64.0.0/10 shared space such as a tailnet) are allowed
 *   when the host is in the scope file or typed with `acknowledge`.
 * - A public host needs `acknowledge` with the exact host typed, and, when a scope file is given, a line for it there too.
 * - Link-local and cloud metadata addresses are refused always.
 * - `ZERO_ENTERPRISE` refuses every target that is not loopback.
 *
 * The host is resolved once and every answer is checked. The classifier matches the one in `0 probe`, so that command can
 * import `classifyAddress` from here.
 */
import { lookup as dnsLookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { assertEgressAllowed } from "./enterprise.js";

export type NetworkClass = "loopback" | "private" | "public";
export type ResolveHost = (hostname: string) => Promise<string[]>;

export class ScopedTargetError extends Error {
  constructor(message: string) { super(message); this.name = "ScopedTargetError"; }
}

export interface ScopedTarget {
  /** The URL as named by the operator, without a fragment. */
  url: string;
  /** `host` or `host:port`, as in the URL. */
  host: string;
  hostname: string;
  addresses: string[];
  network: NetworkClass;
  /** What authorised the run: the scope file, the typed host, or both. */
  authorisedBy: Array<"scope-file" | "acknowledged">;
}

const blocked = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["169.254.0.0", 16], ["224.0.0.0", 4], ["240.0.0.0", 4], ["100.100.100.200", 32], ["192.0.0.192", 32],
] as const) blocked.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [["::", 128], ["fe80::", 10], ["ff00::", 8], ["fd00:ec2::", 32]] as const) blocked.addSubnet(address, prefix, "ipv6");
const loopback = new BlockList();
loopback.addSubnet("127.0.0.0", 8, "ipv4");
loopback.addAddress("::1", "ipv6");
const privateNet = new BlockList();
for (const [address, prefix] of [["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16], ["100.64.0.0", 10]] as const) privateNet.addSubnet(address, prefix, "ipv4");
privateNet.addSubnet("fc00::", 7, "ipv6");

/** The IPv4 inside an IPv4-mapped IPv6 address (`::ffff:a.b.c.d` or `::ffff:7f00:1`), or the address itself. */
function expandV6(address: string): number[] | undefined {
  let text = address.toLowerCase().split("%")[0]!;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) { const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number]; text = text.replace(dotted[0], `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`); }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array<string>(Math.max(fill, 0)).fill("0"), ...tail].map(group => parseInt(group, 16));
  return groups.length === 8 && groups.every(group => Number.isInteger(group) && group >= 0 && group <= 0xffff) ? groups : undefined;
}

function unmap(address: string): string {
  // IPv4-mapped (::ffff:0:0/96), IPv4-compatible and NAT64 (64:ff9b::/96) addresses, in any spelling, are judged by the IPv4 inside.
  if (isIP(address) === 6) {
    const g = expandV6(address);
    if (g && ((g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) || (g.slice(0, 6).every(x => x === 0) && (g[6]! > 0 || g[7]! > 1)) || (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every(x => x === 0)))) return `${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}`;
  }
  const lower = address.toLowerCase();
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (dotted) return dotted[1]!;
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex) { const high = parseInt(hex[1]!, 16), low = parseInt(hex[2]!, 16); return `${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`; }
  return address;
}

/** Where an IP address sits. `blocked` is never allowed. */
export function classifyAddress(raw: string): NetworkClass | "blocked" {
  const address = unmap(raw.replace(/^\[|\]$/g, ""));
  const family = isIP(address);
  if (!family) return "blocked";
  const kind = family === 4 ? "ipv4" : "ipv6";
  if (blocked.check(address, kind)) return "blocked";
  if (loopback.check(address, kind)) return "loopback";
  if (privateNet.check(address, kind)) return "private";
  return "public";
}

const defaultResolve: ResolveHost = async hostname => (await dnsLookup(hostname, { all: true })).map(entry => entry.address);
const bareHost = (hostname: string) => hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
const rank: Record<NetworkClass, number> = { loopback: 0, private: 1, public: 2 };
const MAX_SCOPE_LINES = 1000;

/**
 * Hosts from a scope file: one per line as `host` or `host:port`, `#` starts a comment. A line with a scheme, a path or a
 * wildcard is an error, so a scope file never allows more than it says.
 */
export function parseScopeFile(text: string): string[] {
  const hosts: string[] = [];
  const lines = text.split(/\r?\n/);
  if (lines.length > MAX_SCOPE_LINES) throw new ScopedTargetError(`The scope file has more than ${MAX_SCOPE_LINES} lines.`);
  for (const [index, raw] of lines.entries()) {
    const line = raw.replace(/#.*$/, "").trim().toLowerCase();
    if (!line) continue;
    if (!/^(?:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]+\])(?::\d{1,5})?$/.test(line)) throw new ScopedTargetError(`Scope file line ${index + 1} is not a host or host:port. Write one host per line, with no scheme, path or wildcard.`);
    hosts.push(line);
  }
  return hosts;
}

export interface ScopedTargetOptions {
  /** Hosts from the scope file. Undefined when no scope file was given. */
  scopeHosts?: readonly string[];
  /** The host typed by the operator. Must equal the URL's host (`host:port` when the URL has a port) or its hostname. */
  acknowledge?: string;
  /** Replaces DNS, for tests. */
  resolve?: ResolveHost;
  env?: NodeJS.ProcessEnv;
}

/**
 * Decide whether the target may receive requests, before any is sent. Throws `ScopedTargetError` (or, under
 * `ZERO_ENTERPRISE` for a target that is not loopback, `EnterpriseEgressError`) with the way forward in the message.
 */
export async function assertScopedTarget(input: URL | string, options: ScopedTargetOptions = {}): Promise<ScopedTarget> {
  let url: URL;
  try { url = typeof input === "string" ? new URL(input) : new URL(input.href); } catch { throw new ScopedTargetError(`'${String(input)}' is not a URL.`); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new ScopedTargetError("The target must be an http or https URL.");
  if (url.username || url.password) throw new ScopedTargetError("The target URL must not contain a user name or password.");
  url.hash = "";
  const hostname = bareHost(url.hostname);
  const host = url.host.toLowerCase();
  const typed = options.acknowledge === undefined ? undefined : options.acknowledge.trim().toLowerCase();
  if (typed !== undefined && typed !== host && typed !== hostname) throw new ScopedTargetError(`The acknowledged host must be exactly the host being tested (${host}), not '${options.acknowledge}'.`);

  let addresses: string[];
  if (isIP(hostname)) addresses = [hostname];
  else {
    try { addresses = await (options.resolve ?? defaultResolve)(hostname); }
    catch (error) { throw new ScopedTargetError(`Could not resolve ${hostname}: ${error instanceof Error ? error.message : String(error)}`); }
    if (!addresses.length) throw new ScopedTargetError(`Could not resolve ${hostname}: no addresses.`);
  }
  let network: NetworkClass = "loopback";
  for (const address of addresses) {
    const kind = classifyAddress(address);
    if (kind === "blocked") throw new ScopedTargetError(`Refused: ${hostname} is or resolves to ${address}, a link-local, metadata or otherwise reserved address. These are never tested.`);
    if (rank[kind] > rank[network]) network = kind;
  }
  // The operator-named-destination rule: ZERO_ENTERPRISE keeps traffic on this machine.
  if (network !== "loopback") assertEgressAllowed(host, options.env);

  const listed = options.scopeHosts?.some(entry => entry === host || entry === hostname) ?? false;
  if (options.scopeHosts && !listed && network === "public") throw new ScopedTargetError(`Refused: ${host} is not listed in the scope file.`);
  if (network === "public" && typed === undefined) throw new ScopedTargetError(`Refused: ${hostname} is a public host (${addresses.join(", ")}). Test only systems you own or are authorised to test. If that is you, add --acknowledge-host ${host}.`);
  if (!listed && typed === undefined) throw new ScopedTargetError(options.scopeHosts ? `Refused: ${host} is not listed in the scope file. Add it, or pass --acknowledge-host ${host}.` : `Refused: name the systems you may test. Pass --scope-file with a line for ${host}, or --acknowledge-host ${host}.`);
  const authorisedBy: ScopedTarget["authorisedBy"] = [...(listed ? ["scope-file" as const] : []), ...(typed !== undefined ? ["acknowledged" as const] : [])];
  return { url: url.href, host, hostname, addresses, network, authorisedBy };
}

/** One line for the log and the report: what was tested and on what authority. */
export function describeScopedTarget(target: ScopedTarget): string {
  return `${target.host} (${target.network} network, ${target.addresses.join(", ")}), authorised by ${target.authorisedBy.map(by => by === "scope-file" ? "the scope file" : `the typed host ${target.host}`).join(" and ")}`;
}
