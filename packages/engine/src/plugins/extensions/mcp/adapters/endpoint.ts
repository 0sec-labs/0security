/**
 * The single place a remote MCP endpoint is judged. HTTPS only (plain http only to a literal loopback name, for local
 * servers), no URL credentials or fragment, and the name must resolve to public addresses only: a name that points at a
 * private, loopback, link-local or cloud-metadata address is refused, also when only one of several answers does.
 */
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

export type Resolver = (hostname: string) => Promise<readonly string[]>;
export const systemResolver: Resolver = async host => (await lookup(host, { all: true, verbatim: true })).map(a => a.address);

const blockedIpv4 = new BlockList();
for (const [a, p] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blockedIpv4.addSubnet(a, p, "ipv4");

const globalIpv6 = new BlockList();
globalIpv6.addSubnet("2000::", 3, "ipv6");

const blockedIpv6 = new BlockList();
for (const [a, p] of [["2001::", 23], ["2001:db8::", 32], ["2002::", 16]] as const) {
  blockedIpv6.addSubnet(a, p, "ipv6");
}

function parseIpv6Hextets(address: string): number[] | null {
  let body = address;
  const lastColon = body.lastIndexOf(":");
  let trailing: number[] = [];
  if (lastColon !== -1 && body.slice(lastColon + 1).includes(".")) {
    const octets = body.slice(lastColon + 1).split(".").map(n => Number(n));
    if (octets.length !== 4 || octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    trailing = [(octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!];
    body = body.slice(0, body[lastColon - 1] === ":" ? lastColon + 1 : lastColon);
  }
  const halves = body.split("::");
  if (halves.length > 2) return null;
  const parsePart = (part: string) => part === "" ? [] : part.split(":").map(h => parseInt(h, 16));
  const head = parsePart(halves[0]!);
  const tail = halves.length === 2 ? [...parsePart(halves[1]!), ...trailing] : trailing;
  if (halves.length === 1) {
    const all = [...head, ...trailing];
    return all.length === 8 ? all : null;
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  return [...head, ...Array<number>(missing).fill(0), ...tail];
}

/** True for an address an MCP endpoint must never reach, including all IPv4-embedded and non-global IPv6 forms. */
export function isBlockedAddress(raw: string): boolean {
  const address = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  const family = isIP(address);
  if (family === 0) return true;
  if (family === 4) return blockedIpv4.check(address, "ipv4");

  const groups = parseIpv6Hextets(address);
  if (!groups) return true;
  // IPv4-mapped IPv6 (::ffff:a.b.c.d in any compressed or expanded hex/dotted spelling).
  if (groups[0] === 0 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0xffff) {
    const v4 = `${groups[6]! >> 8}.${groups[6]! & 255}.${groups[7]! >> 8}.${groups[7]! & 255}`;
    return blockedIpv4.check(v4, "ipv4");
  }
  return !globalIpv6.check(address, "ipv6") || blockedIpv6.check(address, "ipv6");
}

const LOOPBACK_NAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Throws a plain sentence when the endpoint must not be used; returns the parsed URL otherwise. */
export async function checkRemoteEndpoint(raw: string, resolve: Resolver = systemResolver): Promise<URL> {
  let url: URL; try { url = new URL(raw); } catch { throw new Error("MCP HTTP endpoint is not a valid URL"); }
  if (url.username || url.password || url.hash) throw new Error("MCP HTTP endpoint must not carry URL credentials or a fragment");
  if (url.protocol === "http:" && LOOPBACK_NAMES.has(url.hostname)) return url;
  if (url.protocol !== "https:") throw new Error("MCP HTTP endpoint requires HTTPS (plain HTTP only to localhost, 127.0.0.1 or [::1])");
  const host = url.hostname;
  if (host === "localhost" || host.endsWith(".localhost")) throw new Error("MCP HTTP endpoint points at a local name; use http://localhost for a local server");
  const addresses = isIP(host.replace(/^\[|\]$/g, "")) ? [host] : await resolve(host).catch(() => { throw new Error(`MCP HTTP endpoint host ${host} could not be resolved`); });
  if (!addresses.length) throw new Error(`MCP HTTP endpoint host ${host} did not resolve to any address`);
  const bad = addresses.find(isBlockedAddress);
  if (bad !== undefined) throw new Error(`MCP HTTP endpoint host ${host} resolves to a private, loopback, link-local or metadata address and is refused`);
  return url;
}
