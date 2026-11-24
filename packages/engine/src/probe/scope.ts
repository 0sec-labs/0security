import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";

/**
 * Scope guard for `0 probe`. Attack traffic goes only where the operator says they may send it.
 *
 * - Loopback and private networks (RFC 1918, unique-local IPv6, and 100.64.0.0/10 shared space such as a tailnet)
 *   are allowed without a flag: they are the operator's own machine or network.
 * - Any public address needs `--i-own-this <host>` with the exact host typed.
 * - Link-local and cloud metadata addresses are refused with or without the flag.
 * - The host is resolved once, every answer is checked, and requests connect to that checked address, so a
 *   second DNS answer cannot move the traffic. A redirect off the named origin is refused.
 */

export type NetworkClass = "loopback" | "private" | "public";
export type ResolveHost = (hostname: string) => Promise<string[]>;

export class ProbeScopeError extends Error {
  constructor(message: string) { super(message); this.name = "ProbeScopeError"; }
}

export interface ProbeScope {
  /** The URL as named by the operator. */
  target: string;
  host: string;
  /** Every address the host resolved to when the run started; requests connect to the first. */
  addresses: string[];
  network: NetworkClass;
  /** The host typed after `--i-own-this`, when the target needed it or the flag was given. */
  acknowledgedHost?: string;
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
function unmap(address: string): string {
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

/**
 * Decide whether the target may be probed, before any request is sent.
 * `acknowledge` is the value of `--i-own-this`. When given it must equal the target host, even for a local target.
 */
export async function assessTarget(url: URL, options: { acknowledge?: string; resolve?: ResolveHost } = {}): Promise<ProbeScope> {
  if (url.username || url.password) throw new ProbeScopeError("The endpoint URL must not contain a user name or password. Pass credentials with --header.");
  const hostname = bareHost(url.hostname);
  const acknowledged = options.acknowledge === undefined ? undefined : bareHost(options.acknowledge);
  if (acknowledged !== undefined && acknowledged !== hostname) throw new ProbeScopeError(`--i-own-this must be the exact host being probed (${hostname}), not '${options.acknowledge}'.`);
  let addresses: string[];
  if (isIP(hostname)) addresses = [hostname];
  else {
    try { addresses = await (options.resolve ?? defaultResolve)(hostname); }
    catch (error) { throw new ProbeScopeError(`Could not resolve ${hostname}: ${error instanceof Error ? error.message : String(error)}`); }
    if (!addresses.length) throw new ProbeScopeError(`Could not resolve ${hostname}: no addresses.`);
  }
  let network: NetworkClass = "loopback";
  for (const address of addresses) {
    const kind = classifyAddress(address);
    if (kind === "blocked") throw new ProbeScopeError(`Refused: ${hostname} is or resolves to ${address}, a link-local, metadata or otherwise reserved address. 0 never probes these, even with --i-own-this.`);
    if (rank[kind] > rank[network]) network = kind;
  }
  if (network === "public" && acknowledged === undefined) throw new ProbeScopeError(`Refused: ${hostname} is a public host (${addresses.join(", ")}). Probe only endpoints you own or are authorized to test. If that is you, pass --i-own-this ${hostname}.`);
  return { target: url.href, host: url.host, addresses, network, ...(acknowledged !== undefined ? { acknowledgedHost: acknowledged } : {}) };
}

/** One line for the log and the findings: what was probed and on what authority. */
export function describeScope(scope: ProbeScope): string {
  return `${scope.host} (${scope.network} network, ${scope.addresses.join(", ")})${scope.acknowledgedHost !== undefined ? `, acknowledged with --i-own-this ${scope.acknowledgedHost}` : ""}`;
}

const MAX_BODY = 4 * 1024 * 1024;
const MAX_REDIRECTS = 3;

/**
 * A fetch that connects to the address `assessTarget` approved and follows a redirect only inside the same origin.
 * It sends no Accept-Encoding header and reads at most 4 MiB.
 */
export function createScopedFetch(scope: ProbeScope): typeof fetch {
  const origin = new URL(scope.target).origin;
  const address = scope.addresses[0]!;
  const family = isIP(address);
  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    let url = new URL(input instanceof Request ? input.url : String(input));
    const headers = Object.fromEntries(new Headers(init.headers)); delete headers["host"];
    const body = typeof init.body === "string" ? Buffer.from(init.body) : undefined;
    for (let hop = 0; ; hop++) {
      if (url.origin !== origin) throw new ProbeScopeError(`Refused: redirect off ${origin} to ${url.origin}.`);
      const response = await new Promise<{ message: IncomingMessage; data: Buffer }>((resolve, reject) => {
        const send = url.protocol === "https:" ? httpsRequest : httpRequest;
        const outgoing = send({
          protocol: url.protocol, hostname: address, port: url.port || undefined, path: url.pathname + url.search, method: init.method ?? "GET", agent: false, family,
          servername: isIP(bareHost(url.hostname)) ? "" : bareHost(url.hostname),
          headers: { ...headers, host: url.host, ...(body ? { "content-length": String(body.length) } : {}) },
          ...(init.signal ? { signal: init.signal } : {}),
        }, message => {
          const chunks: Buffer[] = []; let size = 0;
          message.on("data", (chunk: Buffer) => { size += chunk.length; if (size > MAX_BODY) { message.destroy(new Error("The response is larger than 4 MiB.")); return; } chunks.push(chunk); });
          message.once("end", () => resolve({ message, data: Buffer.concat(chunks) }));
          message.once("error", reject);
        });
        outgoing.once("error", reject);
        outgoing.end(body);
      });
      const status = response.message.statusCode ?? 0;
      const location = response.message.headers.location;
      if ([301, 302, 303, 307, 308].includes(status) && location) {
        if (hop >= MAX_REDIRECTS) throw new ProbeScopeError("Refused: too many redirects.");
        url = new URL(location, url);
        continue;
      }
      let data = response.data;
      const encoding = String(response.message.headers["content-encoding"] ?? "identity").toLowerCase().trim();
      if (encoding === "gzip" || encoding === "x-gzip") data = gunzipSync(data, { maxOutputLength: MAX_BODY });
      else if (encoding === "deflate") data = inflateSync(data, { maxOutputLength: MAX_BODY });
      else if (encoding === "br") data = brotliDecompressSync(data, { maxOutputLength: MAX_BODY });
      else if (encoding !== "identity" && encoding !== "") throw new Error(`Unsupported content encoding '${encoding}'.`);
      const responseHeaders = new Headers();
      for (const [name, value] of Object.entries(response.message.headers)) if (value !== undefined && name !== "content-encoding" && name !== "content-length") responseHeaders.set(name, Array.isArray(value) ? value.join(", ") : value);
      return new Response([204, 205, 304].includes(status) ? null : new Uint8Array(data), { status, ...(response.message.statusMessage ? { statusText: response.message.statusMessage } : {}), headers: responseHeaders });
    }
  }) as typeof fetch;
}
