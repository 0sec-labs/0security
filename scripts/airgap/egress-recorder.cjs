"use strict";
// Preloaded into a Node process with NODE_OPTIONS=--require. It records every attempt to
// leave the machine and refuses the ones that are not loopback, so a verification run
// cannot leak even when the code under test is wrong. Attempts go to $AIRGAP_LOG as JSON lines.
const fs = require("node:fs");
const net = require("node:net");
const dns = require("node:dns");
const cp = require("node:child_process");

const LOG = process.env.AIRGAP_LOG;
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\]|0\.0\.0\.0)$/i;
const NETWORK_COMMANDS = new Set(["gh", "curl", "wget", "ssh", "scp", "sftp", "docker", "podman", "npm", "pnpm", "yarn", "pip", "pip3", "mvn", "gradle", "nmap"]);
const GIT_NETWORK = new Set(["clone", "fetch", "pull", "push", "ls-remote"]);

function record(kind, target, blocked) {
  if (!LOG) return;
  try { fs.appendFileSync(LOG, JSON.stringify({ kind, target: String(target), blocked }) + "\n"); } catch {}
}
const isLoopback = (host) => !host || LOOPBACK.test(String(host));
function refuse(kind, target) {
  record(kind, target, true);
  const error = new Error(`egress blocked by verification: ${kind} ${target}`);
  error.code = "ECONNREFUSED";
  return error;
}

// Sockets. Unix sockets and loopback are allowed.
const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function patchedConnect(...args) {
  const first = args[0];
  let host;
  let isUnix = false;
  if (first && typeof first === "object") {
    if (Array.isArray(first)) { host = undefined; } else { host = first.host; isUnix = typeof first.path === "string" && first.port === undefined; }
  } else if (typeof first === "string" && Number.isNaN(Number(first))) {
    isUnix = true;
  } else {
    host = typeof args[1] === "string" ? args[1] : undefined;
  }
  if (isUnix || isLoopback(host)) return originalConnect.apply(this, args);
  const error = refuse("connect", host);
  process.nextTick(() => this.destroy(error));
  return this;
};

// Name lookups.
for (const name of ["lookup", "resolve", "resolve4", "resolve6", "resolveAny"]) {
  const original = dns[name];
  if (typeof original !== "function") continue;
  dns[name] = function patchedDns(host, ...rest) {
    if (isLoopback(host)) return original.call(this, host, ...rest);
    const error = refuse(`dns.${name}`, host);
    const callback = rest.find((value) => typeof value === "function");
    if (callback) return process.nextTick(callback, error);
    throw error;
  };
}
for (const name of ["lookup", "resolve", "resolve4", "resolve6"]) {
  const original = dns.promises[name];
  if (typeof original !== "function") continue;
  dns.promises[name] = async function patchedDnsPromise(host, ...rest) {
    if (isLoopback(host)) return original.call(this, host, ...rest);
    throw refuse(`dns.promises.${name}`, host);
  };
}

// fetch.
const originalFetch = globalThis.fetch;
if (typeof originalFetch === "function") {
  globalThis.fetch = async function patchedFetch(input, init) {
    let host = "";
    try { host = new URL(typeof input === "string" || input instanceof URL ? input : input.url).hostname; } catch {}
    if (!isLoopback(host)) throw refuse("fetch", host || String(input));
    return originalFetch.call(this, input, init);
  };
}

// Child processes that talk to the network.
function inspectCommand(file, args) {
  const base = String(file).split(/[\\/]/).pop();
  if (NETWORK_COMMANDS.has(base)) return base;
  if (base === "git" && Array.isArray(args) && args.some((arg) => GIT_NETWORK.has(arg))) return "git " + args.find((arg) => GIT_NETWORK.has(arg));
  return undefined;
}
for (const name of ["spawn", "spawnSync", "execFile", "execFileSync"]) {
  const original = cp[name];
  cp[name] = function patchedSpawn(file, args, ...rest) {
    const hit = inspectCommand(file, Array.isArray(args) ? args : []);
    if (hit) {
      const error = refuse("process", hit);
      if (name === "spawnSync") return { status: null, signal: null, error, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), output: null, pid: 0 };
      if (name === "execFileSync") throw error;
    }
    return original.call(this, file, args, ...rest);
  };
}
