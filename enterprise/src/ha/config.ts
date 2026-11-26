// Licensed under the 0security Enterprise License. See enterprise/LICENSE.
//
// Where the shared database is. The connection string comes only from the process environment
// (ZERO_HA_DATABASE_URL) or from a file whose path is named in the process environment
// (ZERO_HA_DATABASE_URL_FILE). A repository, a project file or the database itself cannot supply it.
// A connection to another machine must use TLS. The string holds a password and is never logged.
import { readFileSync, statSync } from "node:fs";
import { isIPv4 } from "node:net";

export const HA_DATABASE_URL_ENV = "ZERO_HA_DATABASE_URL";
export const HA_DATABASE_URL_FILE_ENV = "ZERO_HA_DATABASE_URL_FILE";

const MAX_URL_FILE_BYTES = 4096;
const TLS_MODES = new Set(["require", "verify-ca", "verify-full"]);

export class HaConfigError extends Error {
  override readonly name = "HaConfigError";
}

export interface HaDatabaseConfig {
  /** Holds a password. Pass it to the driver and nowhere else. */
  connectionString: string;
  /** Host and database for messages. Safe to print. */
  label: string;
  source: "env" | "file";
}

function isLoopback(host: string): boolean {
  const name = host.replace(/^\[|\]$/g, "").toLowerCase();
  // A name such as 127.db.example is a DNS name, not an address, so only an IPv4 literal counts.
  return name === "localhost" || name === "::1" || (isIPv4(name) && name.startsWith("127."));
}

/** The shared database, or null when none is named. Throws HaConfigError for a value that is refused. */
export function parseHaDatabaseConfig(env: NodeJS.ProcessEnv = process.env): HaDatabaseConfig | null {
  const inline = env[HA_DATABASE_URL_ENV]?.trim();
  const file = env[HA_DATABASE_URL_FILE_ENV]?.trim();
  if (inline && file) throw new HaConfigError(`Set only one of ${HA_DATABASE_URL_ENV} and ${HA_DATABASE_URL_FILE_ENV}.`);
  let raw: string;
  let source: "env" | "file";
  if (file) {
    try {
      const stat = statSync(file);
      if (!stat.isFile() || stat.size > MAX_URL_FILE_BYTES) throw new Error("size");
      raw = readFileSync(file, "utf8").trim();
    } catch {
      throw new HaConfigError(`${HA_DATABASE_URL_FILE_ENV} does not name a readable file of ${MAX_URL_FILE_BYTES} bytes or less.`);
    }
    source = "file";
  } else if (inline) {
    raw = inline;
    source = "env";
  } else return null;

  let url: URL;
  try { url = new URL(raw); } catch { throw new HaConfigError("The database URL is not a valid URL."); }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") throw new HaConfigError("The database URL must start with postgres:// or postgresql://.");
  if (!url.hostname) throw new HaConfigError("The database URL names no host. Unix sockets are not supported.");
  // The driver lets these query parameters replace the host or switch TLS off, which would bypass the checks here.
  for (const name of ["host", "hostaddr", "ssl"]) {
    if (url.searchParams.has(name)) throw new HaConfigError(`The database URL may not set ${name}. Put the host in the URL and use sslmode.`);
  }
  const mode = url.searchParams.get("sslmode");
  if (!isLoopback(url.hostname) && !(mode && TLS_MODES.has(mode))) {
    throw new HaConfigError(`The database is on another machine, so the URL must set sslmode to require, verify-ca or verify-full.`);
  }
  const database = url.pathname.replace(/^\//, "") || "postgres";
  return { connectionString: raw, label: `${url.host}/${database}`, source };
}
