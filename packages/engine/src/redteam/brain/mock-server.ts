/**
 * A local stand-in for the hosted brain: speaks the v1 contract on 127.0.0.1 and answers with the open starter pack. For tests and for
 * developing against the contract; it is not the real service and generates nothing new.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { validateRequest, type ScenarioRequest, type ScenarioResponse } from "./schema.js";
import { starterFor } from "./starter-pack.js";

export interface MockBrainOptions { /** When set, requests must carry `Authorization: Bearer <token>`. */ token?: string }
export interface MockBrain { server: Server; /** Starts listening on a free loopback port and returns the URL. */ start(): Promise<string>; close(): Promise<void>; requests: { authorization: string | undefined; body: unknown }[] }

const MAX_BODY = 64 * 1024;

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => { size += chunk.length; if (size > MAX_BODY) { reject(new Error("too large")); req.destroy(); } else chunks.push(chunk); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export function createMockBrain(options: MockBrainOptions = {}): MockBrain {
  const requests: MockBrain["requests"] = [];
  const server = createServer((req, res) => {
    const send = (status: number, body: unknown) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
    void (async () => {
      if (req.method !== "POST") return send(405, { error: "POST only" });
      const authorization = req.headers.authorization;
      if (options.token && authorization !== `Bearer ${options.token}`) return send(401, { error: "unauthorized" });
      let parsed: unknown;
      try { parsed = JSON.parse(await readBody(req)); } catch { return send(400, { error: "body is not valid JSON" }); }
      requests.push({ authorization, body: parsed });
      const checked = validateRequest(parsed);
      if (!checked.ok) return send(400, { error: checked.error });
      const request: ScenarioRequest = checked.value;
      const response: ScenarioResponse = { v: 1, task: "scenarios", scenarios: starterFor(request), watermark: "mock-brain" };
      send(200, response);
    })().catch(() => { if (!res.headersSent) send(400, { error: "bad request" }); });
  });
  return {
    server, requests,
    start: () => new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/scenarios`))),
    close: () => new Promise(resolve => { server.close(() => resolve()); server.closeAllConnections?.(); }),
  };
}
