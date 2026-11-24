import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { readIdpMetadataXml } from "./saml-metadata.js";

let server: Server | undefined;
afterEach(async () => {
  const active = server; server = undefined;
  if (active) { active.closeAllConnections(); await new Promise<void>(resolve => active.close(() => resolve())); }
});
async function serve(handler: Parameters<typeof createServer>[1]): Promise<string> {
  server = createServer(handler);
  await new Promise<void>(resolve => server!.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}/m`;
}

describe("SAML metadata fetch", () => {
  it("returns a small document", async () => {
    const metadataUrl = await serve((_req, res) => { res.end("<md/>"); });
    expect(await readIdpMetadataXml({ metadataUrl })).toBe("<md/>");
  });

  it("aborts an endless chunked body once the cap is crossed, and the server sees the connection close", async () => {
    let sent = 0; let closed = false;
    const metadataUrl = await serve((_req, res) => {
      const timer = setInterval(() => { sent += 64 * 1024; res.write(Buffer.alloc(64 * 1024, 97)); }, 1);
      res.on("close", () => { closed = true; clearInterval(timer); });
    });
    await expect(readIdpMetadataXml({ metadataUrl }, { maxBytes: 100_000 })).rejects.toMatchObject({ statusCode: 502, message: expect.stringMatching(/too large/) });
    await new Promise(resolve => setTimeout(resolve, 200));
    expect(closed).toBe(true);
    expect(sent).toBeLessThan(10 * 1024 * 1024);
  });

  it("refuses a declared oversized body", async () => {
    const metadataUrl = await serve((_req, res) => { res.setHeader("Content-Length", "5000000"); res.write("x"); });
    await expect(readIdpMetadataXml({ metadataUrl }, { maxBytes: 1000 })).rejects.toMatchObject({ statusCode: 502 });
  });

  it("gives up on a body that stalls, at the deadline", async () => {
    const metadataUrl = await serve((_req, res) => { res.write("<md>"); });
    const started = Date.now();
    await expect(readIdpMetadataXml({ metadataUrl }, { timeoutMs: 300 })).rejects.toMatchObject({ statusCode: 502 });
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("gives up on a body that trickles forever, at the deadline", async () => {
    const metadataUrl = await serve((_req, res) => {
      const timer = setInterval(() => res.write("x"), 20);
      res.on("close", () => clearInterval(timer));
    });
    await expect(readIdpMetadataXml({ metadataUrl }, { timeoutMs: 300 })).rejects.toMatchObject({ statusCode: 502 });
  });

  it("refuses redirects", async () => {
    const metadataUrl = await serve((_req, res) => { res.writeHead(302, { Location: "http://127.0.0.1:1/" }); res.end(); });
    await expect(readIdpMetadataXml({ metadataUrl })).rejects.toMatchObject({ statusCode: 502 });
  });
});
