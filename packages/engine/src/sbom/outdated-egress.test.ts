import { afterEach, describe, expect, it } from "vitest";
import { checkOutdated } from "./outdated.js";

const bom = { components: [{ type: "library", name: "lodash", version: "4.17.15", purl: "pkg:npm/lodash@4.17.15" }] };
const saved = process.env["ZERO_ENTERPRISE"];
afterEach(() => { if (saved === undefined) delete process.env["ZERO_ENTERPRISE"]; else process.env["ZERO_ENTERPRISE"] = saved; });

describe("0 sbom check --outdated in enterprise mode", () => {
  it("refuses to contact api.deps.dev", async () => {
    process.env["ZERO_ENTERPRISE"] = "1";
    await expect(checkOutdated(bom)).rejects.toThrow("ZERO_ENTERPRISE");
  });
  it("still works with an injected fetch (tests and callers that bring their own)", async () => {
    process.env["ZERO_ENTERPRISE"] = "1";
    const fetchStub = (async () => new Response(JSON.stringify({ versions: [] }), { status: 200 })) as typeof fetch;
    await expect(checkOutdated(bom, { fetch: fetchStub })).resolves.toBeDefined();
  });
});
