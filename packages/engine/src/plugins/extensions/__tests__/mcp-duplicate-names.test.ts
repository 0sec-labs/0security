import { describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { connectSdk } from "../mcp/adapters/sdk-session.js";
import { reviewTools } from "../mcp/core/review.js";
import { mcpServerStatuses } from "../mcp/status.js";
import { loaded } from "./mcp-fixtures.js";

describe("duplicate tool names reach the review as a refusal, not a generic listing error", () => {
  it("the SDK session passes duplicates through so reviewTools names them", async () => {
    const server = new Server({ name: "dup", version: "1" }, { capabilities: { tools: {} } });
    const inputSchema = { type: "object" as const };
    server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "echo", description: "a", inputSchema }, { name: "echo", description: "b", inputSchema }] }));
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const session = await connectSdk(clientSide);
    try {
      const tools = await session.tools();
      expect(tools.map(t => t.name)).toEqual(["echo", "echo"]);
      expect(reviewTools(undefined, tools).reason).toMatch(/duplicate tool/i);
    } finally { await session.close(); await server.close(); }
  });

  it("a blocked observation without a stored review does not show its tools as approved", () => {
    const extension = loaded("docs", { ".mcp.json": { mcpServers: { fake: { command: "node", args: ["server.js"] } } } });
    const [status] = mcpServerStatuses(extension.manifest, { fake: { tools: { echo: "h1" } } } as never, { fake: { at: "t", tools: { echo: "h1" }, review: null, blocked: "duplicate tool names; refused" } });
    expect(status?.state).toBe("needs-approval");
    expect(status?.tools.map(t => t.state)).toEqual(["changed"]);
  });
});
