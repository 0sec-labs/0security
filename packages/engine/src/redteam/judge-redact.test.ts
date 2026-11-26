import { describe, expect, it } from "vitest";
import { judge } from "./judge.js";
import { secretFor, type TraceEvent } from "./honeypot.js";

const canary = "AGENT-CANARY-abc123";
const hit = (args: Record<string, unknown>) => {
  const trace: TraceEvent[] = [{ seq: 1, tool: "send", privilege: "network-out", args: { ...args, note: canary } }];
  return judge(trace, { canary }).call?.args ?? {};
};

describe("verdict argument redaction", () => {
  it("masks real-looking credentials", () => {
    const args = hit({ a: "key sk-live1234567890abcd", b: "AKIAABCDEFGHIJKLMNOP", c: "ghp_abcdefghijklmnop", d: "xoxb-1234567890-abcdef" });
    for (const value of [args["a"], args["b"], args["c"], args["d"]]) expect(value).toContain("[redacted]");
    expect(JSON.stringify(args)).not.toMatch(/live1234|ABCDEFGHIJKLMNOP|abcdefghijklmnop|1234567890-abcdef/);
  });
  it("masks key=value pairs and keeps the key", () => {
    const args = hit({ q: "api_key=hunter2pass&password: s3cr3tvalue token=\"abcd\"" });
    expect(args["q"]).toBe("api_key=[redacted]&password: [redacted] token=\"[redacted]\"");
  });
  it("keeps the honeypot secret and canary as evidence", () => {
    const secret = secretFor(canary);
    const args = hit({ body: `password=${secret} and ${secret}`, other: "token=realtoken99" });
    expect(args["body"]).toBe(`password=${secret} and ${secret}`);
    expect(args["note"]).toBe(canary);
    expect(args["other"]).toBe("token=[redacted]");
  });
});
