/**
 * A local stand-in for an OpenAI-compatible model API that fails on purpose.
 *
 * `plan(n, request)` says how the Nth scan request ends. Requests the scan does not make for review (a model list, a
 * thread title) are answered normally and are not counted. Used by scan-faults.test.ts and for manual fault runs:
 *   OPENAI_BASE_URL=http://127.0.0.1:<port>/v1 OPENAI_API_KEY=<any> OPENAI_WIRE_API=chat_completions 0 scan <folder>
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export type Fault = "ok" | "costly" | "drop" | "http500" | "http429" | "http400" | "http401" | "hang" | "cut";

export interface FaultServer {
  url: string;
  /** Review requests seen so far, in order, with how each was answered. */
  seen: Array<{ n: number; fault: Fault; tools: boolean }>;
  close(): Promise<void>;
}

const REPLY = "Reviewed the files in this batch. No further findings.";

function body(req: IncomingMessage): Promise<string> {
  return new Promise(resolve => { const chunks: Buffer[] = []; req.on("data", chunk => chunks.push(chunk)); req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8"))); req.on("error", () => resolve("")); });
}

function ok(res: ServerResponse, stream: boolean, outputTokens = 12, responses = true): void {
  const usage = { prompt_tokens: 120, completion_tokens: outputTokens, total_tokens: 120 + outputTokens };
  if (responses) {
    const done = { id: "resp_1", object: "response", status: "completed", model: "stub", output: [{ id: "msg_1", type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: REPLY, annotations: [] }] }], usage: { input_tokens: 120, output_tokens: outputTokens, total_tokens: 120 + outputTokens } };
    if (!stream) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(done)); return; }
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    const send = (type: string, data: object) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
    send("response.created", { response: { ...done, status: "in_progress", output: [] } });
    send("response.output_item.added", { output_index: 0, item: { id: "msg_1", type: "message", role: "assistant", status: "in_progress", content: [] } });
    send("response.content_part.added", { item_id: "msg_1", output_index: 0, content_index: 0, part: { type: "output_text", text: "", annotations: [] } });
    send("response.output_text.delta", { item_id: "msg_1", output_index: 0, content_index: 0, delta: REPLY });
    send("response.output_text.done", { item_id: "msg_1", output_index: 0, content_index: 0, text: REPLY });
    send("response.output_item.done", { output_index: 0, item: done.output[0] });
    send("response.completed", { response: done });
    res.end();
    return;
  }
  if (stream) {
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
    res.write(`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: REPLY }, finish_reason: null }] })}\n\n`);
    res.write(`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage })}\n\n`);
    res.end("data: [DONE]\n\n");
    return;
  }
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ id: "c1", object: "chat.completion", choices: [{ index: 0, message: { role: "assistant", content: REPLY }, finish_reason: "stop" }], usage }));
}

export async function startFaultServer(plan: (n: number) => Fault): Promise<FaultServer> {
  const seen: FaultServer["seen"] = [];
  const hung = new Set<ServerResponse>();
  const server: Server = createServer(async (req, res) => {
    const url = req.url ?? "";
    if (req.method === "GET") { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ object: "list", data: [{ id: "gpt-6-luna", object: "model" }] })); return; }
    const text = await body(req);
    let parsed: { stream?: boolean; tools?: unknown[]; messages?: Array<{ content?: unknown }> } = {};
    try { parsed = JSON.parse(text); } catch { /* not JSON: answer it as a plain request */ }
    // A thread title is asked for without tools; the review requests carry the tool list.
    const review = /chat\/completions|responses/.test(url) && Array.isArray(parsed.tools) && parsed.tools.length > 0;
    if (!review) { ok(res, parsed.stream === true, 12, /responses/.test(url)); return; }
    const n = seen.length + 1;
    const fault = plan(n);
    seen.push({ n, fault, tools: true });
    switch (fault) {
      case "ok": ok(res, parsed.stream === true, 12, /responses/.test(url)); return;
      // An answer that reports an enormous number of tokens, so the thread passes its cost ceiling.
      case "costly": ok(res, parsed.stream === true, 50_000_000, /responses/.test(url)); return;
      case "drop": req.socket.destroy(); return;
      case "cut":
        // The answer starts and the connection dies in the middle of it.
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(`data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", choices: [{ index: 0, delta: { role: "assistant", content: "Reviewing" }, finish_reason: null }] })}\n\n`);
        setTimeout(() => req.socket.destroy(), 50);
        return;
      case "http500": res.writeHead(500, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { message: "The server had an error while processing your request.", type: "server_error" } })); return;
      case "http429": res.writeHead(429, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { message: "Rate limit reached for requests per minute.", type: "requests", code: "rate_limit_exceeded" } })); return;
      case "http400": res.writeHead(400, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { message: "Invalid request: unsupported parameter.", type: "invalid_request_error" } })); return;
      case "http401": res.writeHead(401, { "content-type": "application/json" }); res.end(JSON.stringify({ error: { message: "Incorrect API key provided.", type: "invalid_request_error", code: "invalid_api_key" } })); return;
      case "hang": hung.add(res); return;
    }
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/v1`,
    seen,
    close: () => new Promise<void>(resolve => { for (const res of hung) res.destroy(); server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
