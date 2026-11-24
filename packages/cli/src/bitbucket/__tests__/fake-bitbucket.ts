/**
 * A stand-in for Bitbucket Cloud and Data Center for tests: a real HTTP server on this machine that answers the
 * endpoints the client uses, with the response shapes of the published API descriptions. It keeps comments and the last
 * Code Insights report in memory and records every request.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Platform } from "../client.js";

export interface Recorded { method: string; path: string; query: URLSearchParams; headers: Record<string, string | string[] | undefined>; body: unknown }
export interface FakeComment { id: number; text: string; version: number; inline?: unknown }

export interface FakeBitbucket {
  url: string;
  token: string;
  requests: Recorded[];
  comments: FakeComment[];
  report: { path: string; body: unknown; annotations: unknown[] } | undefined;
  /** Raw pull request objects the list and get endpoints return. */
  pullRequests: Array<Record<string, unknown>>;
  diff: string;
  /** Answer this many comment pages with a `next` link before the last one (Cloud), or page size one (Data Center). */
  smallPages: boolean;
  close(): Promise<void>;
}

export async function startFakeBitbucket(platform: Platform, token = "fake-token-value"): Promise<FakeBitbucket> {
  const cloud = platform === "bitbucket-cloud";
  let nextId = 100;
  const state: FakeBitbucket = { url: "", token, requests: [], comments: [], report: undefined, pullRequests: [], diff: "", smallPages: false, close: async () => undefined };
  const base = cloud ? "/2.0/repositories/ws/app" : "/rest/api/latest/projects/PRJ/repos/app";
  const insights = "/rest/insights/latest/projects/PRJ/repos/app";

  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", chunk => chunks.push(chunk as Buffer));
    request.on("end", () => {
      const url = new URL(request.url ?? "/", "http://localhost");
      const raw = Buffer.concat(chunks).toString("utf8");
      let body: unknown;
      try { body = raw ? JSON.parse(raw) : undefined; } catch { body = raw; }
      state.requests.push({ method: request.method ?? "", path: url.pathname, query: url.searchParams, headers: request.headers, body });
      const send = (status: number, value?: unknown, headers: Record<string, string> = {}, type = "application/json") => {
        response.writeHead(status, { "Content-Type": type, ...headers });
        response.end(value === undefined ? "" : typeof value === "string" ? value : JSON.stringify(value));
      };
      if (request.headers.authorization !== `Bearer ${token}`) return send(401, { error: { message: "bad token" } });
      const path = url.pathname;
      const method = request.method;
      const prs = state.pullRequests;
      const comment = (c: FakeComment) => cloud
        ? { id: c.id, content: { raw: c.text }, deleted: false, ...(c.inline ? { inline: c.inline } : {}) }
        : { action: "COMMENTED", comment: { id: c.id, text: c.text, version: c.version } };

      // Code Insights (both products).
      const reportMatch = cloud ? /\/commit\/([0-9a-f]+)\/reports\/([^/]+)(\/annotations)?$/.exec(path) : /\/commits\/([0-9a-f]+)\/reports\/([^/]+)(\/annotations)?$/.exec(path);
      if (reportMatch && (cloud ? path.startsWith(base) : path.startsWith(insights))) {
        if (method === "PUT" && !reportMatch[3]) { state.report = { path, body, annotations: [] }; return send(cloud ? 200 : 204, cloud ? body : undefined); }
        if (method === "POST" && reportMatch[3] && state.report) {
          const list = cloud ? body : (body as { annotations: unknown[] }).annotations;
          state.report.annotations.push(...(list as unknown[]));
          return send(200, cloud ? list : { failed: [] });
        }
        return send(404, {});
      }
      if (!path.startsWith(base)) return send(404, {});
      const rest = path.slice(base.length);
      const prPart = cloud ? "/pullrequests" : "/pull-requests";

      if (rest === prPart && method === "GET") {
        if (cloud) {
          const page = Number(url.searchParams.get("page") ?? 1);
          const size = state.smallPages ? 1 : 50;
          const values = prs.slice((page - 1) * size, page * size);
          const hasNext = page * size < prs.length;
          return send(200, { pagelen: size, page, size: prs.length, values, ...(hasNext ? { next: `${state.url}${base}/pullrequests?state=OPEN&page=${page + 1}` } : {}) });
        }
        const start = Number(url.searchParams.get("start") ?? 0);
        const size = state.smallPages ? 1 : 50;
        const values = prs.slice(start, start + size);
        const last = start + size >= prs.length;
        return send(200, { size: values.length, limit: size, isLastPage: last, start, values, ...(last ? {} : { nextPageStart: start + size }) });
      }
      if (cloud && rest.startsWith("/diff/")) return send(200, state.diff, {}, "text/plain");
      const prMatch = new RegExp(`^${prPart}/(\\d+)(\\.diff|/diff|/comments|/activities)?(?:/(\\d+))?$`).exec(rest);
      if (!prMatch) return send(404, {});
      const [, id, sub, commentId] = prMatch;
      if (!sub && method === "GET") { const found = prs.find(item => item["id"] === Number(id)); return found ? send(200, found) : send(404, {}); }
      if (cloud && sub === "/diff" && method === "GET") return send(302, "", { Location: `${state.url}/2.0/repositories/ws/app/diff/abc..def` });
      if (!cloud && sub === ".diff" && method === "GET") return send(200, state.diff, {}, "text/plain");
      if (sub === "/comments" && !commentId) {
        if (cloud && method === "GET") {
          const page = Number(url.searchParams.get("page") ?? 1);
          const size = state.smallPages ? 1 : 100;
          const values = state.comments.slice((page - 1) * size, page * size).map(comment);
          return send(200, { values, ...(page * size < state.comments.length ? { next: `${state.url}${base}/pullrequests/${id}/comments?page=${page + 1}` } : {}) });
        }
        if (method === "POST") {
          const input = body as { content?: { raw: string }; text?: string; inline?: unknown; anchor?: unknown };
          const created: FakeComment = { id: nextId++, text: cloud ? input.content!.raw : input.text!, version: 0, inline: cloud ? input.inline : input.anchor };
          state.comments.push(created);
          return send(201, cloud ? comment(created) : { id: created.id, version: 0, text: created.text });
        }
      }
      if (!cloud && sub === "/activities" && method === "GET") {
        const start = Number(url.searchParams.get("start") ?? 0);
        const size = state.smallPages ? 1 : 100;
        const values = state.comments.slice(start, start + size).map(comment);
        const last = start + size >= state.comments.length;
        return send(200, { isLastPage: last, start, values, ...(last ? {} : { nextPageStart: start + size }) });
      }
      if (sub === "/comments" && commentId) {
        const found = state.comments.find(item => item.id === Number(commentId));
        if (!found) return send(404, {});
        if (method === "PUT") {
          const input = body as { content?: { raw: string }; text?: string; version?: number };
          if (!cloud && input.version !== found.version) return send(409, { errors: [{ message: "version mismatch" }] });
          found.text = cloud ? input.content!.raw : input.text!;
          found.version++;
          return send(200, {});
        }
        if (method === "DELETE") {
          if (!cloud && Number(url.searchParams.get("version")) !== found.version) return send(409, {});
          state.comments.splice(state.comments.indexOf(found), 1);
          return send(204);
        }
      }
      return send(404, {});
    });
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  state.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  state.close = () => new Promise<void>(done => { server.closeAllConnections(); server.close(() => done()); });
  return state;
}

/** A Cloud pull request object as the API returns it. */
export const cloudPr = (id: number, over: Record<string, unknown> = {}) => ({
  id, title: `PR ${id}`, state: "OPEN", draft: false,
  source: { branch: { name: `feature-${id}` }, commit: { hash: `${String(id).padStart(12, "a")}` }, repository: { full_name: "ws/app" } },
  destination: { branch: { name: "main" }, commit: { hash: "bbbbbbbbbbbb" }, repository: { full_name: "ws/app" } },
  ...over,
});

/** A Data Center pull request object as the API returns it. */
export const dcPr = (id: number, over: Record<string, unknown> = {}) => ({
  id, title: `PR ${id}`, state: "OPEN", draft: false,
  fromRef: { id: `refs/heads/feature-${id}`, displayId: `feature-${id}`, latestCommit: String(id).padStart(40, "a"), repository: { id: 7, slug: "app", project: { key: "PRJ" } } },
  toRef: { id: "refs/heads/main", displayId: "main", latestCommit: "b".repeat(40), repository: { id: 7, slug: "app", project: { key: "PRJ" } } },
  ...over,
});
