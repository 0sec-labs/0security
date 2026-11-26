/**
 * A stand-in for Jira Cloud and Data Center for tests: a real HTTP server on this machine that answers the search and
 * create-issue endpoints with the response shapes of Atlassian's published API descriptions. It is not Jira: the search
 * understands only `labels in (...)`, and it checks nothing a real project would (issue types, required fields, permissions).
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface JiraRecorded { method: string; path: string; headers: Record<string, string | string[] | undefined>; body: any }
export interface FakeIssue { key: string; fields: Record<string, any> }
export interface FakeJira { url: string; requests: JiraRecorded[]; issues: FakeIssue[]; failCreateWith?: number; close(): Promise<void> }

export async function startFakeJira(platform: "jira-cloud" | "jira-dc", auth: string): Promise<FakeJira> {
  const cloud = platform === "jira-cloud";
  const prefix = cloud ? "/rest/api/3" : "/ctx/rest/api/2";
  const state: FakeJira = { url: "", requests: [], issues: [], close: async () => undefined };
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", chunk => chunks.push(chunk as Buffer));
    request.on("end", () => {
      const path = new URL(request.url ?? "/", "http://localhost").pathname;
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw ? JSON.parse(raw) : undefined;
      state.requests.push({ method: request.method ?? "", path, headers: request.headers, body });
      const send = (status: number, payload: unknown) => { response.writeHead(status, { "content-type": "application/json" }); response.end(JSON.stringify(payload)); };
      if (request.headers.authorization !== auth) return send(401, { errorMessages: ["bad credentials"] });
      if (request.method === "POST" && path === `${prefix}${cloud ? "/search/jql" : "/search"}`) {
        const labels = [...String(body.jql).matchAll(/"(0-finding-[^"]*)"/g)].map(match => match[1]);
        return send(200, { issues: state.issues.filter(issue => (issue.fields.labels as string[]).some(label => labels.includes(label))).map(issue => ({ key: issue.key, fields: { labels: issue.fields.labels } })) });
      }
      if (request.method === "POST" && path === `${prefix}/issue`) {
        if (state.failCreateWith) return send(state.failCreateWith, { errors: { project: "bad request echoing " + (request.headers.authorization ?? "") } });
        const key = `${body.fields.project.key}-${state.issues.length + 1}`;
        state.issues.push({ key, fields: body.fields });
        return send(201, { id: String(state.issues.length), key, self: `${state.url}${prefix}/issue/${key}` });
      }
      send(404, { errorMessages: ["not found"] });
    });
  });
  await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
  state.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}${cloud ? "" : "/ctx"}`;
  state.close = () => new Promise(done => server.close(() => done()));
  return state;
}
