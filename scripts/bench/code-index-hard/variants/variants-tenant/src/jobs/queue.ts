import { isoNow, newId } from "../lib/ids";
import type { AuthUser } from "../models/base";

export interface Job<P = any> {
  id: string;
  name: string;
  orgId: string;
  requestedBy: string;
  payload: P;
  status: "queued" | "running" | "done" | "failed";
  result?: unknown;
  error?: string;
  createdAt: string;
}

type Handler = (job: Job) => unknown | Promise<unknown>;

const handlers = new Map<string, Handler>();
const jobs = new Map<string, Job>();

async function run(job: Job): Promise<void> {
  const handler = handlers.get(job.name);
  job.status = "running";
  try {
    if (!handler) throw new Error("no handler for " + job.name);
    job.result = await handler(job);
    job.status = "done";
  } catch (err) {
    job.error = err instanceof Error ? err.message : "job failed";
    job.status = "failed";
  }
}

export const jobQueue = {
  register(name: string, handler: Handler): void {
    handlers.set(name, handler);
  },

  enqueue<P>(name: string, payload: P, user: AuthUser): Job<P> {
    const job: Job<P> = { id: newId("job"), name, orgId: user.orgId, requestedBy: user.id, payload, status: "queued", createdAt: isoNow() };
    jobs.set(job.id, job);
    queueMicrotask(() => void run(job));
    return job;
  },

  get(id: string): Job | undefined {
    return jobs.get(id);
  },
};
