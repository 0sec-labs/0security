import { Router } from "express";
import type { Request } from "express";
import { hub } from "./hub";
import { handleMessage } from "./handlers";

// HTTP bridge for clients that cannot hold a socket open: the same sessions and handlers, polled.
export const realtimeRouter = Router();

const owned = (req: Request) => {
  const session = hub.get(req.params.sid as string);
  return session && session.user.id === req.user!.id ? session : undefined;
};

realtimeRouter.post("/sessions", (req, res) => {
  const session = hub.open(req.user!);
  res.status(201).json({ sessionId: session.id });
});

realtimeRouter.post("/sessions/:sid/messages", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  handleMessage(session, req.body ?? {});
  res.status(202).json({ accepted: true });
});

realtimeRouter.get("/sessions/:sid/events", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  res.json({ events: session.outbox.splice(0) });
});

realtimeRouter.delete("/sessions/:sid", (req, res) => {
  const session = owned(req);
  if (!session) return res.status(404).json({ error: "session not found" });
  hub.close(session.id);
  res.status(204).end();
});
