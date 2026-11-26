import { Router } from "express";
import { randomUUID } from "node:crypto";
import { requireAuth } from "../middleware/auth";
import { invites, members } from "../db";
import { assertTeamOwner } from "../services/teamService";

export const teamsRouter = Router();

teamsRouter.post("/teams/:teamId/invites", requireAuth, (req, res) => {
  const user = (req as any).user;
  assertTeamOwner(user.id, req.params.teamId);
  const token = randomUUID();
  invites.set(token, { token, teamId: req.params.teamId, email: req.body.email, role: req.body.role === "owner" ? "owner" : "member", used: false });
  res.json({ token });
});

teamsRouter.post("/invites/:token/accept", requireAuth, (req, res) => {
  const invite = invites.get(req.params.token);
  if (!invite || invite.used) return res.sendStatus(404);
  invite.used = true;
  members.push({ teamId: invite.teamId, userId: (req as any).user.id, role: invite.role });
  res.sendStatus(204);
});
