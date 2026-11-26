import { members } from "../db";

export function assertTeamOwner(userId: string, teamId: string) {
  const ok = members.some((m) => m.teamId === teamId && m.userId === userId && m.role === "owner");
  if (!ok) throw Object.assign(new Error("forbidden"), { status: 403 });
}
