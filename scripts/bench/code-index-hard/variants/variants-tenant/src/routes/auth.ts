import { Router } from "express";
import { badRequest } from "../lib/errors";
import { checkPassword } from "../lib/password";
import { signToken } from "../lib/token";
import { userRepo } from "../repositories/userRepo";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") throw badRequest("email and password are required");
  const user = userRepo.findByEmail(email);
  if (!user || user.disabled || !checkPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  res.json({ token: signToken(user.id), user: { id: user.id, orgId: user.orgId, role: user.role } });
});
