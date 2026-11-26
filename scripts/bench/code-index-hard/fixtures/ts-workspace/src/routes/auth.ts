import { Router } from "express";
import { authService } from "../services/authService";

export const authRouter = Router();

authRouter.post("/login", (req, res) => {
  res.json(authService.login(req.body?.email, req.body?.passcode));
});

authRouter.post("/register", (req, res) => {
  res.status(201).json(authService.register(req.body ?? {}));
});
