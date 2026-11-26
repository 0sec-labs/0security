import { Router } from "express";
import { adminService } from "../../services/adminService";

export const adminUsersRouter = Router();

adminUsersRouter.get("/", (_req, res) => {
  res.json(adminService.listUsers());
});

adminUsersRouter.put("/:id/role", (req, res) => {
  res.json(adminService.setRole(req.params.id, req.body?.role));
});
