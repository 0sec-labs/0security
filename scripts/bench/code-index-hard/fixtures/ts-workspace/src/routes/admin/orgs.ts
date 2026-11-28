import { Router } from "express";
import { adminService } from "../../services/adminService";

export const adminOrgsRouter = Router();

adminOrgsRouter.get("/", (_req, res) => {
  res.json(adminService.listOrgs());
});
