import { Router } from "express";
import { adminService } from "../../services/adminService";

export const adminAuditRouter = Router();

adminAuditRouter.get("/", (_req, res) => {
  res.json(adminService.auditLog());
});
