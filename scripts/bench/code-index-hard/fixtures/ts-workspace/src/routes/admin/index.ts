import { Router } from "express";
import { adminUsersRouter } from "./users";
import { adminOrgsRouter } from "./orgs";
import { adminAuditRouter } from "./audit";

export const adminRouter = Router();

adminRouter.use("/users", adminUsersRouter);
adminRouter.use("/orgs", adminOrgsRouter);
adminRouter.use("/audit", adminAuditRouter);
