import { Router } from "express";
import { exportService } from "../../services/exportService";

export const internalExportsRouter = Router();

internalExportsRouter.get("/:projectId", (req, res) => {
  res.json(exportService.exportProject(req.params.projectId));
});
