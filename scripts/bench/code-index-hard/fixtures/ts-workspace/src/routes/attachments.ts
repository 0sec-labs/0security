import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { attachmentService } from "../services/attachmentService";

export const attachmentsRouter = Router();

attachmentsRouter.get("/:id/download", (req, res) => {
  const file = attachmentService.download((req as AuthedRequest).user, req.params.id);
  res.type("text/plain").send(file.body);
});
