import { Router } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { requireOrgRole } from "../middleware/requireOrgRole";
import { issueShareToken } from "../lib/tokens";
import { inSeconds } from "../lib/clock";
import { env } from "../config/env";
import { invoiceService } from "../services/invoiceService";
import { pdfService } from "../services/pdfService";

export const invoicesRouter = Router();
const who = (req: unknown) => (req as AuthedRequest).user;

invoicesRouter.get("/", (req, res) => {
  res.json(invoiceService.list(who(req)));
});

invoicesRouter.get("/:id", (req, res) => {
  res.json(invoiceService.get(who(req), req.params.id));
});

invoicesRouter.get("/:id/lines", (req, res) => {
  res.json(invoiceService.get(who(req), req.params.id).lines);
});

invoicesRouter.post("/:id/send", requireOrgRole("manager"), (req, res) => {
  res.json(invoiceService.markSent(who(req), req.params.id));
});

invoicesRouter.post("/:id/share", requireOrgRole("manager"), (req, res) => {
  const invoice = invoiceService.get(who(req), req.params.id);
  res.json({ token: issueShareToken("invoice", invoice.id, inSeconds(env.shareTtlSeconds)) });
});

invoicesRouter.get("/:id/pdf", (req, res) => {
  const document = pdfService.render(req.params.id);
  res.type("text/plain").set("Content-Disposition", `attachment; filename="${document.filename}"`).send(document.body);
});
