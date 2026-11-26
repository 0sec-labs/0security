import { Router } from "express";
import type { Request } from "express";
import type { AuthedRequest } from "../middleware/authenticate";
import { billingService } from "../services/billingService";

export const billingRouter = Router();

// The invoicing job calls these on behalf of the organisation named in X-Org-Id.
const orgOf = (req: Request) => req.get("x-org-id") ?? (req as AuthedRequest).user.orgId;

billingRouter.get("/plan", (req, res) => {
  res.json(billingService.planFor(orgOf(req)));
});

billingRouter.get("/invoices", (req, res) => {
  res.json(billingService.invoicesFor(orgOf(req)));
});

billingRouter.get("/usage", (req, res) => {
  res.json(billingService.usageFor((req as AuthedRequest).user.orgId));
});
