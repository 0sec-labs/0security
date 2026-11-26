import { Router } from "express";
import { requireServiceToken } from "../../middleware/serviceToken";
import { internalInvoicesRouter } from "./invoices";
import { internalExportsRouter } from "./exports";
import { integrationsRouter } from "./integrations";

export const internalRouter = Router();

internalRouter.use(requireServiceToken);
internalRouter.use("/invoices", internalInvoicesRouter);
internalRouter.use("/exports", internalExportsRouter);
internalRouter.use("/integrations", integrationsRouter);
