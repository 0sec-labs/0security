import { Router } from "express";
import { paymentWebhook } from "./paymentWebhook";
import { carrierWebhook } from "./carrierWebhook";

export const integrationsRouter = Router();

integrationsRouter.use("/payments", paymentWebhook);
integrationsRouter.use("/carrier", carrierWebhook);
