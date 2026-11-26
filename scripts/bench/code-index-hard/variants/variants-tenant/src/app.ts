import express from "express";
import { authenticate } from "./middleware/authenticate";
import { errorHandler } from "./middleware/errorHandler";
import { requestLog } from "./middleware/requestLog";
import { serviceToken } from "./middleware/serviceToken";
import { apiRouter } from "./routes/index";
import { authRouter } from "./routes/auth";
import { graphqlRouter } from "./routes/graphql";
import { internalRouter } from "./routes/internal";
import { publicRouter } from "./routes/publicInvoice";
import { integrationsRouter } from "./integrations/index";
import { realtimeRouter } from "./ws/bridge";
import { registerJobs } from "./jobs/registry";
import { seedDemoData } from "./seed";

export function createApp() {
  seedDemoData();
  registerJobs();
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));
  app.use(requestLog);
  app.use("/public", publicRouter);
  app.use("/api/auth", authRouter);
  app.use("/api/internal", serviceToken, internalRouter);
  app.use("/integrations", integrationsRouter);
  app.use("/graphql", authenticate, graphqlRouter);
  app.use("/rt", authenticate, realtimeRouter);
  app.use("/api", authenticate, apiRouter);
  app.use(errorHandler);
  return app;
}
