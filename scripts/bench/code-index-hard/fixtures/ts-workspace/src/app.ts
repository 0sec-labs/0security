import express from "express";
import { authenticate } from "./middleware/authenticate";
import { securityRules } from "./middleware/securityRules";
import { resolveOrg } from "./middleware/resolveOrg";
import { errorHandler } from "./middleware/errors";
import { authRouter } from "./routes/auth";
import { publicRouter } from "./routes/public";
import { boardsPublicRouter } from "./routes/boardsPublic";
import { internalRouter } from "./routes/internal";
import { billingRouter } from "./routes/billing";
import { adminRouter } from "./routes/admin";
import { opsRouter } from "./routes/ops";
import { apiRouter } from "./routes";

export function createApp() {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  app.use("/api/auth", authRouter);
  app.use("/public", publicRouter);
  app.use("/public/boards", boardsPublicRouter);
  app.use("/api/internal", internalRouter);

  const api = express.Router();
  api.use(authenticate);
  api.use(securityRules);
  api.use("/billing", billingRouter);
  api.use(resolveOrg);
  api.use("/admin", adminRouter);
  api.use("/ops", opsRouter);
  api.use(apiRouter);
  app.use("/api", api);

  app.use(errorHandler);
  return app;
}
