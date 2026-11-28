import { randomBytes } from "node:crypto";

const secret = (name: string, bytes = 32): string => process.env[name] ?? randomBytes(bytes).toString("hex");

export const config = {
  port: Number(process.env.PORT ?? 3000),
  tokenSecret: secret("TENANTLY_TOKEN_SECRET"),
  shareSecret: secret("TENANTLY_SHARE_SECRET"),
  webhookSecret: secret("TENANTLY_WEBHOOK_SECRET"),
  serviceToken: secret("TENANTLY_SERVICE_TOKEN", 24),
  tokenTtlSeconds: 3600,
  webhookToleranceSeconds: 3600,
};
