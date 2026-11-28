export const env = {
  tokenSecret: process.env.TOKEN_SECRET ?? "workspace-dev-secret",
  serviceToken: process.env.SERVICE_TOKEN ?? "svc-dev-token",
  uploadRoot: process.env.UPLOAD_ROOT ?? "/tmp/workspace-uploads",
  shareTtlSeconds: Number(process.env.SHARE_TTL_SECONDS ?? 86400),
};
