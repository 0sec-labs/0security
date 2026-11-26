# tenantly-api

Billing and CRM API. Every record belongs to an organisation (`orgId`); users sign in with
`POST /api/auth/login` and send the returned bearer token on every call.

Layout:

- `src/routes` HTTP routers, mounted in `src/routes/index.ts`
- `src/services` business logic shared by routes, jobs and resolvers
- `src/repositories` in-memory repositories (one per record type)
- `src/jobs` background jobs and the queue
- `src/graphql` the small query endpoint at `POST /graphql`
- `src/ws` realtime sessions and message handlers (HTTP bridge under `/rt`)
- `src/integrations` inbound provider webhooks

Run with `npm start`. Secrets come from `TENANTLY_TOKEN_SECRET`, `TENANTLY_SHARE_SECRET`,
`TENANTLY_WEBHOOK_SECRET` and `TENANTLY_SERVICE_TOKEN`.
