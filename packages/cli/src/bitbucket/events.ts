/**
 * Webhook deliveries from Bitbucket Cloud and Data Center that mean "review this pull request".
 *
 * Both products sign the body: `X-Hub-Signature: sha256=<hex HMAC of the raw body>` with the secret set on the webhook
 * (https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/). The event is named in `X-Event-Key`.
 * A delivery only locates a pull request. What gets reviewed is decided by the operator's repository setting.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { cloudPullRequest, dcPullRequest, type Platform, type PullRequest } from "./client.js";

/** Events that carry a new or changed pull request head. Cloud has no event for "new commits only": `updated` covers it. */
export const PULL_REQUEST_EVENTS: Record<Platform, readonly string[]> = {
  "bitbucket-cloud": ["pullrequest:created", "pullrequest:updated"],
  "bitbucket-dc": ["pr:opened", "pr:from_ref_updated"],
};

/** True when `header` is the HMAC-SHA256 of `body` under `secret`. Compares in constant time. */
export function verifySignature(secret: string, body: string | Buffer, header: string | undefined): boolean {
  if (!secret || !header) return false;
  const match = /^sha256=([0-9a-fA-F]{64})$/.exec(header.trim());
  if (!match) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  return timingSafeEqual(expected, Buffer.from(match[1]!, "hex"));
}

export type ParsedDelivery = { ok: true; pr: PullRequest } | { ok: false; reason: string };

const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

/** The pull request in a webhook body, or the reason it is not one to review. */
export function parseDelivery(platform: Platform, eventKey: string, payload: unknown): ParsedDelivery {
  if (!PULL_REQUEST_EVENTS[platform].includes(eventKey)) return { ok: false, reason: "event_not_handled" };
  if (!isRecord(payload)) return { ok: false, reason: "payload_shape" };
  if (platform === "bitbucket-cloud") {
    const repository = isRecord(payload["repository"]) ? payload["repository"]["full_name"] : undefined;
    const [owner, repo, extra] = typeof repository === "string" ? repository.split("/") : [];
    if (!owner || !repo || extra !== undefined) return { ok: false, reason: "payload_shape" };
    const pr = cloudPullRequest(payload["pullrequest"], owner, repo);
    return pr ? { ok: true, pr } : { ok: false, reason: "payload_shape" };
  }
  const request = isRecord(payload["pullRequest"]) ? payload["pullRequest"] : undefined;
  const target = request && isRecord(request["toRef"]) && isRecord(request["toRef"]["repository"]) ? request["toRef"]["repository"] : undefined;
  const project = target && isRecord(target["project"]) ? target["project"]["key"] : undefined;
  const slug = target?.["slug"];
  if (typeof project !== "string" || typeof slug !== "string") return { ok: false, reason: "payload_shape" };
  const pr = dcPullRequest(request, project, slug);
  return pr ? { ok: true, pr } : { ok: false, reason: "payload_shape" };
}
