import { notFound } from "./errors";
import type { AuthUser, OrgRecord } from "../models/base";

export function assertSameOrg(user: AuthUser, record: OrgRecord, what = "record"): void {
  if (record.orgId !== user.orgId) throw notFound(what);
}

export const refundPolicy = {
  canView(user: AuthUser, refund: OrgRecord): boolean {
    return refund.orgId === user.orgId;
  },
  canIssue(user: AuthUser, refund: OrgRecord): boolean {
    return refund.orgId === user.orgId && (user.role === "admin" || user.role === "manager");
  },
};
