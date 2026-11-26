export type Role = "member" | "manager" | "admin";

export interface UrlRule {
  prefix: string;
  roles: Role[];
}

// Path prefixes that need a minimum role before any handler runs.
export const urlRules: UrlRule[] = [
  { prefix: "/api/admin", roles: ["admin"] },
  { prefix: "/api/billing", roles: ["manager", "admin"] },
  { prefix: "/api/ops", roles: ["admin"] },
];
