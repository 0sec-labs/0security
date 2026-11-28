export type Role = "admin" | "manager" | "member" | "support";

export interface OrgRecord {
  id: string;
  orgId: string;
}

export interface AuthUser {
  id: string;
  orgId: string;
  role: Role;
}

export interface User extends OrgRecord {
  email: string;
  name: string;
  role: Role;
  passwordHash: string;
  disabled: boolean;
}
