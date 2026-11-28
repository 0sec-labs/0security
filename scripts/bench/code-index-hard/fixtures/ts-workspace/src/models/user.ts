import type { Role } from "../config/security";

export interface User {
  id: string;
  orgId: string;
  name: string;
  email: string;
  role: Role;
  passcode: string;
}
