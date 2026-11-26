import { customerRepo } from "../repositories/customerRepo";
import type { AuthUser } from "../models/base";
import type { Customer } from "../models/billing";

// One loader set per request; lookups are limited to the caller's organisation.
export function createLoaders(user: AuthUser) {
  const customers = new Map<string, Customer | null>();
  return {
    customer: {
      load(id: string): Customer | null {
        if (!customers.has(id)) customers.set(id, customerRepo.findForOrg(user.orgId, id) ?? null);
        return customers.get(id) ?? null;
      },
    },
  };
}

export type Loaders = ReturnType<typeof createLoaders>;
