import { Repo } from "../lib/store";
import type { IntegrationAccount } from "../models/catalog";

class IntegrationRepo extends Repo<IntegrationAccount> {
  findByExternal(provider: string, externalAccountId: string): IntegrationAccount | undefined {
    for (const account of this.rows.values()) {
      if (account.provider === provider && account.externalAccountId === externalAccountId) return account;
    }
    return undefined;
  }
}

export const integrationRepo = new IntegrationRepo("integrationAccount");
