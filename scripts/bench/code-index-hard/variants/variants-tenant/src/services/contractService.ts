import { notFound } from "../lib/errors";
import { contractRepo } from "../repositories/contractRepo";
import type { Contract } from "../models/billing";

export const contractService = {
  list(orgId: string): Contract[] {
    return contractRepo.listForOrg(orgId);
  },

  get(id: string): Contract {
    const contract = contractRepo.findById(id);
    if (!contract) throw notFound("contract");
    return contract;
  },

  getForOrg(orgId: string, id: string): Contract {
    const contract = contractRepo.findForOrg(orgId, id);
    if (!contract) throw notFound("contract");
    return contract;
  },

  summarize(contract: Contract) {
    return {
      id: contract.id,
      title: contract.title,
      customerId: contract.customerId,
      value: contract.value,
      status: contract.status,
      endsOn: contract.endsOn,
      terms: contract.terms,
    };
  },
};
