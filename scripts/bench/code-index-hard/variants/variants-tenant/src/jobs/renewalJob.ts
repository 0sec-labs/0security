import { contractRepo } from "../repositories/contractRepo";
import type { Job } from "./queue";

export async function contractRenewal(job: Job<{ contractId: string }>) {
  const contract = contractRepo.findById(job.payload.contractId);
  if (!contract || contract.orgId !== job.orgId) throw new Error("contract not found");
  return { contractId: contract.id, title: contract.title, notified: true, endsOn: contract.endsOn };
}
