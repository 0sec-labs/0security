import { invoiceRepo } from "../repositories/invoiceRepo";
import { subscriptionRepo } from "../repositories/subscriptionRepo";
import { userRepo } from "../repositories/userRepo";
import { planRepo } from "../repositories/referenceRepos";
import type { GraphqlContext } from "./executor";

type Args = Record<string, any>;

export const resolvers = {
  Query: {
    me: (_args: Args, ctx: GraphqlContext) => {
      const user = userRepo.findById(ctx.user.id);
      return user ? { id: user.id, email: user.email, name: user.name, role: user.role } : null;
    },

    customer: (args: Args, ctx: GraphqlContext) => {
      return ctx.loaders.customer.load(String(args.id));
    },

    invoices: (_args: Args, ctx: GraphqlContext) => {
      return invoiceRepo.listForOrg(ctx.user.orgId);
    },

    plans: () => planRepo.list(),

    subscription: (args: Args) => {
      const subscription = subscriptionRepo.findById(String(args.id));
      return subscription ?? null;
    },

    openInvoices: (_args: Args, ctx: GraphqlContext) => {
      return invoiceRepo.listOpenForOrg(ctx.user.orgId);
    },
  },
};
