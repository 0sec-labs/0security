import { Repo } from "../lib/store";
import type { Subscription } from "../models/billing";

export const subscriptionRepo = new Repo<Subscription>("subscription");
