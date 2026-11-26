import { Repo } from "../lib/store";
import type { Customer } from "../models/billing";

export const customerRepo = new Repo<Customer>("customer");
