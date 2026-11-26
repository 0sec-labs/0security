import { Repo } from "../lib/store";
import type { Contract } from "../models/billing";

export const contractRepo = new Repo<Contract>("contract");
