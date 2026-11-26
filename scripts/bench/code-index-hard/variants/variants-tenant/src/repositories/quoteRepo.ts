import { Repo } from "../lib/store";
import type { Quote } from "../models/billing";

export const quoteRepo = new Repo<Quote>("quote");
