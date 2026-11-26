import { Repo } from "../lib/store";
import type { CreditNote, Payment, Refund } from "../models/billing";

export const paymentRepo = new Repo<Payment>("payment");
export const creditNoteRepo = new Repo<CreditNote>("creditNote");
export const refundRepo = new Repo<Refund>("refund");
