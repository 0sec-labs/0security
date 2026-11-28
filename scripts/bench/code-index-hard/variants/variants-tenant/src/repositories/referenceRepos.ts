import { RefRepo } from "../lib/store";
import type { Country, Currency, Plan } from "../models/catalog";

export const currencyRepo = new RefRepo<Currency>();
export const countryRepo = new RefRepo<Country>();
export const planRepo = new RefRepo<Plan>();
