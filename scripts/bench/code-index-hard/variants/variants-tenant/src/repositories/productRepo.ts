import { Repo } from "../lib/store";
import type { Product } from "../models/catalog";

export const productRepo = new Repo<Product>("product");
