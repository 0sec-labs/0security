import { Repo } from "../lib/store";
import type { Category, Coupon, PriceList, TaxRate, ApiKeyRecord, WebhookEndpoint } from "../models/finance";

export const categoryRepo = new Repo<Category>("categories");
export const couponRepo = new Repo<Coupon>("coupons");
export const priceListRepo = new Repo<PriceList>("priceLists");
export const taxRateRepo = new Repo<TaxRate>("taxRates");
export const apiKeyRepo = new Repo<ApiKeyRecord>("apiKeys");
export const webhookEndpointRepo = new Repo<WebhookEndpoint>("webhookEndpoints");
