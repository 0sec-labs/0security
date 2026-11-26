import { config } from "../lib/config";
import { hmacHex, safeEqual } from "../lib/hmac";

function fresh(timestamp: string): boolean {
  const seconds = Number(timestamp);
  if (!Number.isFinite(seconds)) return false;
  return Math.abs(Math.floor(Date.now() / 1000) - seconds) <= config.webhookToleranceSeconds;
}

/** Payments provider scheme: the signature is an HMAC of the delivery timestamp. */
export function verifyTimestampSignature(timestamp: string, signature: string): boolean {
  if (!fresh(timestamp)) return false;
  return safeEqual(hmacHex(config.webhookSecret, timestamp), signature);
}

/** Carrier scheme: the signature covers the timestamp and the exact body that was delivered. */
export function verifyBodySignature(timestamp: string, body: unknown, signature: string): boolean {
  if (!fresh(timestamp)) return false;
  return safeEqual(hmacHex(config.webhookSecret, timestamp + "." + JSON.stringify(body)), signature);
}
