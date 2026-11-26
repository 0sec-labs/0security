import { config } from "./config";
import { hmacHex, safeEqual } from "./hmac";

export interface ShareClaims {
  inv: string;
  org: string;
  exp: number;
}

export function signShare(invoiceId: string, orgId: string, ttlSeconds: number): string {
  const claims: ShareClaims = { inv: invoiceId, org: orgId, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return body + "." + hmacHex(config.shareSecret, body);
}

export function readShare(token: string): ShareClaims | null {
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return null;
  if (!safeEqual(hmacHex(config.shareSecret, body), signature)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as ShareClaims;
    if (typeof claims.inv !== "string" || typeof claims.org !== "string") return null;
    if (typeof claims.exp !== "number" || claims.exp < Math.floor(Date.now() / 1000)) return null;
    return claims;
  } catch {
    return null;
  }
}
