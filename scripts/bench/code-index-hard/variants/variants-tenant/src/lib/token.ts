import { config } from "./config";
import { hmacHex, safeEqual } from "./hmac";

export interface TokenClaims {
  sub: string;
  exp: number;
}

export function signToken(sub: string, ttlSeconds: number = config.tokenTtlSeconds): string {
  const claims: TokenClaims = { sub, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  return body + "." + hmacHex(config.tokenSecret, body);
}

export function verifyToken(token: string): TokenClaims | null {
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return null;
  if (!safeEqual(hmacHex(config.tokenSecret, body), signature)) return null;
  let claims: TokenClaims;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (typeof claims.sub !== "string" || typeof claims.exp !== "number") return null;
  if (claims.exp < Math.floor(Date.now() / 1000)) return null;
  return claims;
}
