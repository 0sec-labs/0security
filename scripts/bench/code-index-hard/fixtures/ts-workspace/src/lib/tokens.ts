import { createHmac, timingSafeEqual } from "node:crypto";
import { env } from "../config/env";

function mac(value: string): string {
  return createHmac("sha256", env.tokenSecret).update(value).digest("base64url");
}

function same(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function issueToken(userId: string): string {
  const body = Buffer.from(userId).toString("base64url");
  return `${body}.${mac(body)}`;
}

export function readToken(token: string): string | null {
  const [body, signature] = token.split(".");
  if (!body || !signature || !same(signature, mac(body))) return null;
  return Buffer.from(body, "base64url").toString();
}

export interface ShareClaim {
  kind: string;
  id: string;
  expiresAt: number;
}

export function issueShareToken(kind: string, id: string, expiresAt: number): string {
  const body = Buffer.from(`${kind}:${id}:${expiresAt}`).toString("base64url");
  return `${body}.${mac(body)}`;
}

export function readShareToken(token: string): ShareClaim | null {
  const [body, signature] = token.split(".");
  if (!body || !signature || !same(signature, mac(body))) return null;
  const [kind, id, expiresAt] = Buffer.from(body, "base64url").toString().split(":");
  if (!kind || !id || !Number.isFinite(Number(expiresAt))) return null;
  return { kind, id, expiresAt: Number(expiresAt) };
}
