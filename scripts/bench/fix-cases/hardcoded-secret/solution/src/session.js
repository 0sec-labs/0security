import { createHmac, timingSafeEqual } from "node:crypto";

function secret() {
  const value = process.env.SESSION_SECRET;
  if (!value) throw new Error("SESSION_SECRET is not set");
  return value;
}

export function signSession(userId) {
  const mac = createHmac("sha256", secret()).update(userId).digest("hex");
  return `${userId}.${mac}`;
}

export function verifySession(token) {
  const at = token.lastIndexOf(".");
  if (at < 1) return null;
  const userId = token.slice(0, at);
  const expected = Buffer.from(signSession(userId));
  const actual = Buffer.from(token);
  return expected.length === actual.length && timingSafeEqual(expected, actual) ? userId : null;
}
