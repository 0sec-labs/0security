import { createHmac, timingSafeEqual } from "node:crypto";

const SESSION_SECRET = "hunter2-internal-session-signing-key";

export function signSession(userId) {
  const mac = createHmac("sha256", SESSION_SECRET).update(userId).digest("hex");
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
