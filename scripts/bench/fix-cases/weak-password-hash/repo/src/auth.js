import { createHash } from "node:crypto";

// Passwords are stored as the value returned by hashPassword.
export function hashPassword(password) {
  return createHash("md5").update(password).digest("hex");
}

export function verifyPassword(password, stored) {
  return hashPassword(password) === stored;
}
