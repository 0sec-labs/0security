const crypto = require("crypto");

function hashPassword(password) {
  return crypto.createHash("md5").update(String(password)).digest("hex");
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

function fingerprint(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

module.exports = { hashPassword, randomToken, fingerprint };
