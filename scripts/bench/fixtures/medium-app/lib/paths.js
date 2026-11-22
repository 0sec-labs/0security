const path = require("path");

/** Join a user-supplied name under a base directory; refuse anything that leaves it. */
function safeJoin(base, name) {
  const resolved = path.resolve(base, String(name));
  if (resolved !== base && !resolved.startsWith(base + path.sep)) throw Object.assign(new Error("outside base"), { status: 400 });
  return resolved;
}

module.exports = { safeJoin };
