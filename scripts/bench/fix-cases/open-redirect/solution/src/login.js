// Where to send a user after a successful login. `next` comes from the query string.
// Only a local path is allowed: one leading slash, no second slash or backslash after it.
export function redirectAfterLogin(next) {
  if (typeof next !== "string" || !/^\/(?![/\\])[^\r\n\t\\]*$/.test(next)) return "/";
  return next;
}

export function loginResponse(next) {
  return { status: 302, headers: { Location: redirectAfterLogin(next) } };
}
