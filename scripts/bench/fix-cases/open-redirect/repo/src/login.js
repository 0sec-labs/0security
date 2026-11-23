// Where to send a user after a successful login. `next` comes from the query string.
export function redirectAfterLogin(next) {
  if (!next) return "/";
  return next;
}

export function loginResponse(next) {
  return { status: 302, headers: { Location: redirectAfterLogin(next) } };
}
