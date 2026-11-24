// Route shapes for browser-driven single sign-on. One place, so the request guards and the router agree.
export const SAML_PREFIX = "/api/team/auth/saml/";
export const SAML_ACS_PATH = `${SAML_PREFIX}acs`;

const pathOf = (target: string): string => target.split("?")[0] ?? "";

/** The SAML assertion consumer service: the identity provider's browser posts the sign-in response here. */
export function isSamlAcsPost(method: string | undefined, target: string | undefined): boolean {
  return method === "POST" && pathOf(target ?? "") === SAML_ACS_PATH;
}

/**
 * Requests a browser makes while signing in, before it has a session. They carry no control token and no
 * session. Each one proves itself inside its handler (one-use state, a browser cookie and, for SAML, a signed response).
 */
export function isTeamSsoRoute(method: string | undefined, pathname: string): boolean {
  if (method === "GET") return pathname === "/api/team/auth/sso" || pathname === "/api/team/auth/callback"
    || pathname === `${SAML_PREFIX}sso` || pathname === `${SAML_PREFIX}complete` || pathname === `${SAML_PREFIX}metadata`;
  return isSamlAcsPost(method, pathname);
}

/**
 * Requests the browser sends as a cross-site navigation by design: the OIDC provider returns by GET, the SAML
 * identity provider posts the response and is then redirected to the completion step.
 */
export function isCrossSiteSignInReturn(method: string | undefined, target: string | undefined): boolean {
  const path = pathOf(target ?? "");
  if (isSamlAcsPost(method, path)) return true;
  return method === "GET" && (path === "/api/team/auth/callback" || path === `${SAML_PREFIX}complete`);
}
