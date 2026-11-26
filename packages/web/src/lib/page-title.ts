import { useEffect } from "react";
import { matchPath } from "react-router-dom";
import { LEGACY_REDIRECTS } from "./workspace-navigation";

const SUFFIX = "0security";

const TITLES: Array<[RegExp, string]> = [
  [/^\/metrics(?:\/|$)/, "Run metrics"],
  [/^\/chats(?:\/|$)/, "Home"],
  [/^\/findings(?:\/|$)/, "Findings"],
  [/^\/sentinels(?:\/|$)/, "Sentinels"],
  [/^\/skills(?:\/|$)/, "Skills"],
  [/^\/extensions(?:\/|$)/, "Extensions"],
  [/^\/(?:settings|project)(?:\/|$)/, "Settings"],
  [/^\/(?:connections|models)(?:\/|$)/, "Models"],
  [/^\/doctor(?:\/|$)/, "Diagnostics"],
  [/^\/tools(?:\/|$)/, "Tools"],
  [/^\/api-access(?:\/|$)/, "API access"],
  [/^\/team(?:\/|$)/, "Team"],
  [/^\/computers(?:\/|$)/, "Computers"],
];

/** Paths that only redirect (see LEGACY_REDIRECTS) read as the app while the redirect lands. */
const isKnown = (pathname: string): boolean => pathname === "/" || LEGACY_REDIRECTS.some(row => row.routes.some(route => matchPath(route, pathname)));

/** Per-route document title, e.g. "Findings · 0security". Unknown paths read as a 404. */
export function pageTitleFor(pathname: string): string {
  const hit = TITLES.find(([pattern]) => pattern.test(pathname));
  if (hit) return `${hit[1]} · ${SUFFIX}`;
  return isKnown(pathname) ? `Command Center · ${SUFFIX}` : `Page not found · ${SUFFIX}`;
}

export function usePageTitle(pathname: string) {
  useEffect(() => { document.title = pageTitleFor(pathname); }, [pathname]);
}
