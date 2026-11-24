import { assertEgressAllowed } from "../../policy/enterprise.js";
import { readWebSearchResponse, type WebSearchResult } from "./web-search-response.js";

// Opt-in web_search backend. Selected only with ZERO_WEB_SEARCH_PROVIDER=keenable.
// The request carries the model-written query and nothing else. KEENABLE_API_KEY
// (process environment only) switches to the keyed endpoint for a higher rate limit.
export const KEENABLE_HOST = "api.keenable.ai";
export const KEENABLE_PUBLIC_ENDPOINT = `https://${KEENABLE_HOST}/v1/search/public`;
export const KEENABLE_KEYED_ENDPOINT = `https://${KEENABLE_HOST}/v1/search`;
type SearchResult = { ok: true; results: WebSearchResult[] } | { ok: false; error: string };

export type WebSearchProvider = "parallel" | "keenable";

/** Unset or "parallel" keeps the default. Any other value is an error, never a silent choice. */
export function selectedWebSearchProvider(env: NodeJS.ProcessEnv = process.env): { provider: WebSearchProvider } | { error: string } {
  const raw = env["ZERO_WEB_SEARCH_PROVIDER"]?.trim().toLowerCase();
  if (!raw || raw === "parallel") return { provider: "parallel" };
  if (raw === "keenable") return { provider: "keenable" };
  return { error: `Unknown ZERO_WEB_SEARCH_PROVIDER "${raw.slice(0, 40)}". Use "parallel" or "keenable", or unset it.` };
}

const object = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
const clean = (value: unknown): string => typeof value === "string" ? value.replace(/\s+/g, " ").trim() : "";

function normalize(payload: unknown): SearchResult {
  const list = object(payload)?.results;
  if (!Array.isArray(list)) return { ok: false, error: "Keenable search returned an unrecognized result shape." };
  const results: WebSearchResult[] = [];
  const seen = new Set<string>();
  for (const item of list) {
    const source = object(item);
    if (typeof source?.url !== "string" || source.url.length > 4096 || /[\u0000- \u007f]/.test(source.url)) continue;
    let url: URL;
    try { url = new URL(source.url); } catch { continue; }
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password || url.href.length > 4096) continue;
    if (seen.has(url.href)) continue;
    seen.add(url.href);
    results.push({
      title: (clean(source.title) || url.href).slice(0, 300),
      url: url.href,
      snippet: (clean(source.snippet) || clean(source.description)).slice(0, 1000),
    });
    if (results.length === 5) break;
  }
  if (!results.length && list.length) return { ok: false, error: "Keenable search returned no usable source URLs." };
  return { ok: true, results };
}

/** One POST. The caller supplies the scoped, authority-checked transport and the deadline. */
export async function searchKeenable(query: string, options: { signal: AbortSignal; fetchImpl: typeof fetch; env?: NodeJS.ProcessEnv }): Promise<SearchResult> {
  const { signal, fetchImpl } = options;
  const env = options.env ?? process.env;
  assertEgressAllowed(`${KEENABLE_HOST} (web search)`, env);
  const apiKey = env["KEENABLE_API_KEY"]?.trim();
  try {
    signal.throwIfAborted();
    const response = await fetchImpl(apiKey ? KEENABLE_KEYED_ENDPOINT : KEENABLE_PUBLIC_ENDPOINT, {
      method: "POST", redirect: "error", signal,
      headers: {
        "Content-Type": "application/json", Accept: "application/json", "X-Keenable-Title": "0security",
        ...(apiKey ? { "X-API-Key": apiKey } : {}),
      },
      body: JSON.stringify({ query, max_results: 5 }),
    });
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      return { ok: false, error: `Keenable search request failed (HTTP ${response.status}).` };
    }
    const text = await readWebSearchResponse(response, signal);
    signal.throwIfAborted();
    return normalize(JSON.parse(text));
  } catch (error) {
    signal.throwIfAborted();
    return { ok: false, error: error instanceof SyntaxError ? "Keenable search returned malformed JSON." : error instanceof Error ? error.message : "Keenable search failed." };
  }
}
