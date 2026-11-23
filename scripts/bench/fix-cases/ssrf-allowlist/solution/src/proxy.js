const ALLOWED_HOST = "api.example.com";

// Only the partner API may be fetched on behalf of a user.
export function isAllowedUrl(raw) {
  let url;
  try { url = new URL(raw); } catch { return false; }
  return url.protocol === "https:" && url.hostname === ALLOWED_HOST && url.username === "" && url.password === "";
}

export async function proxyFetch(raw, fetchImpl = fetch) {
  if (!isAllowedUrl(raw)) throw new Error("host not allowed");
  const res = await fetchImpl(new URL(raw).href);
  return res.text();
}
