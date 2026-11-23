const ALLOWED_HOST = "api.example.com";

// Only the partner API may be fetched on behalf of a user.
export function isAllowedUrl(raw) {
  return raw.startsWith("https://" + ALLOWED_HOST);
}

export async function proxyFetch(raw, fetchImpl = fetch) {
  if (!isAllowedUrl(raw)) throw new Error("host not allowed");
  const res = await fetchImpl(raw);
  return res.text();
}
