// Small helpers for prove.mjs: an HTTP client and a PASS/FAIL table runner.
export function makeClient(base) {
  return async function http(method, path, { token, body, headers = {} } = {}) {
    const init = { method, headers: { ...headers } };
    if (token) init.headers.authorization = "Bearer " + token;
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await fetch(base + path, init);
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = undefined; }
    return { status: res.status, text, json };
  };
}

/** Runs cases in order, prints a table, returns the number of failures. */
export async function runCases(cases) {
  let failures = 0;
  const counts = {};
  for (const c of cases) {
    let verdict = "PASS";
    let detail = "";
    try {
      await c.fn();
    } catch (err) {
      verdict = "FAIL";
      detail = "  -> " + (err instanceof Error ? err.message : String(err));
      failures++;
    }
    counts[c.group] ??= { pass: 0, fail: 0 };
    counts[c.group][verdict === "PASS" ? "pass" : "fail"]++;
    console.log(verdict + "  " + c.group.padEnd(8) + " " + c.name + detail);
  }
  console.log("");
  for (const [group, n] of Object.entries(counts)) console.log(group.padEnd(8) + " " + n.pass + " pass, " + n.fail + " fail");
  console.log(failures ? failures + " case(s) FAILED" : "all " + cases.length + " cases passed");
  return failures;
}
