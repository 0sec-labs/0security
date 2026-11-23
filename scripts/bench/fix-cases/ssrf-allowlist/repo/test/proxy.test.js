import assert from "node:assert/strict";
import test from "node:test";
import { isAllowedUrl, proxyFetch } from "../src/proxy.js";

test("allows the partner API", () => {
  assert.equal(isAllowedUrl("https://api.example.com/v1/items?id=1"), true);
  assert.equal(isAllowedUrl("https://api.example.com"), true);
});

test("rejects other hosts", () => {
  assert.equal(isAllowedUrl("https://other.example.org/v1"), false);
  assert.equal(isAllowedUrl("http://api.example.com/v1"), false);
});

test("proxyFetch returns the body of an allowed URL", async () => {
  const body = await proxyFetch("https://api.example.com/v1", async () => ({ text: async () => "ok" }));
  assert.equal(body, "ok");
});

test("proxyFetch refuses a disallowed URL", async () => {
  await assert.rejects(() => proxyFetch("https://other.example.org/", async () => ({ text: async () => "x" })));
});
