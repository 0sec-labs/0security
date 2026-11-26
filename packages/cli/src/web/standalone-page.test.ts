import { describe, expect, it } from "vitest";
import { buildContentSecurityPolicy } from "./dashboard-csp.js";
import { escapeHtml, loginPageHtml, signInCompletePageHtml, standalonePage } from "./standalone-page.js";

const pages = {
  token: loginPageHtml({ teamMode: false, sso: false, saml: false }),
  team: loginPageHtml({ teamMode: true, sso: false, saml: false }),
  both: loginPageHtml({ teamMode: true, sso: true, saml: true }),
  done: signInCompletePageHtml(true),
  failed: signInCompletePageHtml(false),
};

describe("sign-in page", () => {
  it("names the product and labels the access token field", () => {
    expect(pages.token).toContain("<h1>Sign in to 0security</h1>");
    expect(pages.token).toContain('<label for="token">Access token</label>');
    expect(pages.token).toMatch(/<input id="token"[^>]*autocomplete="current-password"[^>]*autofocus>/);
    expect(pages.token).toContain("<title>Sign in - 0security</title>");
  });

  it("labels the team fields with autocomplete hints and focuses the first", () => {
    expect(pages.team).toContain('<label for="userId">User ID</label>');
    expect(pages.team).toContain('<label for="password">Password</label>');
    expect(pages.team).toMatch(/<input id="userId"[^>]*autocomplete="username"[^>]*autofocus>/);
    expect(pages.team).toMatch(/<input id="password"[^>]*type="password"[^>]*autocomplete="current-password"/);
    expect(pages.team.indexOf('id="userId"')).toBeLessThan(pages.team.indexOf('id="password"'));
    expect(pages.team.match(/autofocus/g)).toHaveLength(1);
  });

  it("has an announced error region and an enabled submit button", () => {
    expect(pages.team).toContain('<p id="m" class="msg" role="alert"></p>');
    expect(pages.team).toMatch(/<button class="btn primary" type="submit">Sign in<\/button>/);
    expect(pages.team).not.toMatch(/<button[^>]*disabled/);
    expect(pages.team).toContain("Signing in");
  });

  it("keeps the endpoint and request shape of the sign-in script", () => {
    expect(pages.team).toContain('fetch("/_access/login",{method:"POST",headers:{"Content-Type":"application/json"}');
    expect(pages.team).toContain('credentials:"same-origin"');
    expect(pages.team).toContain('location.replace("/")');
  });

  it("shows SSO and SAML buttons only when enabled", () => {
    for (const html of [pages.token, pages.team]) {
      expect(html).not.toContain("/api/team/auth/");
      expect(html).not.toContain('class="divider"');
    }
    expect(pages.both).toContain('<a class="btn secondary" href="/api/team/auth/sso">Sign in with single sign-on</a>');
    expect(pages.both).toContain('<a class="btn secondary" href="/api/team/auth/saml/sso">Sign in with SAML</a>');
    expect(pages.both).toContain("<span>or</span>");
    const onlySaml = loginPageHtml({ teamMode: true, sso: false, saml: true });
    expect(onlySaml).toContain("/api/team/auth/saml/sso");
    expect(onlySaml).not.toContain('href="/api/team/auth/sso"');
  });

  it("supports both colour schemes and reduced motion", () => {
    expect(pages.team).toContain("color-scheme:light dark");
    expect(pages.team).toContain("prefers-color-scheme:dark");
    expect(pages.team).toContain("prefers-reduced-motion:reduce");
    expect(pages.team).toContain(":focus-visible");
  });
});

describe("standalone pages", () => {
  it("make no external request and use no inline style attributes", () => {
    for (const [name, html] of Object.entries(pages)) {
      expect(html, name).not.toMatch(/https?:\/\//i);
      expect(html, name).not.toMatch(/<(link|img|iframe|object|embed)\b|@import|url\(|\sstyle=|\ssrc=/i);
      expect(html, name).not.toMatch(/[\u{1F300}-\u{1FAFF}☀-➿]/u);
    }
  });

  it("is covered by the strict script policy through a hash", () => {
    const csp = buildContentSecurityPolicy(pages.team);
    expect(csp).toMatch(/script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/);
    expect(buildContentSecurityPolicy(pages.done)).toContain("script-src 'self';");
  });

  it("completion pages carry no script and echo nothing from the request", () => {
    expect(pages.done).toContain("Sign-in complete");
    expect(pages.failed).toContain("Sign-in was not completed");
    expect(pages.done).not.toContain("<script");
    expect(pages.failed).not.toContain("<script");
  });

  it("escapes interpolated text", () => {
    expect(escapeHtml(`<img src=x onerror="a()">&'`)).toBe("&lt;img src=x onerror=&quot;a()&quot;&gt;&amp;&#39;");
    const html = standalonePage({ title: `</title><script>alert(1)</script>`, card: "" });
    expect(html).toContain("<title>&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;</title>");
    expect(html).not.toContain("<script>alert(1)");
  });
});
