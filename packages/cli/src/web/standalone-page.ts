// Standalone HTML pages the server renders outside the React console: the sign-in page and the loopback
// "sign-in complete" page. They are plain HTML with one embedded <style> block whose variables mirror the console
// tokens in packages/web/src/styles.css (neutral accent, light and dark by prefers-color-scheme). They make no
// external request: the wordmark is inline SVG and the font stack falls back to the system face when Inter is absent.

const ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/** Escape text for an HTML text node or a quoted attribute value. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, ch => ESCAPES[ch] ?? ch);
}

const WORDMARK = `<svg class="wordmark" viewBox="-2 -2 240 24" role="img" aria-label="0security"><path fill="#FD802E" d="M12.5 2 H17.5 L7.5 18 H2.5 Z"/><g fill="currentColor"><path fill-rule="evenodd" d="M4 0 H16 L20 4 V16 L16 20 H4 L0 16 V4 Z M4 5 V15 L5 16 H15 L16 15 V5 L15 4 H5 Z"/><path transform="translate(28,0)" d="M0 0 H20 V4 H0 Z M0 4 H4 V8 H0 Z M0 8 H20 V12 H0 Z M16 12 H20 V16 H16 Z M0 16 H20 V20 H0 Z"/><path transform="translate(56,0)" d="M0 0 H20 V4 H0 Z M0 0 H4 V20 H0 Z M0 8 H16 V12 H0 Z M0 16 H20 V20 H0 Z"/><path transform="translate(84,0)" d="M0 0 H20 V4 H0 Z M0 0 H4 V20 H0 Z M0 16 H20 V20 H0 Z"/><path transform="translate(112,0)" d="M0 0H4V16H16V0H20V20H0Z"/><path fill-rule="evenodd" transform="translate(140,0)" d="M0 0H20V12H12L20 20H14.4L6.4 12H4V20H0Z M4 4V8H16V4Z"/><path transform="translate(168,0)" d="M0 0H12V4H8V16H12V20H0V16H4V4H0Z"/><path transform="translate(188,0)" d="M0 0H20V4H12V20H8V4H0Z"/><path transform="translate(216,0)" d="M0 0H4V8H16V0H20V12H12V20H8V12H0Z"/></g></svg>`;

const CSS = `
:root{color-scheme:light dark;--bg:oklch(96.2% .0025 290);--fg:oklch(23.5% .0038 290);--card:oklch(100% 0 0);--muted:color-mix(in oklch,var(--fg) 62%,var(--bg));--line:oklch(0% 0 0 / .11);--line-strong:oklch(0% 0 0 / .22);--primary:#18181b;--primary-fg:#fff;--primary-hover:color-mix(in oklch,var(--primary) 82%,white);--secondary:oklch(0% 0 0 / .05);--secondary-hover:oklch(0% 0 0 / .08);--ring:color-mix(in oklch,var(--primary) 55%,transparent);--danger:oklch(50% .2 27);--shadow:0 6px 18px oklch(0% 0 0 / .04),0 1px 2px oklch(0% 0 0 / .06)}
@media (prefers-color-scheme:dark){:root{--bg:oklch(14.03% .0022 286.1);--fg:oklch(94.04% .0013 286.4);--card:oklch(21.82% .0019 286.2);--muted:color-mix(in oklch,var(--fg) 68%,var(--bg));--line:oklch(100% 0 0 / .12);--line-strong:oklch(100% 0 0 / .24);--primary:#fafafa;--primary-fg:#18181b;--primary-hover:color-mix(in oklch,var(--primary) 86%,black);--secondary:oklch(100% 0 0 / .08);--secondary-hover:oklch(100% 0 0 / .11);--ring:color-mix(in oklch,var(--primary) 70%,transparent);--danger:oklch(74% .16 25);--shadow:0 0 0 1px oklch(0% 0 0 / .3),0 3px 8px oklch(0% 0 0 / .09)}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:1.5rem 1rem;background:var(--bg);color:var(--fg);font:14px/1.5 "Inter Variable",Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;letter-spacing:-.01em;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:24rem;display:flex;flex-direction:column;align-items:center;gap:1.5rem}
.wordmark{display:block;width:11rem;max-width:70%;height:auto;color:var(--fg)}
.card{width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:2rem 1.75rem;box-shadow:var(--shadow)}
h1{margin:0;font-size:1.375rem;line-height:1.25;font-weight:560;letter-spacing:-.02em;text-align:center}
.lead{margin:.5rem 0 0;color:var(--muted);text-align:center}
form{margin:1.5rem 0 0}
.field+.field{margin-top:1rem}
label{display:block;margin:0 0 .375rem;font-weight:500}
input{display:block;width:100%;height:2.5rem;padding:0 .75rem;font:inherit;letter-spacing:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line-strong);border-radius:6px;transition:border-color .1s,box-shadow .1s}
input:hover{border-color:color-mix(in oklch,var(--fg) 40%,var(--bg))}
input:focus-visible,.btn:focus-visible{outline:2px solid var(--ring);outline-offset:2px}
input:focus-visible{border-color:var(--fg)}
input[aria-invalid=true]{border-color:var(--danger)}
.msg{min-height:1.25rem;margin:.75rem 0 0;color:var(--danger);font-weight:500;overflow-wrap:anywhere}
.btn{display:flex;align-items:center;justify-content:center;width:100%;height:2.5rem;padding:0 1rem;font:inherit;font-weight:500;letter-spacing:inherit;text-decoration:none;cursor:pointer;border:1px solid transparent;border-radius:6px;transition:background-color .1s,border-color .1s}
.primary{margin-top:.5rem;background:var(--primary);color:var(--primary-fg)}
.primary:hover{background:var(--primary-hover)}
.primary:disabled{opacity:.65;cursor:progress}
.secondary{color:var(--fg);background:var(--secondary);border-color:var(--line-strong)}
.secondary:hover{background:var(--secondary-hover)}
.secondary+.secondary{margin-top:.5rem}
.divider{display:flex;align-items:center;gap:.75rem;margin:1.25rem 0;color:var(--muted);font-size:13px}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--line)}
.note{margin:1.5rem 0 0;color:var(--muted);font-size:13px;text-align:center}
@media (max-width:400px){body{padding:1rem .75rem}.card{padding:1.5rem 1.25rem}}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
`.replace(/\n/g, "");

export interface StandalonePage {
  /** Document title; escaped. */
  title: string;
  /** Trusted markup for inside the card (build interpolated text with escapeHtml). */
  card: string;
  /** Inline script source, covered by the CSP hash. */
  script?: string;
}

/** The shared shell: wordmark above one centered card, theme by prefers-color-scheme, no external requests. */
export function standalonePage(page: StandalonePage): string {
  const script = page.script ? `<script>${page.script}</script>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>${escapeHtml(page.title)}</title><style>${CSS}</style></head><body><main>${WORDMARK}<div class="card">${page.card}</div></main>${script}</body></html>`;
}

export interface LoginPageMode { teamMode: boolean; sso: boolean; saml: boolean }

/** Client script for the sign-in form: same endpoint and body as before, plus a busy state and field error marks. */
const LOGIN_SCRIPT = `const f=document.querySelector("form"),m=document.querySelector("#m"),s=f.querySelector("button"),i=f.querySelectorAll("input");const bad=v=>i.forEach(x=>v?x.setAttribute("aria-invalid","true"):x.removeAttribute("aria-invalid"));f.addEventListener("submit",async e=>{e.preventDefault();if(s.disabled)return;m.textContent="";bad(false);s.disabled=true;s.textContent="Signing in\\u2026";const b=Object.fromEntries(new FormData(f));try{const r=await fetch("/_access/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b),credentials:"same-origin"});if(r.ok){location.replace("/");return}const d=await r.json().catch(()=>({}));m.textContent=d.error||"Sign-in failed.";bad(true)}catch{m.textContent="Could not reach the server."}s.disabled=false;s.textContent="Sign in";const x=i[i.length-1];x.focus()});`;

export function loginPageHtml(mode: LoginPageMode): string {
  const fields = mode.teamMode
    ? `<div class="field"><label for="userId">User ID</label><input id="userId" name="userId" type="text" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="m" required autofocus></div><div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" aria-describedby="m" required></div>`
    : `<div class="field"><label for="token">Access token</label><input id="token" name="token" type="password" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" aria-describedby="m" required autofocus></div>`;
  const lead = mode.teamMode ? "Enter your user ID and password." : "Enter the access token for this server.";
  const alternatives = [
    mode.sso ? `<a class="btn secondary" href="/api/team/auth/sso">Sign in with single sign-on</a>` : "",
    mode.saml ? `<a class="btn secondary" href="/api/team/auth/saml/sso">Sign in with SAML</a>` : "",
  ].join("");
  const card = `<h1>Sign in to 0security</h1><p class="lead">${lead}</p><form method="post" action="/_access/login">${fields}<p id="m" class="msg" role="alert"></p><button class="btn primary" type="submit">Sign in</button></form>${alternatives ? `<div class="divider" role="separator"><span>or</span></div><div class="alt-list">${alternatives}</div>` : ""}`;
  return standalonePage({ title: "Sign in - 0security", card, script: LOGIN_SCRIPT });
}

/** The page a loopback sign-in callback shows. No interpolated text: the provider's error code is never echoed. */
export function signInCompletePageHtml(ok: boolean): string {
  const card = ok
    ? `<h1>Sign-in complete</h1><p class="lead">You can close this tab and return to 0security.</p>`
    : `<h1>Sign-in was not completed</h1><p class="lead">Return to 0security and start the sign-in again.</p>`;
  return standalonePage({ title: ok ? "Sign-in complete - 0security" : "Sign-in not completed - 0security", card });
}
