import { escapeHtml } from "./text.js";

const CSS = `
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f1ea; color: #1c1915; }
@media (prefers-color-scheme: dark) { body { background: #161410; color: #f4f1ea; } }
main { width: min(26rem, calc(100% - 2rem)); }
h1 { font-size: 1.35rem; font-weight: 650; margin: 0 0 0.4rem; }
p { margin: 0 0 1rem; line-height: 1.45; }
form, .providers { display: grid; gap: 0.6rem; }
a.button, button { font: inherit; text-decoration: none; text-align: center; border-radius: 999px; padding: 0.7rem 1rem; border: 1px solid #1c1915; background: #1c1915; color: #f4f1ea; cursor: pointer; }
@media (prefers-color-scheme: dark) { a.button, button { border-color: #f4f1ea; background: #f4f1ea; color: #161410; } }
label { display: grid; gap: 0.35rem; font-size: 0.95rem; }
input { font: inherit; padding: 0.65rem 0.8rem; border-radius: 0.7rem; border: 1px solid color-mix(in srgb, currentColor 35%, transparent); background: transparent; color: inherit; }
.note { color: color-mix(in srgb, currentColor 75%, transparent); font-size: 0.92rem; }
.error { color: #9f1239; }
@media (prefers-color-scheme: dark) { .error { color: #fda4af; } }
`;

function page(title: string, body: string): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><style>${CSS}</style></head><body><main>${body}</main></body></html>`;
}

export interface LoginPage {
  google?: string;
  github?: string;
  microsoft?: string;
  email: boolean;
  error?: string | null;
}

/** The account-origin sign-in page. Provider addresses are already absolute. */
export function loginPage(options: LoginPage): string {
  const buttons = [
    options.google ? `<a class="button" href="${escapeHtml(options.google)}">Continue with Google</a>` : "",
    options.github ? `<a class="button" href="${escapeHtml(options.github)}">Continue with GitHub</a>` : "",
    options.microsoft ? `<a class="button" href="${escapeHtml(options.microsoft)}">Continue with Microsoft</a>` : "",
  ].filter(Boolean).join("");
  const email = options.email ? `<form method="post" action="/email/start"><label>Email<input name="email" type="email" autocomplete="email" required></label><button type="submit">Email me a link</button></form>` : "";
  const error = options.error ? `<p class="error">${escapeHtml(options.error)}</p>` : "";
  return page("Sign in — FOSS Earth", `<h1>Sign in</h1><p>Sign in to use Google 3D Tiles on FOSS Earth apps. Flat maps keep working either way.</p>${error}<div class="providers">${buttons}</div>${email ? `<p class="note">Or use your email. The link expires in 15 minutes.</p>${email}` : ""}`);
}

export function emailSentPage(email: string): string {
  return page("Check your email — FOSS Earth", `<h1>Check your email</h1><p>A sign-in link is on its way to ${escapeHtml(email)}. It expires in 15 minutes and works once.</p>`);
}

export function messagePage(title: string, message: string): string {
  return page(`${title} — FOSS Earth`, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}
