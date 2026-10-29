import type { DatabaseSync } from "node:sqlite";
import { emailSentPage, loginPage, messagePage } from "./pages.js";
import type { OAuthProvider, ProviderId } from "./providers.js";
import { ProviderError } from "./providers.js";
import {
  AccountDisabled, GOOGLE_TILES, accountForIdentity, consumeAuthCode, consumeMagicLink, createAuthCode,
  createBrowserSession, createMagicLink, createPending, findClient, issueTokens, quotaFor, readBrowserSession,
  readPending, registeredOrigins, reserveRoot, resolveAccessToken, revokeAccountSessions, rotateRefresh,
  type AccountRow, type ClientRecord,
} from "./records.js";
import { looksLikeEmail, normalizeEmail, sha256 } from "./text.js";

const SESSION_COOKIE = "fe_session";
const LOGIN_COOKIE = "fe_login";
const TILES_PREFIX = "/v1/3dtiles/";
const ROOT_PATH = "/v1/3dtiles/root.json";
const CACHE_MS = 60_000;

export interface Mailer {
  send(message: { to: string; subject: string; text: string }): Promise<void>;
}

export interface AccountAppOptions {
  database: DatabaseSync;
  accountOrigin: string;
  clients: readonly ClientRecord[];
  providers: Partial<Record<ProviderId, OAuthProvider>>;
  mail?: Mailer;
  googleTilesKey?: string | null;
  rootsPerDay?: number;
  rootsFirstDay?: number;
  now?: () => Date;
  upstream?: (url: string, init: RequestInit) => Promise<Response>;
}

interface TokenCacheEntry {
  account: AccountRow | null;
  expiresAt: string;
  checkedAt: number;
}

export interface AccountApp {
  handle(request: Request): Promise<Response>;
}

export function createAccountApp(options: AccountAppOptions): AccountApp {
  const now = options.now ?? (() => new Date());
  const rootsPerDay = options.rootsPerDay ?? 40;
  const rootsFirstDay = options.rootsFirstDay ?? 10;
  const upstream = options.upstream ?? ((url, init) => fetch(url, init));
  const origins = registeredOrigins(options.clients);
  const tokenCache = new Map<string, TokenCacheEntry>();
  const mailHits = new Map<string, number[]>();

  const allow = (request: Request): string | null => {
    const origin = request.headers.get("origin");
    if (!origin || !origins.has(origin)) return null;
    return origin;
  };

  const cors = (request: Request, response: Response): Response => {
    const origin = allow(request);
    if (!origin) return response;
    const headers = new Headers(response.headers);
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-headers", "authorization, content-type");
    headers.set("vary", "Origin");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  };

  const html = (body: string, status = 200, extra?: Headers): Response => {
    const headers = extra ?? new Headers();
    headers.set("content-type", "text/html; charset=utf-8");
    headers.set("cache-control", "no-store");
    return new Response(body, { status, headers });
  };

  const json = (body: unknown, status: number, request?: Request): Response => {
    const response = new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
    return request ? cors(request, response) : response;
  };

  const cookie = (request: Request, name: string): string | null => {
    const header = request.headers.get("cookie");
    if (!header) return null;
    for (const part of header.split(";")) {
      const split = part.indexOf("=");
      if (split === -1) continue;
      if (part.slice(0, split).trim() === name) return decodeURIComponent(part.slice(split + 1).trim());
    }
    return null;
  };

  const setCookie = (headers: Headers, name: string, value: string, maxAge: number): void => {
    const secure = options.accountOrigin.startsWith("https://") ? "; Secure" : "";
    headers.append("set-cookie", `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`);
  };

  const clientIp = (request: Request): string => request.headers.get("x-foss-earth-client") ?? "unknown";

  const limited = (key: string, limit: number, windowMs: number): boolean => {
    const at = now().getTime();
    const hits = (mailHits.get(key) ?? []).filter(time => at - time < windowMs);
    if (hits.length >= limit) {
      mailHits.set(key, hits);
      return true;
    }
    hits.push(at);
    mailHits.set(key, hits);
    return false;
  };

  const providerLinks = (pendingId: string): { google?: string; github?: string; microsoft?: string } => {
    const links: { google?: string; github?: string; microsoft?: string } = {};
    for (const id of ["google", "github", "microsoft"] as const) {
      if (options.providers[id]) links[id] = `/start/${id}?login=${encodeURIComponent(pendingId)}`;
    }
    return links;
  };

  const complete = (accountId: string, pending: { client_id: string; redirect_uri: string; code_challenge: string; app_state: string }): Response => {
    const at = now();
    const session = createBrowserSession(options.database, accountId, at);
    const code = createAuthCode(options.database, {
      clientId: pending.client_id, redirectUri: pending.redirect_uri, accountId, codeChallenge: pending.code_challenge, now: at,
    });
    const destination = new URL(pending.redirect_uri);
    destination.searchParams.set("code", code);
    destination.searchParams.set("state", pending.app_state);
    const headers = new Headers({ location: destination.toString(), "cache-control": "no-store" });
    setCookie(headers, SESSION_COOKIE, `${session.id}.${session.secret}`, 30 * 24 * 3600);
    setCookie(headers, LOGIN_COOKIE, "", 0);
    return new Response(null, { status: 302, headers });
  };

  const tokenBody = (current: AccountRow, tokens: { accessToken: string; refreshToken: string; expiresAt: string }): Record<string, unknown> => {
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresAt: tokens.expiresAt,
      account: { id: current.id, email: current.email },
      entitlements: [GOOGLE_TILES],
      quota: { [GOOGLE_TILES]: quotaFor(options.database, current, now(), rootsPerDay, rootsFirstDay) },
    };
  };

  const tilesPath = (url: URL): string | null => {
    if (!url.pathname.startsWith(TILES_PREFIX) || url.pathname.includes("\\")) return null;
    const parts = url.pathname.split("/");
    if (parts.some(part => part === "" ? false : part === "." || part === "..")) return null;
    return url.pathname;
  };

  async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      const origin = allow(request);
      if (!origin) return new Response(null, { status: 403 });
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "authorization, content-type",
          "access-control-max-age": "600",
          vary: "Origin",
        },
      });
    }
    if (request.method === "GET" && url.pathname === "/health") return json({ ok: true }, 200);
    if (request.method === "GET" && url.pathname === "/authorize") return authorize(request, url);
    if (request.method === "GET" && url.pathname.startsWith("/start/")) return startProvider(request, url);
    if (request.method === "GET" && url.pathname.startsWith("/callback/")) return callback(url);
    if (request.method === "POST" && url.pathname === "/email/start") return startEmail(request);
    if (request.method === "GET" && url.pathname === "/email/sent") return html(emailSentPage("your inbox"));
    if (request.method === "GET" && url.pathname === "/email/verify") return verifyEmail(url);
    if (request.method === "POST" && url.pathname === "/token") return token(request);
    if (request.method === "GET" && url.pathname === "/logout") return logout(request, url);
    if ((request.method === "GET" || request.method === "HEAD") && url.pathname.startsWith(TILES_PREFIX)) return proxyTiles(request, url);
    return html(messagePage("Not found", "That page is not on this server."), 404);
  }

  function authorize(request: Request, url: URL): Response {
    const clientId = url.searchParams.get("client_id") ?? "";
    const redirectUri = url.searchParams.get("redirect_uri") ?? "";
    const challenge = url.searchParams.get("code_challenge") ?? "";
    const method = url.searchParams.get("code_challenge_method");
    const state = url.searchParams.get("state") ?? "";
    if (url.searchParams.get("response_type") !== "code" || method !== "S256" || !challenge || state.length > 2000 || !findClient(options.clients, clientId, redirectUri)) {
      return html(messagePage("Sign-in refused", "This app is not registered for that address."), 400);
    }
    const at = now();
    const session = readBrowserSession(options.database, cookie(request, SESSION_COOKIE), at);
    if (session) {
      const code = createAuthCode(options.database, { clientId, redirectUri, accountId: session.id, codeChallenge: challenge, now: at });
      const destination = new URL(redirectUri);
      destination.searchParams.set("code", code);
      destination.searchParams.set("state", state);
      return new Response(null, { status: 302, headers: { location: destination.toString(), "cache-control": "no-store" } });
    }
    const pending = createPending(options.database, { clientId, redirectUri, codeChallenge: challenge, appState: state, now: at });
    const headers = new Headers({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    setCookie(headers, LOGIN_COOKIE, pending, 15 * 60);
    return new Response(loginPage({ ...providerLinks(pending), email: Boolean(options.mail) }), { status: 200, headers });
  }

  function startProvider(request: Request, url: URL): Response {
    const id = url.pathname.slice("/start/".length) as ProviderId;
    const provider = options.providers[id];
    const pendingId = url.searchParams.get("login") || cookie(request, LOGIN_COOKIE);
    if (!provider || !pendingId || !readPending(options.database, pendingId, now())) {
      return html(messagePage("Sign-in expired", "Start again from the app."), 400);
    }
    return new Response(null, { status: 302, headers: { location: provider.authorizationUrl(pendingId), "cache-control": "no-store" } });
  }

  async function callback(url: URL): Promise<Response> {
    const id = url.pathname.slice("/callback/".length) as ProviderId;
    const provider = options.providers[id];
    const pendingId = url.searchParams.get("state") ?? "";
    const code = url.searchParams.get("code") ?? "";
    const pending = provider && code ? readPending(options.database, pendingId, now()) : null;
    if (!provider || !pending) return html(messagePage("Sign-in expired", "Start again from the app."), 400);
    try {
      const proof = await provider.exchange(code);
      const account = accountForIdentity(options.database, proof, now());
      return complete(account.id, pending);
    } catch (error) {
      const message = error instanceof ProviderError || error instanceof AccountDisabled ? error.message : "Sign-in did not finish.";
      return html(loginPage({ ...providerLinks(pending.id), email: Boolean(options.mail), error: message }), 400);
    }
  }

  async function startEmail(request: Request): Promise<Response> {
    if (!options.mail) return html(messagePage("Email is not available", "Choose another way to sign in."), 404);
    const pending = readPending(options.database, cookie(request, LOGIN_COOKIE) ?? "", now());
    if (!pending) return html(messagePage("Sign-in expired", "Start again from the app."), 400);
    const form = await request.formData().catch(() => null);
    const email = normalizeEmail(String(form?.get("email") ?? ""));
    const ip = clientIp(request);
    if (limited(`ip:${ip}`, 20, 60 * 60 * 1000) || limited(`email:${email}`, 5, 60 * 60 * 1000)) {
      return html(messagePage("Slow down", "Wait a while before asking for another link."), 429);
    }
    if (!looksLikeEmail(email)) return html(loginPage({ ...providerLinks(pending.id), email: true, error: "Enter an email address." }), 400);
    const token = createMagicLink(options.database, email, pending.id, now());
    const link = `${options.accountOrigin}/email/verify?token=${encodeURIComponent(token)}`;
    try {
      await options.mail.send({
        to: email,
        subject: "Sign in to FOSS Earth",
        text: `Sign in to FOSS Earth\n\n${link}\n\nThis link expires in 15 minutes and works once.\n`,
      });
    } catch {
      return html(messagePage("Email was not sent", "Try again in a moment, or choose another way to sign in."), 502);
    }
    return new Response(null, { status: 302, headers: { location: "/email/sent", "cache-control": "no-store" } });
  }

  function verifyEmail(url: URL): Response {
    const consumed = consumeMagicLink(options.database, url.searchParams.get("token") ?? "", now());
    const pending = consumed ? readPending(options.database, consumed.pendingId, now()) : null;
    if (!consumed || !pending) return html(messagePage("Link expired", "That sign-in link has already been used or has expired. Start again from the app."), 400);
    try {
      const account = accountForIdentity(options.database, { provider: "email", subject: consumed.email, email: consumed.email }, now());
      return complete(account.id, pending);
    } catch (error) {
      const message = error instanceof AccountDisabled ? error.message : "Sign-in did not finish.";
      return html(messagePage("Sign-in refused", message), 400);
    }
  }

  async function token(request: Request): Promise<Response> {
    if (!allow(request)) return json({ error: "origin" }, 403);
    if (limited(`token:${clientIp(request)}`, 30, 60_000)) return json({ error: "slow" }, 429, request);
    const body = await request.json().catch(() => null) as Record<string, unknown> | null;
    if (!body) return json({ error: "invalid" }, 400, request);
    const at = now();
    if (body.grant_type === "authorization_code") {
      const account = consumeAuthCode(options.database, {
        code: String(body.code ?? ""),
        clientId: String(body.client_id ?? ""),
        redirectUri: String(body.redirect_uri ?? ""),
        verifier: String(body.code_verifier ?? ""),
        now: at,
      });
      if (!account || !findClient(options.clients, String(body.client_id ?? ""), String(body.redirect_uri ?? ""))) {
        return json({ error: "invalid" }, 400, request);
      }
      const tokens = issueTokens(options.database, account.id, String(body.client_id), at);
      return json(tokenBody(account, tokens), 200, request);
    }
    if (body.grant_type === "refresh_token") {
      const rotated = rotateRefresh(options.database, String(body.refresh_token ?? ""), String(body.client_id ?? ""), at);
      if (!rotated.ok) return json({ error: rotated.reason }, 400, request);
      return json(tokenBody(rotated.account, rotated.tokens), 200, request);
    }
    return json({ error: "invalid" }, 400, request);
  }

  function logout(request: Request, url: URL): Response {
    const clientId = url.searchParams.get("client_id") ?? "";
    const redirectUri = url.searchParams.get("post_logout_redirect_uri") ?? "";
    if (!findClient(options.clients, clientId, redirectUri)) return html(messagePage("Sign-out refused", "This app is not registered for that address."), 400);
    const account = readBrowserSession(options.database, cookie(request, SESSION_COOKIE), now());
    if (account) revokeAccountSessions(options.database, account.id, now());
    const headers = new Headers({ location: redirectUri, "cache-control": "no-store" });
    setCookie(headers, SESSION_COOKIE, "", 0);
    setCookie(headers, LOGIN_COOKIE, "", 0);
    return new Response(null, { status: 302, headers });
  }

  async function proxyTiles(request: Request, url: URL): Promise<Response> {
    const origin = allow(request);
    if (!origin) return new Response(null, { status: 403 });
    const path = tilesPath(url);
    if (!path) return json({ error: "path" }, 400, request);
    const header = request.headers.get("authorization") ?? "";
    const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
    const at = now();
    const resolved = resolveBearer(token, path === ROOT_PATH, at);
    if (!resolved) return json({ error: "unauthorized" }, 401, request);
    if (!options.googleTilesKey) return json({ error: "unavailable" }, 503, request);
    const upstreamUrl = new URL(`https://tile.googleapis.com${path}`);
    url.searchParams.forEach((value, name) => { if (name !== "key") upstreamUrl.searchParams.append(name, value); });
    upstreamUrl.searchParams.set("key", options.googleTilesKey);
    const isRoot = path === ROOT_PATH;
    const reservation = isRoot ? reserveRoot(options.database, resolved.account, at, rootsPerDay, rootsFirstDay) : null;
    if (reservation && !reservation.ok) return json({ error: "quota", resetsAt: reservation.resetsAt }, 402, request);
    let response: Response;
    try {
      response = await upstream(upstreamUrl.toString(), { method: "GET", redirect: "manual" });
    } catch {
      if (reservation?.ok) reservation.refund();
      return json({ error: "upstream" }, 502, request);
    }
    if (isRoot && !response.ok && reservation?.ok) reservation.refund();
    const headers = new Headers();
    const type = response.headers.get("content-type");
    const cache = response.headers.get("cache-control");
    const etag = response.headers.get("etag");
    if (type) headers.set("content-type", type);
    if (cache) headers.set("cache-control", cache);
    if (etag) headers.set("etag", etag);
    headers.set("access-control-allow-origin", origin);
    headers.set("cross-origin-resource-policy", "cross-origin");
    headers.set("vary", "Origin");
    if (request.method === "HEAD") return new Response(null, { status: response.status, headers });
    return new Response(response.body, { status: response.status, headers });
  }

  function resolveBearer(token: string, fresh: boolean, at: Date): { account: AccountRow } | null {
    if (!token) return null;
    const hash = sha256(token);
    const cached = tokenCache.get(hash);
    if (!fresh && cached && at.getTime() - cached.checkedAt < CACHE_MS) {
      if (!cached.account || cached.account.disabled_at || cached.expiresAt <= at.toISOString()) return null;
      return { account: cached.account };
    }
    const resolved = resolveAccessToken(options.database, token, at);
    tokenCache.set(hash, {
      account: resolved?.account ?? null,
      expiresAt: resolved?.expiresAt ?? at.toISOString(),
      checkedAt: at.getTime(),
    });
    return resolved ? { account: resolved.account } : null;
  }

  return { handle };
}
