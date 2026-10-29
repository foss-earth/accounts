import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createAccountApp, type AccountApp, type Mailer } from "../src/app.js";
import type { IdentityProof, OAuthProvider, ProviderId } from "../src/providers.js";
import { ProviderError } from "../src/providers.js";
import { openDatabase } from "../src/schema.js";
import { DEFAULT_CLIENTS } from "../src/config.js";
import { runCli } from "../src/cli.js";

const ORIGIN = "https://foss-earth.github.io";
const REDIRECT = "https://foss-earth.github.io/app/";

function proof(provider: ProviderId, code: string): IdentityProof {
  const table: Record<string, IdentityProof | "unverified"> = {
    ada: { provider, subject: `${provider}-ada`, email: "ada@example.com" },
    "ada-other": { provider, subject: `${provider}-ada-2`, email: "ada@example.com" },
    bea: { provider, subject: `${provider}-bea`, email: "bea@example.com" },
    unverified: "unverified",
  };
  const found = table[code];
  if (found === "unverified") throw new ProviderError("That account has no verified email we can use.");
  if (!found) throw new ProviderError("The sign-in provider refused the code.");
  return { ...found, provider };
}

function provider(id: ProviderId): OAuthProvider {
  return {
    id,
    authorizationUrl: state => `https://${id}.test/authorize?state=${encodeURIComponent(state)}`,
    exchange: async code => proof(id, code),
  };
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

function cookie(response: Response, name: string): string {
  const found = response.headers.getSetCookie().find(item => item.startsWith(`${name}=`));
  if (!found) throw new Error(`No ${name} cookie.`);
  return decodeURIComponent(found.slice(name.length + 1).split(";")[0] ?? "");
}

function app(extra: {
  now?: () => Date;
  mail?: Mailer;
  upstream?: (url: string, init: RequestInit) => Promise<Response>;
  googleTilesKey?: string | null;
  rootsPerDay?: number;
  rootsFirstDay?: number;
} = {}): AccountApp {
  return createAccountApp({
    database: openDatabase(":memory:"),
    accountOrigin: "https://login.foss.earth",
    clients: DEFAULT_CLIENTS,
    providers: { google: provider("google"), github: provider("github"), microsoft: provider("microsoft") },
    googleTilesKey: extra.googleTilesKey === undefined ? "server-key" : extra.googleTilesKey,
    rootsPerDay: extra.rootsPerDay ?? 40,
    rootsFirstDay: extra.rootsFirstDay ?? 10,
    ...extra,
  });
}

async function signIn(service: AccountApp, code = "ada", id: ProviderId = "google"): Promise<{ access: string; refresh: string; accountId: string; session: string }> {
  const { verifier, challenge } = pkce();
  const state = "state-1";
  const start = await service.handle(new Request(`https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`));
  expect(start.status).toBe(200);
  const login = cookie(start, "fe_login");
  const providerStart = await service.handle(new Request(`https://login.foss.earth/start/${id}?login=${login}`));
  const pending = new URL(providerStart.headers.get("location") ?? "").searchParams.get("state");
  const back = await service.handle(new Request(`https://login.foss.earth/callback/${id}?code=${code}&state=${pending}`));
  expect(back.status).toBe(302);
  const landed = new URL(back.headers.get("location") ?? "");
  expect(landed.searchParams.get("state")).toBe(state);
  const exchanged = await service.handle(new Request("https://login.foss.earth/token", {
    method: "POST",
    headers: { origin: ORIGIN, "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "authorization_code", code: landed.searchParams.get("code"), redirect_uri: REDIRECT, client_id: "earth", code_verifier: verifier }),
  }));
  expect(exchanged.status).toBe(200);
  const body = await exchanged.json() as { accessToken: string; refreshToken: string; account: { id: string }; entitlements: string[] };
  expect(body.entitlements).toEqual(["google-3d-tiles"]);
  return { access: body.accessToken, refresh: body.refreshToken, accountId: body.account.id, session: cookie(back, "fe_session") };
}

describe("sign-in", () => {
  it("refuses an unregistered redirect before sending the person anywhere", async () => {
    const start = await app().handle(new Request("https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=https://evil.example/app/&code_challenge=abc&code_challenge_method=S256&state=s"));
    expect(start.status).toBe(400);
    expect(start.headers.get("location")).toBeNull();
  });

  it("links a second verified provider to the same account and rejects an unverified one", async () => {
    const service = app();
    const first = await signIn(service, "ada", "google");
    const second = await signIn(service, "ada-other", "github");
    expect(second.accountId).toBe(first.accountId);
    const refused = await service.handle(new Request("https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=" + encodeURIComponent(REDIRECT) + "&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256&state=s"));
    const login = cookie(refused, "fe_login");
    const pending = new URL((await service.handle(new Request(`https://login.foss.earth/start/github?login=${login}`))).headers.get("location") ?? "").searchParams.get("state");
    const back = await service.handle(new Request(`https://login.foss.earth/callback/github?code=unverified&state=${pending}`));
    expect(back.status).toBe(400);
    expect(await back.text()).toContain("no verified email");
  });

  it("rejects a reused code, a wrong verifier, and reuse of a rotated refresh token", async () => {
    const service = app();
    const { verifier, challenge } = pkce();
    const start = await service.handle(new Request(`https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&state=s`));
    const login = cookie(start, "fe_login");
    const pending = new URL((await service.handle(new Request(`https://login.foss.earth/start/google?login=${login}`))).headers.get("location") ?? "").searchParams.get("state");
    const back = await service.handle(new Request(`https://login.foss.earth/callback/google?code=bea&state=${pending}`));
    const code = new URL(back.headers.get("location") ?? "").searchParams.get("code");
    const exchange = (verifierValue: string) => service.handle(new Request("https://login.foss.earth/token", {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, client_id: "earth", code_verifier: verifierValue }),
    }));
    expect((await exchange("wrong-verifier")).status).toBe(400);
    const ok = await exchange(verifier);
    expect(ok.status).toBe(200);
    expect((await exchange(verifier)).status).toBe(400);
    const body = await ok.json() as { refreshToken: string };
    const refresh = (token: string) => service.handle(new Request("https://login.foss.earth/token", {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: token, client_id: "earth" }),
    }));
    const rotated = await refresh(body.refreshToken);
    expect(rotated.status).toBe(200);
    const next = await rotated.json() as { refreshToken: string };
    expect((await refresh(body.refreshToken)).status).toBe(400);
    expect((await refresh(next.refreshToken)).status).toBe(400);
    const foreign = await service.handle(new Request("https://login.foss.earth/token", {
      method: "POST", headers: { origin: "https://evil.example", "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: next.refreshToken, client_id: "earth" }),
    }));
    expect(foreign.status).toBe(403);
  });

  it("signs the next app in from the cookie and signs every app out", async () => {
    const service = app();
    const first = await signIn(service);
    const { challenge } = pkce();
    const again = await service.handle(new Request(`https://login.foss.earth/authorize?response_type=code&client_id=tour&redirect_uri=${encodeURIComponent("https://umn-vr.github.io/tour/")}&code_challenge=${challenge}&code_challenge_method=S256&state=tour`, {
      headers: { cookie: `fe_session=${encodeURIComponent(first.session)}` },
    }));
    expect(again.status).toBe(302);
    expect(again.headers.get("location")).toContain("https://umn-vr.github.io/tour/");
    expect(await again.text()).not.toContain("Continue with");
    const out = await service.handle(new Request(`https://login.foss.earth/logout?client_id=earth&post_logout_redirect_uri=${encodeURIComponent(REDIRECT)}`, {
      headers: { cookie: `fe_session=${encodeURIComponent(first.session)}` },
    }));
    expect(out.status).toBe(302);
    expect(out.headers.get("location")).toBe(REDIRECT);
    const silent = await service.handle(new Request(`https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&state=s`, {
      headers: { cookie: `fe_session=${encodeURIComponent(first.session)}` },
    }));
    expect(silent.status).toBe(200);
    expect(await silent.text()).toContain("Continue with Google");
  });

  it("sends one magic link and refuses the second use", async () => {
    const sent: { to: string; text: string }[] = [];
    const service = app({ mail: { async send(message) { sent.push(message); } } });
    const { challenge } = pkce();
    const start = await service.handle(new Request(`https://login.foss.earth/authorize?response_type=code&client_id=earth&redirect_uri=${encodeURIComponent(REDIRECT)}&code_challenge=${challenge}&code_challenge_method=S256&state=mail`));
    const posted = await service.handle(new Request("https://login.foss.earth/email/start", {
      method: "POST",
      headers: { cookie: `fe_login=${encodeURIComponent(cookie(start, "fe_login"))}`, "content-type": "application/x-www-form-urlencoded" },
      body: "email=Ada%40Example.com",
    }));
    expect(posted.status).toBe(302);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe("ada@example.com");
    const link = sent[0]?.text.match(/https:\/\/login\.foss\.earth\/email\/verify\?token=[^\s]+/)?.[0];
    expect(link).toBeTruthy();
    const verified = await service.handle(new Request(link!));
    expect(verified.status).toBe(302);
    expect(new URL(verified.headers.get("location") ?? "").searchParams.get("state")).toBe("mail");
    expect((await service.handle(new Request(link!))).status).toBe(400);
  });
});

describe("hosted tiles", () => {
  it("adds the server key, spends a root only on success, and stops at the budget", async () => {
    let clock = new Date("2026-10-27T15:00:00.000Z");
    const calls: string[] = [];
    const service = app({
      now: () => clock,
      rootsFirstDay: 2,
      rootsPerDay: 5,
      upstream: async url => {
        calls.push(url);
        if (url.includes("fail")) return new Response("no", { status: 503 });
        return new Response("tile", { status: 200, headers: { "content-type": "application/json", etag: "\"e\"", "cache-control": "private" } });
      },
    });
    const signed = await signIn(service);
    const { access } = signed;
    const get = (path: string, token = access, origin = ORIGIN) => service.handle(new Request(`https://login.foss.earth${path}`, {
      headers: { authorization: `Bearer ${token}`, origin },
    }));
    const other = await get("/v1/3dtiles/root.json", access, "https://evil.example");
    expect(other.status).toBe(403);
    expect(calls).toHaveLength(0);
    const outside = await get("/secret");
    expect(outside.status).toBe(404);
    expect(calls).toHaveLength(0);
    const failed = await get("/v1/3dtiles/root.json?session=abc&key=stolen&child=fail");
    expect(failed.status).toBe(503);
    expect(calls[0]).toContain("key=server-key");
    expect(calls[0]).not.toContain("stolen");
    expect(calls[0]).toContain("child=fail");
    const root = await get("/v1/3dtiles/root.json?session=abc&key=stolen");
    expect(root.status).toBe(200);
    expect(root.headers.get("cross-origin-resource-policy")).toBe("cross-origin");
    expect(root.headers.get("etag")).toBe("\"e\"");
    const child = await get("/v1/3dtiles/datasets/a/files/b.glb?session=abc");
    expect(child.status).toBe(200);
    const spent = calls.filter(url => url.includes("root.json") && !url.includes("child=fail"));
    expect(spent).toHaveLength(1);
    const second = await get("/v1/3dtiles/root.json");
    expect(second.status).toBe(200);
    expect((await get("/v1/3dtiles/root.json")).status).toBe(402);
    expect(calls.filter(url => url.includes("root.json"))).toHaveLength(3);
    clock = new Date("2026-10-28T15:00:01.000Z");
    const renewed = await service.handle(new Request("https://login.foss.earth/token", {
      method: "POST",
      headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "refresh_token", refresh_token: signed.refresh, client_id: "earth" }),
    }));
    expect(renewed.status).toBe(200);
    const next = await renewed.json() as { accessToken: string };
    expect((await get("/v1/3dtiles/root.json", next.accessToken)).status).toBe(200);
  });

  it("stops a disabled account on the next root and on a mesh after the cache window", async () => {
    let clock = new Date("2026-10-27T15:00:00.000Z");
    const database = openDatabase(":memory:");
    const service = createAccountApp({
      database, accountOrigin: "https://login.foss.earth", clients: DEFAULT_CLIENTS,
      providers: { google: provider("google") }, googleTilesKey: "server-key", now: () => clock,
      upstream: async () => new Response("ok", { status: 200 }),
    });
    const signed = await signIn(service);
    const mesh = () => service.handle(new Request("https://login.foss.earth/v1/3dtiles/tile.glb", {
      headers: { authorization: `Bearer ${signed.access}`, origin: ORIGIN },
    }));
    expect((await mesh()).status).toBe(200);
    const logs: string[] = [];
    expect(runCli(["account", "disable", "--email", "ada@example.com"], database, { log: message => logs.push(message), error: message => logs.push(message) }, clock)).toBe(0);
    expect(logs.join(" ")).toContain("disabled");
    expect((await service.handle(new Request("https://login.foss.earth/v1/3dtiles/root.json", {
      headers: { authorization: `Bearer ${signed.access}`, origin: ORIGIN },
    }))).status).toBe(401);
    clock = new Date(clock.getTime() + 61_000);
    expect((await mesh()).status).toBe(401);
    expect(runCli(["account", "enable", "--email", "ada@example.com"], database, { log: () => {}, error: () => {} }, clock)).toBe(0);
    expect(runCli(["quota", "set", "--email", "ada@example.com", "--daily-roots", "3"], database, { log: message => logs.push(message), error: () => {} })).toBe(0);
    expect(logs.join(" ")).toContain("3 root requests");
  });
});
