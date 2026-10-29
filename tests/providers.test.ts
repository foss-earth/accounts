import { generateKeyPairSync, randomUUID, type JsonWebKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import { githubProvider, googleProvider } from "../src/providers.js";
import { sign } from "node:crypto";

function signedToken(payload: Record<string, unknown>, kid: string): { token: string; jwk: JsonWebKey } {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  jwk.kid = kid;
  jwk.alg = "RS256";
  jwk.use = "sig";
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey).toString("base64url");
  return { token: `${header}.${body}.${signature}`, jwk };
}

describe("provider exchanges", () => {
  it("accepts a Google ID token and refuses an unverified email", async () => {
    const now = new Date("2026-10-27T12:00:00.000Z");
    const good = signedToken({
      iss: "https://accounts.google.com", aud: "google-client", exp: Math.floor(now.getTime() / 1000) + 60,
      sub: "google-subject", email: "Ada@Example.com", email_verified: true,
    }, "key-1");
    const fetch = async (url: string) => {
      if (url.includes("token")) return new Response(JSON.stringify({ id_token: good.token }));
      return new Response(JSON.stringify({ keys: [good.jwk] }));
    };
    const google = googleProvider({ clientId: "google-client", clientSecret: "secret", redirectUri: "https://login.foss.earth/callback/google", fetch, now: () => now });
    expect(google.authorizationUrl("pending")).toContain("accounts.google.com");
    await expect(google.exchange("code")).resolves.toEqual({ provider: "google", subject: "google-subject", email: "ada@example.com" });
    const bad = signedToken({ ...JSON.parse(Buffer.from(good.token.split(".")[1]!, "base64url").toString()), email_verified: false }, "key-1");
    const refusing = googleProvider({
      clientId: "google-client", clientSecret: "secret", redirectUri: "https://login.foss.earth/callback/google", now: () => now,
      fetch: async url => url.includes("token") ? new Response(JSON.stringify({ id_token: bad.token })) : new Response(JSON.stringify({ keys: [bad.jwk] })),
    });
    await expect(refusing.exchange("code")).rejects.toThrow(/verified email/);
  });

  it("uses GitHub's verified primary email and refuses when there is none", async () => {
    const fetch = async (url: string) => {
      if (url.includes("access_token")) return new Response(JSON.stringify({ access_token: "gh" }));
      if (url.endsWith("/user")) return new Response(JSON.stringify({ id: 42 }));
      return new Response(JSON.stringify([
        { email: "hidden@example.com", primary: false, verified: true },
        { email: "Ada@Example.com", primary: true, verified: true },
      ]));
    };
    const github = githubProvider({ clientId: "id", clientSecret: "secret", redirectUri: "https://login.foss.earth/callback/github", fetch });
    await expect(github.exchange("code")).resolves.toEqual({ provider: "github", subject: "42", email: "ada@example.com" });
    const none = githubProvider({
      clientId: "id", clientSecret: "secret", redirectUri: "https://login.foss.earth/callback/github",
      fetch: async url => {
        if (url.includes("access_token")) return new Response(JSON.stringify({ access_token: "gh" }));
        if (url.endsWith("/user")) return new Response(JSON.stringify({ id: randomUUID() }));
        return new Response(JSON.stringify([{ email: "ada@example.com", primary: true, verified: false }]));
      },
    });
    await expect(none.exchange("code")).rejects.toThrow(/verified primary email/);
  });
});
