import { looksLikeEmail, normalizeEmail } from "./text.js";
import { selectJwk, tokenKid, TokenError, verifyRs256 } from "./jwt.js";
import type { JsonWebKey } from "node:crypto";

export type ProviderId = "google" | "github" | "microsoft";

export interface IdentityProof {
  provider: ProviderId | "email";
  subject: string;
  email: string;
}

export class ProviderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderError";
  }
}

export interface OAuthProvider {
  id: ProviderId;
  authorizationUrl(state: string): string;
  exchange(code: string): Promise<IdentityProof>;
}

export interface ProviderFetch {
  (url: string, init?: RequestInit): Promise<Response>;
}

interface OidcOptions {
  id: "google" | "microsoft";
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authorize: string;
  token: string;
  jwks: string;
  scope: string;
  issuer(iss: string): boolean;
  fetch: ProviderFetch;
  now(): Date;
  extra?: Record<string, string>;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text();
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new ProviderError("The sign-in provider returned an unreadable answer.");
  }
}

function oidcProvider(options: OidcOptions): OAuthProvider {
  return {
    id: options.id,
    authorizationUrl(state) {
      const url = new URL(options.authorize);
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", options.redirectUri);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("scope", options.scope);
      url.searchParams.set("state", state);
      for (const [name, value] of Object.entries(options.extra ?? {})) url.searchParams.set(name, value);
      return url.toString();
    },
    async exchange(code) {
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: options.redirectUri,
        client_id: options.clientId,
        client_secret: options.clientSecret,
      });
      const tokenResponse = await options.fetch(options.token, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body,
      });
      const token = await readJson(tokenResponse);
      if (!tokenResponse.ok || typeof token.id_token !== "string") throw new ProviderError("The sign-in provider refused the code.");
      const keysResponse = await options.fetch(options.jwks);
      const keys = await readJson(keysResponse);
      const list = Array.isArray(keys.keys) ? keys.keys as JsonWebKey[] : [];
      if (!keysResponse.ok || list.length === 0) throw new ProviderError("The sign-in provider's signing keys could not be read.");
      let payload: Record<string, unknown>;
      try {
        payload = verifyRs256(token.id_token, selectJwk(list, tokenKid(token.id_token)), {
          audience: options.clientId,
          issuer: options.issuer,
          now: options.now(),
        });
      } catch (error) {
        if (error instanceof TokenError) throw new ProviderError(error.message);
        throw error;
      }
      const email = typeof payload.email === "string" ? normalizeEmail(payload.email) : "";
      const microsoftOmitted = options.id === "microsoft" && (payload.email_verified === undefined || payload.email_verified === null);
      const verified = payload.email_verified === true || payload.email_verified === "true" || microsoftOmitted;
      if (!looksLikeEmail(email) || !verified || typeof payload.sub !== "string" || !payload.sub) {
        throw new ProviderError("That account has no verified email we can use.");
      }
      return { provider: options.id, subject: payload.sub, email };
    },
  };
}

export function googleProvider(options: { clientId: string; clientSecret: string; redirectUri: string; fetch: ProviderFetch; now(): Date }): OAuthProvider {
  return oidcProvider({
    id: "google",
    ...options,
    authorize: "https://accounts.google.com/o/oauth2/v2/auth",
    token: "https://oauth2.googleapis.com/token",
    jwks: "https://www.googleapis.com/oauth2/v3/certs",
    scope: "openid email profile",
    issuer: iss => iss === "https://accounts.google.com" || iss === "accounts.google.com",
    extra: { prompt: "select_account" },
  });
}

export function microsoftProvider(options: { clientId: string; clientSecret: string; redirectUri: string; fetch: ProviderFetch; now(): Date }): OAuthProvider {
  return oidcProvider({
    id: "microsoft",
    ...options,
    authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    jwks: "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    scope: "openid email profile",
    issuer: iss => /^https:\/\/login\.microsoftonline\.com\/[0-9a-f-]{36}\/v2\.0$/i.test(iss),
  });
}

interface GitHubEmail { email?: unknown; primary?: unknown; verified?: unknown }

export function githubProvider(options: { clientId: string; clientSecret: string; redirectUri: string; fetch: ProviderFetch }): OAuthProvider {
  return {
    id: "github",
    authorizationUrl(state) {
      const url = new URL("https://github.com/login/oauth/authorize");
      url.searchParams.set("client_id", options.clientId);
      url.searchParams.set("redirect_uri", options.redirectUri);
      url.searchParams.set("scope", "read:user user:email");
      url.searchParams.set("state", state);
      return url.toString();
    },
    async exchange(code) {
      const tokenResponse = await options.fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          client_id: options.clientId,
          client_secret: options.clientSecret,
          code,
          redirect_uri: options.redirectUri,
        }),
      });
      const token = await readJson(tokenResponse);
      if (!tokenResponse.ok || typeof token.access_token !== "string") throw new ProviderError("GitHub refused the code.");
      const headers = { authorization: `Bearer ${token.access_token}`, accept: "application/vnd.github+json", "user-agent": "foss-earth-accounts" };
      const userResponse = await options.fetch("https://api.github.com/user", { headers });
      const user = await readJson(userResponse);
      const emailsResponse = await options.fetch("https://api.github.com/user/emails", { headers });
      const emails = await emailsResponse.json() as unknown;
      if (!userResponse.ok || !emailsResponse.ok || !Array.isArray(emails)) throw new ProviderError("GitHub did not return the account.");
      const primary = emails.find((entry): entry is GitHubEmail => {
        const email = entry as GitHubEmail;
        return email.primary === true && email.verified === true && typeof email.email === "string";
      });
      const address = primary && typeof primary.email === "string" ? normalizeEmail(primary.email) : "";
      if (!looksLikeEmail(address) || (typeof user.id !== "number" && typeof user.id !== "string")) {
        throw new ProviderError("That GitHub account has no verified primary email. Verify one on GitHub, then try again.");
      }
      return { provider: "github", subject: String(user.id), email: address };
    },
  };
}
