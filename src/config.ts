import type { ClientRecord } from "./records.js";

/** The three apps, on their published sites and on the local HTTPS dev ports. */
export const DEFAULT_CLIENTS: readonly ClientRecord[] = [
  { id: "earth", redirectUris: ["https://foss-earth.github.io/app/", "https://localhost:3600/app/"] },
  { id: "tour", redirectUris: ["https://umn-vr.github.io/tour/", "https://localhost:8660/tour/"] },
  { id: "fly", redirectUris: ["https://0sfs.github.io/fly/", "https://localhost:7470/fly/"] },
];

export interface ServerConfig {
  accountOrigin: string;
  databasePath: string;
  clients: readonly ClientRecord[];
  googleTilesKey: string | null;
  rootsPerDay: number;
  rootsFirstDay: number;
  google: { clientId: string; clientSecret: string } | null;
  github: { clientId: string; clientSecret: string } | null;
  microsoft: { clientId: string; clientSecret: string } | null;
  mail: { url: string; token: string; from: string } | null;
  tls: { keyPath: string; certPath: string } | null;
  port: number;
}

function required(name: string, value: string | undefined): string {
  const trimmed = value?.trim() ?? "";
  if (!trimmed) throw new Error(`${name} is required.`);
  return trimmed;
}

function pair(idName: string, secretName: string, env: NodeJS.ProcessEnv): { clientId: string; clientSecret: string } | null {
  const clientId = env[idName]?.trim() ?? "";
  const clientSecret = env[secretName]?.trim() ?? "";
  if (!clientId && !clientSecret) return null;
  return { clientId: required(idName, clientId), clientSecret: required(secretName, clientSecret) };
}

/** Reads the process environment. Throws when a required value is missing. */
export function readConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const keyPath = env.TLS_KEY?.trim() ?? "";
  const certPath = env.TLS_CERT?.trim() ?? "";
  const mailToken = env.MAIL_API_TOKEN?.trim() ?? "";
  return {
    accountOrigin: (env.ACCOUNT_ORIGIN?.trim() || "https://login.foss.earth").replace(/\/$/, ""),
    databasePath: env.ACCOUNT_DATABASE?.trim() || "build/accounts.sqlite",
    clients: DEFAULT_CLIENTS,
    googleTilesKey: env.GOOGLE_TILES_KEY?.trim() || null,
    rootsPerDay: numberOr(env.ROOTS_PER_DAY, 40),
    rootsFirstDay: numberOr(env.ROOTS_FIRST_DAY, 10),
    google: pair("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", env),
    github: pair("GITHUB_OAUTH_CLIENT_ID", "GITHUB_OAUTH_CLIENT_SECRET", env),
    microsoft: pair("MICROSOFT_OAUTH_CLIENT_ID", "MICROSOFT_OAUTH_CLIENT_SECRET", env),
    mail: mailToken ? { url: env.MAIL_API_URL?.trim() || "https://api.resend.com/emails", token: mailToken, from: required("MAIL_FROM", env.MAIL_FROM) } : null,
    tls: keyPath || certPath ? { keyPath: required("TLS_KEY", keyPath), certPath: required("TLS_CERT", certPath) } : null,
    port: numberOr(env.PORT, 8787),
  };
}

function numberOr(value: string | undefined, fallback: number): number {
  if (!value?.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) throw new Error(`Expected a non-negative integer, got ${value}.`);
  return parsed;
}
