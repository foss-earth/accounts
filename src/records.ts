import type { DatabaseSync } from "node:sqlite";
import { nextUtcMidnight, normalizeEmail, randomToken, sha256, sha256Base64Url, utcDay } from "./text.js";
import type { IdentityProof } from "./providers.js";

export const GOOGLE_TILES = "google-3d-tiles";
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_MS = 30 * DAY_MS;
const ACCESS_MS = 15 * 60 * 1000;
const REFRESH_MS = 30 * DAY_MS;
const CODE_MS = 2 * 60 * 1000;
const PENDING_MS = 15 * 60 * 1000;
const MAGIC_MS = 15 * 60 * 1000;

export interface AccountRow {
  id: string;
  email: string;
  created_at: string;
  disabled_at: string | null;
  daily_roots: number | null;
  first_window_ends_at: string;
  first_window_spent: number;
}

export interface ClientRecord {
  id: string;
  redirectUris: readonly string[];
}

export class AccountDisabled extends Error {
  constructor() {
    super("This account is disabled.");
    this.name = "AccountDisabled";
  }
}

function iso(date: Date): string {
  return date.toISOString();
}

export function findClient(clients: readonly ClientRecord[], id: string, redirectUri: string): ClientRecord | null {
  const client = clients.find(entry => entry.id === id);
  if (!client || !client.redirectUris.includes(redirectUri)) return null;
  return client;
}

export function originOf(uri: string): string | null {
  try {
    return new URL(uri).origin;
  } catch {
    return null;
  }
}

export function registeredOrigins(clients: readonly ClientRecord[]): Set<string> {
  const origins = new Set<string>();
  for (const client of clients) for (const uri of client.redirectUris) {
    const origin = originOf(uri);
    if (origin) origins.add(origin);
  }
  return origins;
}

export function createPending(database: DatabaseSync, input: {
  clientId: string; redirectUri: string; codeChallenge: string; appState: string; now: Date;
}): string {
  const id = randomToken(16);
  database.prepare(`INSERT INTO pending_login (id, client_id, redirect_uri, code_challenge, app_state, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(id, input.clientId, input.redirectUri, input.codeChallenge, input.appState, iso(new Date(input.now.getTime() + PENDING_MS)));
  return id;
}

export function readPending(database: DatabaseSync, id: string, now: Date): {
  id: string; client_id: string; redirect_uri: string; code_challenge: string; app_state: string;
} | null {
  const row = database.prepare(`SELECT id, client_id, redirect_uri, code_challenge, app_state, expires_at FROM pending_login WHERE id = ?`).get(id) as {
    id: string; client_id: string; redirect_uri: string; code_challenge: string; app_state: string; expires_at: string;
  } | undefined;
  if (!row || row.expires_at <= iso(now)) return null;
  return row;
}

/** Finds or creates the account for a verified identity. A disabled account is refused. */
export function accountForIdentity(database: DatabaseSync, proof: IdentityProof, now: Date): AccountRow {
  const existing = database.prepare(`SELECT account_id FROM identity WHERE provider = ? AND subject = ?`).get(proof.provider, proof.subject) as { account_id: string } | undefined;
  if (existing) {
    const account = readAccount(database, existing.account_id);
    if (!account || account.disabled_at) throw new AccountDisabled();
    return account;
  }
  const byEmail = database.prepare(`SELECT id FROM account WHERE email = ?`).get(proof.email) as { id: string } | undefined;
  const account = byEmail ? readAccount(database, byEmail.id) : null;
  if (account?.disabled_at) throw new AccountDisabled();
  const accountId = account?.id ?? createAccount(database, proof.email, now);
  database.prepare(`INSERT INTO identity (id, account_id, provider, subject, email, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(randomToken(16), accountId, proof.provider, proof.subject, proof.email, iso(now));
  const created = readAccount(database, accountId);
  if (!created) throw new Error("The account was not stored.");
  return created;
}

function createAccount(database: DatabaseSync, email: string, now: Date): string {
  const id = randomToken(16);
  database.prepare(`INSERT INTO account (id, email, created_at, disabled_at, daily_roots, first_window_ends_at, first_window_spent)
    VALUES (?, ?, ?, NULL, NULL, ?, 0)`).run(id, normalizeEmail(email), iso(now), iso(new Date(now.getTime() + DAY_MS)));
  return id;
}

export function readAccount(database: DatabaseSync, id: string): AccountRow | null {
  return database.prepare(`SELECT id, email, created_at, disabled_at, daily_roots, first_window_ends_at, first_window_spent FROM account WHERE id = ?`).get(id) as AccountRow | undefined ?? null;
}

export function accountByEmail(database: DatabaseSync, email: string): AccountRow | null {
  const normalized = normalizeEmail(email);
  return database.prepare(`SELECT id, email, created_at, disabled_at, daily_roots, first_window_ends_at, first_window_spent FROM account WHERE email = ?`).get(normalized) as AccountRow | undefined ?? null;
}

export function setDisabled(database: DatabaseSync, email: string, disabled: boolean, now: Date): AccountRow | null {
  const account = accountByEmail(database, email);
  if (!account) return null;
  database.prepare(`UPDATE account SET disabled_at = ? WHERE id = ?`).run(disabled ? iso(now) : null, account.id);
  if (disabled) revokeAccountSessions(database, account.id, now);
  return readAccount(database, account.id);
}

export function setDailyRoots(database: DatabaseSync, email: string, dailyRoots: number): AccountRow | null {
  const account = accountByEmail(database, email);
  if (!account) return null;
  database.prepare(`UPDATE account SET daily_roots = ? WHERE id = ?`).run(dailyRoots, account.id);
  return readAccount(database, account.id);
}

export function createBrowserSession(database: DatabaseSync, accountId: string, now: Date): { id: string; secret: string; expiresAt: string } {
  const id = randomToken(16);
  const secret = randomToken();
  const expiresAt = iso(new Date(now.getTime() + SESSION_MS));
  database.prepare(`INSERT INTO browser_session (id, account_id, secret_hash, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL)`)
    .run(id, accountId, sha256(secret), expiresAt);
  return { id, secret, expiresAt };
}

export function readBrowserSession(database: DatabaseSync, cookie: string | null, now: Date): AccountRow | null {
  if (!cookie) return null;
  const split = cookie.indexOf(".");
  if (split <= 0) return null;
  const id = cookie.slice(0, split);
  const secret = cookie.slice(split + 1);
  const row = database.prepare(`SELECT account_id, secret_hash, expires_at, revoked_at FROM browser_session WHERE id = ?`).get(id) as {
    account_id: string; secret_hash: string; expires_at: string; revoked_at: string | null;
  } | undefined;
  if (!row || row.revoked_at || row.expires_at <= iso(now) || row.secret_hash !== sha256(secret)) return null;
  const account = readAccount(database, row.account_id);
  if (!account || account.disabled_at) return null;
  return account;
}

export function createAuthCode(database: DatabaseSync, input: {
  clientId: string; redirectUri: string; accountId: string; codeChallenge: string; now: Date;
}): string {
  const code = randomToken();
  database.prepare(`INSERT INTO auth_code (hash, client_id, redirect_uri, account_id, code_challenge, expires_at, used_at)
    VALUES (?, ?, ?, ?, ?, ?, NULL)`).run(sha256(code), input.clientId, input.redirectUri, input.accountId, input.codeChallenge, iso(new Date(input.now.getTime() + CODE_MS)));
  return code;
}

export function consumeAuthCode(database: DatabaseSync, input: {
  code: string; clientId: string; redirectUri: string; verifier: string; now: Date;
}): AccountRow | null {
  const row = database.prepare(`SELECT client_id, redirect_uri, account_id, code_challenge, expires_at, used_at FROM auth_code WHERE hash = ?`).get(sha256(input.code)) as {
    client_id: string; redirect_uri: string; account_id: string; code_challenge: string; expires_at: string; used_at: string | null;
  } | undefined;
  if (!row || row.used_at || row.expires_at <= iso(input.now)) return null;
  if (row.client_id !== input.clientId || row.redirect_uri !== input.redirectUri) return null;
  if (row.code_challenge !== sha256Base64Url(input.verifier)) return null;
  database.prepare(`UPDATE auth_code SET used_at = ? WHERE hash = ?`).run(iso(input.now), sha256(input.code));
  const account = readAccount(database, row.account_id);
  if (!account || account.disabled_at) return null;
  return account;
}

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  familyId: string;
}

export function issueTokens(database: DatabaseSync, accountId: string, clientId: string, now: Date, familyId = randomToken(16)): IssuedTokens {
  const accessToken = randomToken();
  const refreshToken = randomToken();
  const expiresAt = iso(new Date(now.getTime() + ACCESS_MS));
  database.prepare(`INSERT INTO access_token (hash, account_id, client_id, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL)`)
    .run(sha256(accessToken), accountId, clientId, expiresAt);
  database.prepare(`INSERT INTO refresh_token (hash, family_id, account_id, client_id, expires_at, rotated_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL, NULL)`)
    .run(sha256(refreshToken), familyId, accountId, clientId, iso(new Date(now.getTime() + REFRESH_MS)));
  return { accessToken, refreshToken, expiresAt, familyId };
}

export type RefreshResult =
  | { ok: true; account: AccountRow; tokens: IssuedTokens }
  | { ok: false; reason: "invalid" | "reused" };

/** Rotates a refresh token. Reuse of an already rotated token revokes the family. */
export function rotateRefresh(database: DatabaseSync, token: string, clientId: string, now: Date): RefreshResult {
  const hash = sha256(token);
  const row = database.prepare(`SELECT family_id, account_id, client_id, expires_at, rotated_at, revoked_at FROM refresh_token WHERE hash = ?`).get(hash) as {
    family_id: string; account_id: string; client_id: string; expires_at: string; rotated_at: string | null; revoked_at: string | null;
  } | undefined;
  if (!row || row.client_id !== clientId) return { ok: false, reason: "invalid" };
  if (row.rotated_at || row.revoked_at) {
    database.prepare(`UPDATE refresh_token SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL`).run(iso(now), row.family_id);
    database.prepare(`UPDATE access_token SET revoked_at = ? WHERE account_id = ? AND client_id = ? AND revoked_at IS NULL`).run(iso(now), row.account_id, clientId);
    return { ok: false, reason: "reused" };
  }
  if (row.expires_at <= iso(now)) return { ok: false, reason: "invalid" };
  const account = readAccount(database, row.account_id);
  if (!account || account.disabled_at) return { ok: false, reason: "invalid" };
  database.prepare(`UPDATE refresh_token SET rotated_at = ? WHERE hash = ?`).run(iso(now), hash);
  return { ok: true, account, tokens: issueTokens(database, account.id, clientId, now, row.family_id) };
}

export interface AccessResolution {
  account: AccountRow;
  clientId: string;
  expiresAt: string;
}

export function resolveAccessToken(database: DatabaseSync, token: string, now: Date): AccessResolution | null {
  const row = database.prepare(`SELECT account_id, client_id, expires_at, revoked_at FROM access_token WHERE hash = ?`).get(sha256(token)) as {
    account_id: string; client_id: string; expires_at: string; revoked_at: string | null;
  } | undefined;
  if (!row || row.revoked_at || row.expires_at <= iso(now)) return null;
  const account = readAccount(database, row.account_id);
  if (!account || account.disabled_at) return null;
  return { account, clientId: row.client_id, expiresAt: row.expires_at };
}

export function revokeAccountSessions(database: DatabaseSync, accountId: string, now: Date): void {
  const at = iso(now);
  database.prepare(`UPDATE browser_session SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`).run(at, accountId);
  database.prepare(`UPDATE refresh_token SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`).run(at, accountId);
  database.prepare(`UPDATE access_token SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL`).run(at, accountId);
}

export function createMagicLink(database: DatabaseSync, email: string, pendingId: string, now: Date): string {
  const token = randomToken();
  database.prepare(`INSERT INTO magic_link (hash, email, pending_id, expires_at, used_at) VALUES (?, ?, ?, ?, NULL)`)
    .run(sha256(token), normalizeEmail(email), pendingId, iso(new Date(now.getTime() + MAGIC_MS)));
  return token;
}

export function consumeMagicLink(database: DatabaseSync, token: string, now: Date): { email: string; pendingId: string } | null {
  const hash = sha256(token);
  const row = database.prepare(`SELECT email, pending_id, expires_at, used_at FROM magic_link WHERE hash = ?`).get(hash) as {
    email: string; pending_id: string; expires_at: string; used_at: string | null;
  } | undefined;
  if (!row || row.used_at || row.expires_at <= iso(now)) return null;
  database.prepare(`UPDATE magic_link SET used_at = ? WHERE hash = ?`).run(iso(now), hash);
  return { email: row.email, pendingId: row.pending_id };
}

export interface Quota {
  remainingRootRequests: number;
  resetsAt: string;
}

export function quotaFor(database: DatabaseSync, account: AccountRow, now: Date, rootsPerDay: number, rootsFirstDay: number): Quota {
  const first = now.toISOString() < account.first_window_ends_at;
  const dailyBudget = account.daily_roots ?? rootsPerDay;
  const day = utcDay(now);
  const spentToday = (database.prepare(`SELECT count FROM root_spend WHERE account_id = ? AND day = ?`).get(account.id, day) as { count: number } | undefined)?.count ?? 0;
  const dailyRemaining = Math.max(0, dailyBudget - spentToday);
  if (!first) return { remainingRootRequests: dailyRemaining, resetsAt: nextUtcMidnight(now) };
  const firstRemaining = Math.max(0, rootsFirstDay - account.first_window_spent);
  const remaining = Math.min(dailyRemaining, firstRemaining);
  const resetsAt = firstRemaining <= dailyRemaining ? account.first_window_ends_at : nextUtcMidnight(now);
  return { remainingRootRequests: remaining, resetsAt };
}

export type ReserveResult = { ok: true; refund(): void } | { ok: false; resetsAt: string };

/**
 * Reserves one root request. The caller refunds it when Google does not
 * succeed. The store, not a later counter, is the source of truth.
 */
export function reserveRoot(database: DatabaseSync, account: AccountRow, now: Date, rootsPerDay: number, rootsFirstDay: number): ReserveResult {
  const quota = quotaFor(database, account, now, rootsPerDay, rootsFirstDay);
  if (quota.remainingRootRequests <= 0) return { ok: false, resetsAt: quota.resetsAt };
  const day = utcDay(now);
  const first = now.toISOString() < account.first_window_ends_at;
  database.exec("BEGIN IMMEDIATE");
  try {
    const current = readAccount(database, account.id);
    const fresh = current ? quotaFor(database, current, now, rootsPerDay, rootsFirstDay) : quota;
    if (!current || current.disabled_at || fresh.remainingRootRequests <= 0) {
      database.exec("ROLLBACK");
      return { ok: false, resetsAt: fresh.resetsAt };
    }
    database.prepare(`INSERT INTO root_spend (account_id, day, count) VALUES (?, ?, 1)
      ON CONFLICT(account_id, day) DO UPDATE SET count = count + 1`).run(account.id, day);
    if (first) database.prepare(`UPDATE account SET first_window_spent = first_window_spent + 1 WHERE id = ?`).run(account.id);
    database.exec("COMMIT");
  } catch (error) {
    try { database.exec("ROLLBACK"); } catch { /* already closed */ }
    throw error;
  }
  let refunded = false;
  return {
    ok: true,
    refund() {
      if (refunded) return;
      refunded = true;
      database.exec("BEGIN IMMEDIATE");
      try {
        database.prepare(`UPDATE root_spend SET count = MAX(0, count - 1) WHERE account_id = ? AND day = ?`).run(account.id, day);
        if (first) database.prepare(`UPDATE account SET first_window_spent = MAX(0, first_window_spent - 1) WHERE id = ?`).run(account.id);
        database.exec("COMMIT");
      } catch (error) {
        try { database.exec("ROLLBACK"); } catch { /* already closed */ }
        throw error;
      }
    },
  };
}
