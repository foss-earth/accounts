import { DatabaseSync } from "node:sqlite";

const SCHEMA = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS account (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  disabled_at TEXT,
  daily_roots INTEGER,
  first_window_ends_at TEXT NOT NULL,
  first_window_spent INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS identity (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account(id),
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  email TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(provider, subject)
);
CREATE INDEX IF NOT EXISTS identity_email ON identity(email);
CREATE TABLE IF NOT EXISTS browser_session (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account(id),
  secret_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS pending_login (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  app_state TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_code (
  hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  account_id TEXT NOT NULL REFERENCES account(id),
  code_challenge TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS access_token (
  hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES account(id),
  client_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS refresh_token (
  hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  account_id TEXT NOT NULL REFERENCES account(id),
  client_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  rotated_at TEXT,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS magic_link (
  hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  pending_id TEXT NOT NULL REFERENCES pending_login(id),
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE TABLE IF NOT EXISTS root_spend (
  account_id TEXT NOT NULL REFERENCES account(id),
  day TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (account_id, day)
);
`;

/** Opens the account store, creating it when the file is new. `:memory:` is a private store. */
export function openDatabase(path: string): DatabaseSync {
  const database = new DatabaseSync(path);
  database.exec(SCHEMA);
  return database;
}
