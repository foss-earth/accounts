#!/usr/bin/env node
import { readConfig } from "./config.js";
import { setDailyRoots, setDisabled } from "./records.js";
import { openDatabase } from "./schema.js";
import { normalizeEmail } from "./text.js";
import type { DatabaseSync } from "node:sqlite";

export interface CliIO {
  log(message: string): void;
  error(message: string): void;
}

/** Runs one admin command. Returns the process status. */
export function runCli(argv: readonly string[], database: DatabaseSync, io: CliIO, now = new Date()): number {
  const [command, action, ...rest] = argv;
  const emailFlag = rest.indexOf("--email");
  const email = emailFlag >= 0 ? rest[emailFlag + 1] : undefined;
  if (command === "quota" && action === "set") {
    const rootsFlag = rest.indexOf("--daily-roots");
    const roots = rootsFlag >= 0 ? Number(rest[rootsFlag + 1]) : NaN;
    if (!email || !Number.isInteger(roots) || roots < 0) {
      io.error("Usage: accounts quota set --email person@example.com --daily-roots 40");
      return 1;
    }
    const account = setDailyRoots(database, email, roots);
    if (!account) {
      io.error(`No account for ${normalizeEmail(email)}.`);
      return 1;
    }
    io.log(`${account.email}: ${roots} root requests a day.`);
    return 0;
  }
  if (command === "account" && (action === "disable" || action === "enable")) {
    if (!email) {
      io.error(`Usage: accounts account ${action} --email person@example.com`);
      return 1;
    }
    const account = setDisabled(database, email, action === "disable", now);
    if (!account) {
      io.error(`No account for ${normalizeEmail(email)}.`);
      return 1;
    }
    io.log(`${account.email}: ${account.disabled_at ? "disabled" : "enabled"}.`);
    return 0;
  }
  io.error("Usage: accounts quota set | accounts account disable | accounts account enable");
  return 1;
}

const entry = process.argv[1]?.replaceAll("\\", "/");
if (entry && (entry.endsWith("/cli.ts") || entry.endsWith("/cli.js"))) {
  const config = readConfig();
  const database = openDatabase(config.databasePath);
  const status = runCli(process.argv.slice(2), database, { log: message => console.log(message), error: message => console.error(message) });
  database.close();
  process.exitCode = status;
}
