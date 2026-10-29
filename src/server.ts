#!/usr/bin/env node
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createAccountApp } from "./app.js";
import { readConfig } from "./config.js";
import { httpsMailer } from "./mail.js";
import { githubProvider, googleProvider, microsoftProvider, type OAuthProvider, type ProviderId } from "./providers.js";
import { openDatabase } from "./schema.js";

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => resolve());
  });
}

function adapter(handle: (request: Request) => Promise<Response>) {
  return (incoming: IncomingMessage, outgoing: ServerResponse): void => {
    const chunks: Buffer[] = [];
    incoming.on("data", (chunk: Buffer) => { chunks.push(chunk); });
    incoming.on("end", () => {
      const host = incoming.headers.host ?? "localhost";
      const protocol = incoming.socket && "encrypted" in incoming.socket && incoming.socket.encrypted ? "https" : "http";
      const url = new URL(incoming.url ?? "/", `${protocol}://${host}`);
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value === undefined) continue;
        if (Array.isArray(value)) for (const item of value) headers.append(name, item);
        else headers.set(name, value);
      }
      const address = incoming.socket.remoteAddress;
      if (address && !headers.has("x-foss-earth-client")) headers.set("x-foss-earth-client", address);
      const body = chunks.length ? Buffer.concat(chunks) : undefined;
      const request = new Request(url, { method: incoming.method, headers, body: body && incoming.method !== "GET" && incoming.method !== "HEAD" ? body : undefined });
      void handle(request).then(async response => {
        const tuples: [string, string][] = [];
        response.headers.forEach((value, name) => {
          if (name.toLowerCase() === "set-cookie") return;
          tuples.push([name, value]);
        });
        for (const value of response.headers.getSetCookie()) tuples.push(["set-cookie", value]);
        outgoing.writeHead(response.status, tuples);
        if (response.body) {
          const reader = response.body.getReader();
          const pump = async (): Promise<void> => {
            const next = await reader.read();
            if (next.done) { outgoing.end(); return; }
            outgoing.write(Buffer.from(next.value));
            await pump();
          };
          await pump();
        } else outgoing.end();
      }).catch(error => {
        console.error(error instanceof Error ? error.message : "Request failed.");
        if (!outgoing.headersSent) outgoing.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        outgoing.end("The account service hit an unexpected error.");
      });
    });
  };
}

/** Starts the account process from the environment. */
export async function startServer(): Promise<Server> {
  const config = readConfig();
  const database = openDatabase(config.databasePath);
  const redirect = (provider: ProviderId) => `${config.accountOrigin}/callback/${provider}`;
  const providers: Partial<Record<ProviderId, OAuthProvider>> = {};
  if (config.google) providers.google = googleProvider({ ...config.google, redirectUri: redirect("google"), fetch, now: () => new Date() });
  if (config.github) providers.github = githubProvider({ ...config.github, redirectUri: redirect("github"), fetch });
  if (config.microsoft) providers.microsoft = microsoftProvider({ ...config.microsoft, redirectUri: redirect("microsoft"), fetch, now: () => new Date() });
  const app = createAccountApp({
    database,
    accountOrigin: config.accountOrigin,
    clients: config.clients,
    providers,
    mail: config.mail ? httpsMailer(config.mail) : undefined,
    googleTilesKey: config.googleTilesKey,
    rootsPerDay: config.rootsPerDay,
    rootsFirstDay: config.rootsFirstDay,
  });
  const handler = adapter(request => app.handle(request));
  const server = config.tls
    ? createHttpsServer({ key: readFileSync(config.tls.keyPath), cert: readFileSync(config.tls.certPath) }, handler)
    : createHttpServer(handler);
  await listen(server, config.port);
  console.log(`Accounts listening on ${config.accountOrigin} (port ${config.port}).`);
  return server;
}

const entry = process.argv[1]?.replaceAll("\\", "/");
if (entry && (entry.endsWith("/server.ts") || entry.endsWith("/server.js"))) {
  startServer().catch(error => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
