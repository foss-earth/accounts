import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dir = path.join(root, "build", "dev-cert");
mkdirSync(dir, { recursive: true });
const key = path.join(dir, "key.pem");
const cert = path.join(dir, "cert.pem");
try {
  readFileSync(key);
  readFileSync(cert);
} catch {
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "90",
    "-subj", "/CN=FOSS Earth accounts", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", key, "-out", cert], { stdio: "pipe" });
  writeFileSync(path.join(dir, "certificate.json"), `${JSON.stringify({ names: ["DNS:localhost"] })}\n`);
}

const child = spawn(process.execPath, ["--experimental-strip-types", path.join(root, "src", "server.ts")], {
  cwd: root,
  stdio: "inherit",
  env: {
    ...process.env,
    ACCOUNT_ORIGIN: process.env.ACCOUNT_ORIGIN?.trim() || "https://localhost:8787",
    PORT: process.env.PORT?.trim() || "8787",
    TLS_KEY: key,
    TLS_CERT: cert,
    ACCOUNT_DATABASE: process.env.ACCOUNT_DATABASE?.trim() || path.join(root, "build", "accounts.sqlite"),
  },
});
child.on("exit", code => process.exit(code ?? 0));
