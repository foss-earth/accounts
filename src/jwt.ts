import { createPublicKey, verify, type JsonWebKey } from "node:crypto";

export class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TokenError";
  }
}

function decode(segment: string): string {
  return Buffer.from(segment, "base64url").toString("utf8");
}

export interface JwtChecks {
  audience: string;
  /** Accepts the token's issuer. */
  issuer(iss: string): boolean;
  now: Date;
}

/**
 * Verifies an RS256 JWT against one JWK. Refuses a wrong audience, issuer,
 * expiry, or signature. Does not trust the header's embedded key.
 */
export function verifyRs256(token: string, jwk: JsonWebKey, checks: JwtChecks): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new TokenError("The identity token is not a JWT.");
  const [encodedHeader, encodedPayload, encodedSignature] = parts as [string, string, string];
  let header: { alg?: unknown; kid?: unknown };
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(decode(encodedHeader)) as { alg?: unknown };
    payload = JSON.parse(decode(encodedPayload)) as Record<string, unknown>;
  } catch {
    throw new TokenError("The identity token could not be read.");
  }
  if (header.alg !== "RS256") throw new TokenError("The identity token is not RS256.");
  const key = createPublicKey({ key: jwk, format: "jwk" });
  const signature = Buffer.from(encodedSignature, "base64url");
  const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`);
  if (!verify("RSA-SHA256", signed, key, signature)) throw new TokenError("The identity token signature is not valid.");
  if (typeof payload.iss !== "string" || !checks.issuer(payload.iss)) throw new TokenError("The identity token issuer is not accepted.");
  const audience = payload.aud;
  const audiences = Array.isArray(audience) ? audience : [audience];
  if (!audiences.includes(checks.audience)) throw new TokenError("The identity token is for a different app.");
  if (typeof payload.exp !== "number" || payload.exp * 1000 <= checks.now.getTime()) throw new TokenError("The identity token has expired.");
  return payload;
}

/** Finds the JWK with `kid`, or the only key when the token names none. */
export function selectJwk(keys: readonly JsonWebKey[], kid: string | null): JsonWebKey {
  const named = kid ? keys.find(key => key.kid === kid) : undefined;
  const only = keys.length === 1 ? keys[0] : undefined;
  const key = named ?? only;
  if (!key) throw new TokenError("No signing key matches the identity token.");
  return key;
}

export function tokenKid(token: string): string | null {
  const encoded = token.split(".")[0];
  if (!encoded) return null;
  try {
    const header = JSON.parse(decode(encoded)) as { kid?: unknown };
    return typeof header.kid === "string" ? header.kid : null;
  } catch {
    return null;
  }
}
