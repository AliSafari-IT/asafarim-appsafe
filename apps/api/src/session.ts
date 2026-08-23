import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { Request, Response } from "express";
import { config } from "./config.js";

type SessionPayload = {
  iat: number;
  exp: number;
};

function sign(payload: string): string {
  return createHmac("sha256", config.sessionSecret)
    .update(payload)
    .digest("base64url");
}

function encode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function decode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

export function secretsMatch(provided: string, expected: string): boolean {
  const providedDigest = createHash("sha256").update(provided, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();

  return timingSafeEqual(providedDigest, expectedDigest);
}

export function createSessionToken(now = Math.floor(Date.now() / 1000)): string {
  const payload = encode(
    JSON.stringify({
      iat: now,
      exp: now + config.sessionTtlSeconds,
    })
  );

  return `${payload}.${sign(payload)}`;
}

export function verifySessionToken(token: string | undefined): boolean {
  if (!token) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [payload, signature] = parts;
  const actualSignature = Buffer.from(signature, "base64url");
  const expectedSignature = Buffer.from(sign(payload), "base64url");

  if (
    actualSignature.length !== expectedSignature.length ||
    !timingSafeEqual(actualSignature, expectedSignature)
  ) {
    return false;
  }

  try {
    const parsed = JSON.parse(decode(payload)) as Partial<SessionPayload>;
    const issuedAt = parsed.iat;
    const expiresAt = parsed.exp;
    const now = Math.floor(Date.now() / 1000);

    if (
      typeof issuedAt !== "number" ||
      typeof expiresAt !== "number" ||
      !Number.isSafeInteger(issuedAt) ||
      !Number.isSafeInteger(expiresAt)
    ) {
      return false;
    }

    return expiresAt > now && issuedAt <= now + 60;
  } catch {
    return false;
  }
}

export function getCookie(request: Request, name: string): string | undefined {
  const header = request.headers.cookie;

  if (!header) {
    return undefined;
  }

  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key = pair.slice(0, separator).trim();

    if (key !== name) {
      continue;
    }

    try {
      return decodeURIComponent(pair.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }

  return undefined;
}

export function hasValidSession(request: Request): boolean {
  return verifySessionToken(getCookie(request, config.cookieName));
}

export function setSessionCookie(response: Response): void {
  const cookie = [
    `${config.cookieName}=${createSessionToken()}`,
    "Path=/",
    "HttpOnly",
    `Max-Age=${config.sessionTtlSeconds}`,
    `SameSite=${config.cookieSameSite}`,
  ];

  if (config.cookieSecure) {
    cookie.push("Secure");
  }

  response.setHeader("Set-Cookie", cookie.join("; "));
}

export function clearSessionCookie(response: Response): void {
  const cookie = [
    `${config.cookieName}=`,
    "Path=/",
    "HttpOnly",
    "Max-Age=0",
    `SameSite=${config.cookieSameSite}`,
  ];

  if (config.cookieSecure) {
    cookie.push("Secure");
  }

  response.setHeader("Set-Cookie", cookie.join("; "));
}
