type CookieSameSite = "lax" | "strict" | "none";

function required(name: string): string {
  const value = process.env[name];

  if (!value || value.trim().length === 0) {
    throw new Error(`[config] Missing required environment variable: ${name}`);
  }

  return value;
}

function positiveInteger(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);

  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`[config] ${name} must be a positive integer`);
  }

  return value;
}

const nodeEnv = process.env.NODE_ENV ?? "development";
const accessCode = required("APP_ACCESS_CODE");
const sessionSecret = required("SESSION_SECRET");

if (accessCode.length < 8) {
  throw new Error("[config] APP_ACCESS_CODE must be at least 8 characters long");
}

if (Buffer.byteLength(sessionSecret, "utf8") < 32) {
  throw new Error("[config] SESSION_SECRET must be at least 32 bytes long");
}

const cookieSameSite = (process.env.COOKIE_SAME_SITE?.toLowerCase() ??
  "lax") as CookieSameSite;

if (!["lax", "strict", "none"].includes(cookieSameSite)) {
  throw new Error("[config] COOKIE_SAME_SITE must be lax, strict, or none");
}

const cookieSecure = process.env.COOKIE_SECURE === "true" || nodeEnv === "production";

if (cookieSameSite === "none" && !cookieSecure) {
  throw new Error("[config] COOKIE_SECURE must be true when COOKIE_SAME_SITE is none");
}

export const config = {
  accessCode,
  sessionSecret,
  port: positiveInteger("PORT", 4000),
  sessionTtlSeconds: positiveInteger("SESSION_TTL_SECONDS", 28_800),
  webOrigins: (process.env.WEB_ORIGIN ?? "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean),
  cookieName: "appsafe_session",
  cookieSameSite,
  cookieSecure,
  trustProxy: process.env.TRUST_PROXY === "true",
};
