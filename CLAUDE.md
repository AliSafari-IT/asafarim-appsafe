# CLAUDE.md

Project-level guidance for AI agents working in this repository.

## Project overview

AppSafe is a PNPM monorepo built around a browser-local encryption toolkit. The reusable crypto core is published as the npm package `@asafarim/appsafe`. The owner-only product UI (`apps/web`) is gated by a server-verified access code; a separate public playground (`apps/demo`) demonstrates the package API without the gate.

## Repository layout

| Path | Package | Purpose |
| --- | --- | --- |
| `packages/appsafe` | `@asafarim/appsafe` | npm-publishable Web Crypto encryption core (AES-256-GCM with PBKDF2 password or ECDH P-256 public-key modes). |
| `packages/shared-tokens` | `@asafarim/shared-tokens` | Local design-token stylesheet consumed by all UIs. |
| `apps/web` | `@asafarim/appsafe-web` | Owner-gated Next.js App Router UI. |
| `apps/api` | `@asafarim/appsafe-api` | Express gate service; verifies access code, issues signed cookie. |
| `apps/demo` | `@asafarim/appsafe-demo` | Public, ungated Next.js playground for the package. |
| `packages/appsafe-cli` | `@asafarim/appsafe-cli` | Node.js CLI for config-driven local file and folder encryption. |

## Tech stack

- **Package manager:** PNPM 11 (pinned via `packageManager` in root `package.json`).
- **Node:** >= 22.0.0.
- **Language:** TypeScript everywhere. Strict mode.
- **Frontend:** Next.js 16 App Router, React 19, Turbopack for dev.
- **Backend:** Express 5, Helmet, express-rate-limit, CORS.
- **Crypto:** Web Crypto API only — no custom primitives, no Node `crypto` for the package.
- **Styling:** Plain CSS using design-token CSS variables from `@asafarim/shared-tokens`. **No Tailwind.**

## Commands

Run from the repository root.

| Command | Description |
| --- | --- |
| `pnpm install` | Install all workspace dependencies. |
| `pnpm appsafe -- <command>` | Run the local AppSafe CLI. |
| `pnpm build` | Build the CLI, crypto package, and all three apps. |
| `pnpm build:cli` | Build the crypto package and AppSafe CLI. |
| `pnpm build:crypto` | Build only `@asafarim/appsafe`. |
| `pnpm build:demo` | Build the crypto core and the demo app. |
| `pnpm dev` | Build crypto, then run `apps/web` (port 3000) and `apps/api` (port 4000) in parallel. |
| `pnpm dev:demo` | Build crypto, then run `apps/demo` on port 3001 (auto-kills any stale process on 3001 first via `kill-port`). |
| `pnpm test` | Run the crypto and CLI test suites (`tsx --test`). |
| `pnpm typecheck` | Typecheck every package and app. |

Per-app scripts live in each `apps/*/package.json` and can be run via `pnpm --filter <pkg-name> <script>`.

## Architecture rules

### Crypto package (`packages/appsafe`)

- Browser-first: relies on `globalThis.crypto.subtle`. No Node-specific imports.
- Two selectable modes, both ending in AES-256-GCM: password (PBKDF2-HMAC-SHA-256) and public-key (ECDH P-256 + HKDF-SHA-256 key wrapping, 1–16 recipients).
- Default 600,000 PBKDF2 iterations; callers may pass `iterations` in `[100_000, 2_000_000]`.
- Password envelope (version 1): `ASAFE` magic (5 bytes) + version (1) + salt (16) + IV (12) + iterations (4, big-endian) + ciphertext+tag.
- Public-key envelope (version 2): `ASAFE` magic (5) + version (1) + algorithm (1) + recipient count (1) + IV (12) + 141-byte stanza per recipient (key id, ephemeral public key, wrap IV, wrapped key) + ciphertext+tag.
- The full header is authenticated as AES-GCM additional data in both versions. Version-1 payloads must stay decryptable.
- Key text formats: `appsafe-pub-p256:<base64url>` and `APPSAFE-PRIVATE-KEY-P256:<base64url>`. Not Age-compatible.
- All exported functions throw `AppSafeCryptoError` with a typed `code` field — never rethrow raw `Error`. Error messages never include keys or passwords.
- Wrong passwords, wrong private keys, cross-mode use, and tampered payloads must fail closed.
- The package performs **no network requests** and never reads files or creates downloads.
- Published package contains only `dist`, `README.md`, and `LICENSE`.

### CLI package (`packages/appsafe-cli`)

- Node.js-only filesystem layer; keep Node-specific imports out of the browser crypto package.
- Configuration versions `1` (password only) and `2` (global `encryption.mode` plus per-target overrides) are both supported; target paths are resolved relative to the config file.
- `init` creates a placeholder configuration only when the requested config path is absent; it never overwrites an existing config.
- `keygen` never overwrites a private key and adds it to `.gitignore` before writing it.
- Encrypt files directly and archive folders as ZIP data before encrypting. Decryption selects the mode from each payload header.
- Do not store passwords or private-key material in configuration; prompt without echo or use explicit stdin/environment/file options. Never accept secrets as literal CLI arguments.
- `rekey` re-encrypts every artifact in memory before replacing any file.
- Write outputs atomically, reject symbolic links and unsafe archive paths, and require `--force` for replacements.
- Update `.gitignore` only after all configured targets encrypt successfully; never delete sources automatically.

### Gate API (`apps/api`)

- `APP_ACCESS_CODE` and `SESSION_SECRET` come from environment variables — never commit them, never expose them to the web app.
- Compare the access code with a timing-safe comparison.
- Issue an HttpOnly, SameSite, expiring signed cookie. Stateless — no database.
- Routes: `POST /api/gate/verify`, `GET /api/gate/status`, `POST /api/gate/lock`, `GET /health`.
- Helmet, rate limiting, and CORS are required.

### Web app (`apps/web`)

- Publicly visible landing page; encryption UI mounts only after a successful gate check.
- Server-side rewrite proxies `/api/gate/*` to the Express API via `API_URL`, so browser requests stay same-origin.
- Uses `fflate` only to zip folder entries before encrypting — not for crypto.
- File contents and operation passwords never leave the browser.

### Demo app (`apps/demo`)

- Public, ungated reference implementation for package consumers.
- No network requests for encryption or decryption.
- Demonstrates both modes: `encryptText`/`decryptText`, `encryptBytes`/`decryptBytes`, `generateKeyPair`, `encrypt*ForRecipients`/`decrypt*WithPrivateKey`, and `inspectAppSafePayload`.
- Demo keys are ephemeral (React state only). Includes flow diagrams, a live failure lab, a mode comparison, and copyable TypeScript recipes.

## Design token compliance

All UIs must import the shared token stylesheet:

```ts
import "@asafarim/shared-tokens/styles.css";
```

**No hard-coded values** for colors, spacing, radius, typography, shadows, or transitions. Use the CSS custom properties defined in `packages/shared-tokens/styles.css` (e.g. `var(--color-surface)`, `var(--space-4)`, `var(--radius-lg)`). If a token is missing, pick a reasonable existing token and proceed.

## Environment variables

| Variable | Used by | Notes |
| --- | --- | --- |
| `APP_ACCESS_CODE` | `apps/api` | Owner-only secret. Long random string. Never exposed client-side. |
| `SESSION_SECRET` | `apps/api` | Signs the gate cookie. >= 32 chars. Different from `APP_ACCESS_CODE`. |
| `WEB_ORIGIN` | `apps/api` | Public web origin for CORS and cookie scoping. |
| `API_URL` | `apps/web` | Public API URL for the server-side rewrite. |
| `COOKIE_SAME_SITE` | `apps/api` | `lax` (default) or `none` for cross-site deployments. |
| `COOKIE_SECURE` | `apps/api` | `true` in production. |
| `TRUST_PROXY` | `apps/api` | `true` behind a reverse proxy. |
| `NPM_TOKEN` | GitHub Actions | Repository secret used only for npm publishing. |

See `.env.example` and `apps/api/.env.example` for templates.

## Code style

- TypeScript strict mode everywhere.
- Compact code: collapse duplicate branches, avoid unnecessary nesting, share abstractions.
- Do not add or remove comments unless asked.
- Do not over-engineer; keep components clean and predictable.
- Follow existing patterns in neighboring files before introducing new abstractions.
- Error handling: handle errors at the right boundary, do not wrap every line in try/catch.

## Verification

Before considering a task complete, run:

```bash
pnpm typecheck
pnpm test
pnpm build
```

For demo-only changes, `pnpm build:demo` plus `pnpm --filter @asafarim/appsafe-demo typecheck` is sufficient.

## CI/CD

- Pull requests and pushes run typecheck, tests, and production builds.
- Successful pushes to `main` publish `@asafarim/appsafe` and `@asafarim/appsafe-cli` when their versions are not already on npm.
- Successful pushes to `main` deploy the statically exported `apps/demo` build to GitHub Pages.
- The Pages build sets `NEXT_PUBLIC_BASE_PATH` from the GitHub Pages metadata and requires no application secrets.
- npm publishing reads only the `NPM_TOKEN` repository Actions secret.

## Deployment

Three separate Node web services defined in `render.yaml`:

1. `appsafe-api` — Express gate service with secrets.
2. `appsafe-web` — gated Next.js app with `API_URL`.
3. `appsafe-demo` — public Next.js app, no secrets.

Add owner-only secrets in the provider dashboard; set `API_URL` before building the web services.

## Security boundaries

- Never expose `APP_ACCESS_CODE` or `SESSION_SECRET` to the browser.
- Never commit secrets or `.env` files.
- Never modify security policies, branch protection, or compliance controls to work around CI failures — escalate instead.
- The gate controls application use, not the cryptographic secrecy of the public JS bundle. Browser crypto code is necessarily public.
- Assist with defensive security tasks only.

## Publishing

```bash
pnpm --filter @asafarim/appsafe build
pnpm --filter @asafarim/appsafe publish --access public

pnpm --filter @asafarim/appsafe-cli build
pnpm --filter @asafarim/appsafe-cli publish --access public
```

`prepublishOnly` runs the build automatically. The published tarballs exclude source, tests, and apps.
