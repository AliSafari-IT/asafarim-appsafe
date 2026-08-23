# AppSafe

AppSafe is a publicly visible PNPM workspace built around a browser-local encryption toolkit. The reusable crypto core is published as the npm package [`@asafarim/appsafe`](./packages/appsafe). The owner-only product UI lives in `apps/web` and is gated by a server-verified access code; a separate public playground in `apps/demo` demonstrates the package API without the gate.

## Repository layout

| Path | Package name | Purpose |
| --- | --- | --- |
| `packages/appsafe` | `@asafarim/appsafe` | npm-publishable Web Crypto encryption core (AES-256-GCM + PBKDF2). |
| `packages/shared-tokens` | `@asafarim/shared-tokens` | Local design-token stylesheet consumed by all UIs. |
| `apps/web` | `@asafarim/appsafe-web` | Owner-gated Next.js App Router UI for the encryption tools. |
| `apps/api` | `@asafarim/appsafe-api` | Express gate service that verifies the access code and issues a signed session cookie. |
| `apps/demo` | `@asafarim/appsafe-demo` | Public, ungated Next.js playground for the published package. |

The API never receives file contents or encryption passwords. No database is required because the gate session is a stateless HMAC-signed token; add persistence only if revocation or audit history becomes necessary.

## Prerequisites

- Node.js 20 or newer
- PNPM 10 (the workspace pins `pnpm@10.28.2` via `packageManager`)

## Workspace scripts

Run from the repository root.

| Script | Description |
| --- | --- |
| `pnpm install` | Install all workspace dependencies. |
| `pnpm build` | Build every package and all three apps. |
| `pnpm build:crypto` | Build only `@asafarim/appsafe`. |
| `pnpm build:demo` | Build the crypto core and the demo app. |
| `pnpm dev` | Build crypto, then run `apps/web` and `apps/api` in parallel. |
| `pnpm dev:demo` | Build crypto, then run `apps/demo` on port 3001 (auto-kills any stale process on 3001 first). |
| `pnpm test` | Run the `@asafarim/appsafe` crypto test suite. |
| `pnpm typecheck` | Typecheck every package and app. |

## Local setup

1. Install dependencies:

   ```bash
   pnpm install
   ```

2. Copy `.env.example` into the environment used by the API and Next.js processes. The API requires:
   - `APP_ACCESS_CODE` — long random string the owner enters to unlock the gated UI.
   - `SESSION_SECRET` — different random string of at least 32 characters used to sign the gate cookie.
   - `WEB_ORIGIN` — public origin of the web app, used for CORS and cookie scoping.
   - Optional: `COOKIE_SAME_SITE`, `COOKIE_SECURE`, `TRUST_PROXY` for production deployments.

   Do not put `APP_ACCESS_CODE` or `SESSION_SECRET` in the web app environment or commit them.

3. Build the crypto core (required by both apps):

   ```bash
   pnpm build:crypto
   ```

4. Run the gated product (web + API):

   ```bash
   pnpm dev
   ```

   - Web app: `http://localhost:3000`
   - API: `http://localhost:4000`

5. Run the public package playground separately:

   ```bash
   pnpm dev:demo
   ```

   Open `http://localhost:3001`. The demo is intentionally ungated and performs no network requests for encryption or decryption.

`API_URL` is consumed by the Next.js server-side rewrite, so browser requests stay same-origin at `/api/gate/*`. For separate deployments, set `API_URL` to the public Express URL, set `WEB_ORIGIN` on the API to the public web URL, and use `COOKIE_SAME_SITE=none` with `COOKIE_SECURE=true`.

## Unlock flow

1. The browser sends the entered code to `POST /api/gate/verify` over HTTPS.
2. The API compares it against `APP_ACCESS_CODE` using a timing-safe comparison and returns only `{ "unlocked": true }` or `{ "unlocked": false }`. The code is never returned or embedded in the frontend.
3. On success the API sets an HttpOnly, SameSite, expiring cookie containing an HMAC-signed timestamp payload.
4. `GET /api/gate/status` validates the cookie; `POST /api/gate/lock` clears it.

The gate controls application use, not the cryptographic secrecy of the public JavaScript bundle. The owner code remains server-only, while the browser crypto code must necessarily be delivered to the browser to execute.

## Encryption design

`@asafarim/appsafe` uses the browser's Web Crypto API with:

- AES-256-GCM for authenticated encryption;
- PBKDF2-HMAC-SHA-256 with a random 16-byte salt and 600,000 iterations (default) for password-based key derivation;
- a random 96-bit GCM nonce for every operation;
- a versioned binary envelope (`ASAFE` magic + version + salt + IV + iteration count) authenticated as AES-GCM additional data.

This keeps file contents and operation passwords local, uses standardized primitives already implemented by modern browsers, and avoids shipping a custom cryptographic primitive. The gated UI uses `fflate` only to zip selected folder entries before encrypting them.

See [`packages/appsafe/README.md`](./packages/appsafe/README.md) for the full API surface.

## Publishing the package

From the workspace root:

```bash
pnpm --filter @asafarim/appsafe build
pnpm --filter @asafarim/appsafe publish --access public
```

The published package contains only its built `dist` output, README, and LICENSE. The apps and API are not included.

## Deployment

Deploy three separate Node web services:

- `apps/api` with `APP_ACCESS_CODE`, `SESSION_SECRET`, `WEB_ORIGIN`, and cookie settings.
- `apps/web` with `API_URL` pointing at the public API URL.
- `apps/demo` with no secrets — it is fully public.

The included [`render.yaml`](./render.yaml) is a starting point for all three services. Add the owner-only secrets in the provider dashboard and set `API_URL` before building the web services.

## License

MIT. See [`LICENSE`](./LICENSE).
