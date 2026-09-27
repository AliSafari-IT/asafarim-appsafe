# AppSafe

AppSafe is a publicly visible PNPM workspace built around a browser-local encryption toolkit. The reusable crypto core is published as the npm package [`@asafarim/appsafe`](./packages/appsafe). The owner-only product UI lives in `apps/web` and is gated by a server-verified access code; a separate public playground in `apps/demo` demonstrates the package API without the gate.

## Repository layout

| Path | Package name | Purpose |
| --- | --- | --- |
| `packages/appsafe` | `@asafarim/appsafe` | npm-publishable Web Crypto encryption core (AES-256-GCM with PBKDF2 password or ECDH P-256 public-key modes). |
| `packages/shared-tokens` | `@asafarim/shared-tokens` | Local design-token stylesheet consumed by all UIs. |
| `apps/web` | `@asafarim/appsafe-web` | Owner-gated Next.js App Router UI for the encryption tools. |
| `apps/api` | `@asafarim/appsafe-api` | Express gate service that verifies the access code and issues a signed session cookie. |
| `apps/demo` | `@asafarim/appsafe-demo` | Public, ungated Next.js playground for the published package. |
| `packages/appsafe-cli` | `@asafarim/appsafe-cli` | Node.js CLI for config-driven local file and folder encryption. |

The API never receives file contents or encryption passwords. No database is required because the gate session is a stateless HMAC-signed token; add persistence only if revocation or audit history becomes necessary.

## Prerequisites

- Node.js 22 or newer
- PNPM 11 (the workspace pins `pnpm@11.23.0` via `packageManager`)

## Workspace scripts

Run from the repository root.

| Script | Description |
| --- | --- |
| `pnpm install` | Install all workspace dependencies. |
| `pnpm appsafe -- <command>` | Run the local AppSafe CLI. |
| `pnpm build` | Build the CLI, crypto package, and all three apps. |
| `pnpm build:cli` | Build the crypto package and AppSafe CLI. |
| `pnpm build:crypto` | Build only `@asafarim/appsafe`. |
| `pnpm build:demo` | Build the crypto core and the demo app. |
| `pnpm dev` | Build crypto, then run `apps/web` and `apps/api` in parallel. |
| `pnpm dev:demo` | Build crypto, then run `apps/demo` on port 3001 (auto-kills any stale process on 3001 first). |
| `pnpm test` | Run the crypto and CLI test suites. |
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

   For local development, copy `apps/api/.env.example` to `apps/api/.env` and replace the placeholders. The API `dev` script loads that file automatically (Node's `--env-file-if-exists`, Node 22.9+); variables already set in your shell also work. The value of `APP_ACCESS_CODE` is the "Secret access code" you enter in the web app.

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

`@asafarim/appsafe` uses the browser's Web Crypto API and supports two selectable methods. Both finish with AES-256-GCM over an authenticated, versioned `ASAFE` envelope, so a payload always identifies its own method.

- **Password mode (envelope v1, default):** PBKDF2-HMAC-SHA-256 with a random 16-byte salt and 600,000 iterations derives the AES key. Header: magic + version + salt + IV + iteration count.
- **Public-key mode (envelope v2):** a random 256-bit content key encrypts the data; for each of up to 16 recipients, an ephemeral ECDH P-256 exchange and HKDF-SHA-256 derive a key that wraps the content key. Header: magic + version + algorithm + recipient count + IV + one stanza per recipient.

The whole header is AES-GCM additional data in both modes, so wrong passwords, wrong private keys, and any tampering fail closed with typed errors. Every operation uses fresh random salts, nonces, content keys, and ephemeral keys. The public-key construction follows the ECIES / JWE `ECDH-ES+A256KW` pattern with standard Web Crypto primitives only; it shares Age's recipient/identity model but is not Age-compatible.

| Concern | Password mode | Public-key mode |
| --- | --- | --- |
| Who can encrypt | Anyone with the password | Anyone with a recipient public key |
| Who can decrypt | Anyone with the password | Only holders of a listed private key |
| Safe to commit | Ciphertext | Ciphertext and public keys |
| Must stay secret | The password | Private keys |
| Automation | Needs the password in both directions | Encrypt-only jobs need no secret |
| Rotation | New password, re-encrypt every artifact | New key pair, re-encrypt, verify, retire old key |
| Recovery | Lost password = lost data | Lost private key = lost data unless another recipient key exists |

This keeps file contents, passwords, and private keys local, uses standardized primitives already implemented by modern browsers, and avoids shipping a custom cryptographic primitive. Existing password payloads remain decryptable. The gated UI uses `fflate` only to zip selected folder entries before encrypting them.

See [`packages/appsafe/README.md`](./packages/appsafe/README.md) for the full API surface.

## CLI encryption

The separate `@asafarim/appsafe-cli` package adds local filesystem commands without changing the browser-first crypto core. Run `init` to create a starter configuration with placeholders when no configuration exists, then edit the target paths:

```bash
pnpm appsafe -- init
pnpm appsafe -- encrypt --config appsafe.config.json
pnpm appsafe -- decrypt --config appsafe.config.json
pnpm appsafe -- check --config appsafe.config.json
```

The CLI package README documents the full configuration schema and safety behavior.

For public-key mode, create a version-2 config and a key pair. The public key is safe to commit; the private key is added to `.gitignore` automatically:

```bash
pnpm appsafe -- init --mode public-key
pnpm appsafe -- keygen            # .appsafe/key.pub + .appsafe/key.txt
pnpm appsafe -- encrypt           # needs only the public key
pnpm appsafe -- decrypt           # needs the private key
pnpm appsafe -- rekey             # migrate artifacts to the configured mode or keys
```

Modes can be set globally and overridden per file or folder target, so a private application folder and an individual file can use different methods in one config. Version-1 password configs keep working unchanged.

The CLI writes encrypted artifacts beside their sources by default, never deletes sources automatically, and updates `.gitignore` only after every configured target has encrypted successfully. Existing outputs require `--force` to be replaced, and `keygen` never overwrites a private key. Passwords are prompted without echo; `--password-stdin` and `--password-env <name>` are available for automation. Private keys come from the configured `privateKeyFile`, `--private-key-file`, `--private-key-stdin`, or `--private-key-env <name>` — never from literal command-line values. Use `--dry-run` to validate paths and preview changes without writing files.

Key custody, backup, loss, rotation, and CI examples are documented in the CLI README.

Folder targets are archived as ZIP data before encryption. Symbolic links are rejected, and archive extraction validates paths before restoring them. See [`packages/appsafe-cli/README.md`](./packages/appsafe-cli/README.md) for the configuration schema and CLI details.

## Use it as a library

Use the browser package directly in application code:

```ts
import { decryptText, encryptText } from "@asafarim/appsafe";

const payload = await encryptText("private note", password);
const plaintext = await decryptText(payload, password);
```

Or encrypt for a public key so only the private-key holder can decrypt:

```ts
import {
  decryptTextWithPrivateKey,
  encryptTextForRecipients,
  generateKeyPair,
} from "@asafarim/appsafe";

const { publicKey, privateKey } = await generateKeyPair();
const payload = await encryptTextForRecipients("private note", publicKey);
const plaintext = await decryptTextWithPrivateKey(payload, privateKey);
```

Use the Node.js package when your application needs configured filesystem workflows:

```ts
import {
  encryptConfiguredTargets,
  loadConfig,
} from "@asafarim/appsafe-cli";

const loaded = await loadConfig("appsafe.config.json");
await encryptConfiguredTargets(loaded.config, loaded.path, password);
```

See the package READMEs for the complete browser API, CLI commands, configuration schema, and safety behavior.

## Publishing the package

From the workspace root:

```bash
pnpm --filter @asafarim/appsafe build
pnpm --filter @asafarim/appsafe publish --access public

pnpm --filter @asafarim/appsafe-cli build
pnpm --filter @asafarim/appsafe-cli publish --access public
```

The published packages contain only their built `dist` output, README, and LICENSE. The apps and API are not included.

## CI/CD

GitHub Actions runs typechecking, tests, and production builds for pull requests and pushes. A successful push to `main`:

- publishes `@asafarim/appsafe` and `@asafarim/appsafe-cli` only when the package version is not already on npm;
- builds the demo as a static Next.js export;
- deploys the demo artifact to GitHub Pages.

The workflow reads the `NPM_TOKEN` repository Actions secret for npm publishing. Enable GitHub Pages in repository settings with **Build and deployment → Source → GitHub Actions**. Bump a package version before merging a change that should produce a new npm release; already-published versions are skipped safely.

The demo build uses the base path reported by GitHub Pages and does not require application secrets.

## Deployment

Deploy three separate Node web services:

- `apps/api` with `APP_ACCESS_CODE`, `SESSION_SECRET`, `WEB_ORIGIN`, and cookie settings.
- `apps/web` with `API_URL` pointing at the public API URL.
- `apps/demo` with no secrets — it is fully public.

The included [`render.yaml`](./render.yaml) is a starting point for all three services. Add the owner-only secrets in the provider dashboard and set `API_URL` before building the web services.

## License

MIT. See [`LICENSE`](./LICENSE).
