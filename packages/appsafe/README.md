# @asafarim/appsafe

A small browser-first encryption package built on the Web Crypto API. It encrypts arbitrary bytes or UTF-8 text with AES-256-GCM and derives the key from a user-supplied password with PBKDF2-HMAC-SHA-256. Passwords and plaintext stay in the calling runtime; this package performs no network requests.

## Install

```bash
pnpm add @asafarim/appsafe
# or
npm install @asafarim/appsafe
```

Requires a runtime that provides `globalThis.crypto.subtle` (all modern browsers, Node 20+, and Deno).

## API

### `encryptBytes(input, password, options?): Promise<Uint8Array>`

Encrypts an `ArrayBuffer` or `Uint8Array` and returns a self-describing binary payload.

### `decryptBytes(input, password): Promise<Uint8Array>`

Decrypts a payload produced by `encryptBytes`. Throws `AppSafeCryptoError` with code `INVALID_PASSWORD_OR_DATA` if the password or payload is wrong.

### `encryptText(input, password, options?): Promise<Uint8Array>`

UTF-8 encodes the string, then calls `encryptBytes`.

### `decryptText(input, password): Promise<string>`

Calls `decryptBytes` and UTF-8 decodes the result. Throws `AppSafeCryptoError` with code `INVALID_TEXT` if the decrypted bytes are not valid UTF-8.

### `isAppSafePayload(input): boolean`

Cheap header check — verifies the `ASAFE` magic and version byte. Useful for validating a file before attempting decryption.

### `DEFAULT_PBKDF2_ITERATIONS`

The default PBKDF2 work factor: `600_000` SHA-256 iterations.

### `EncryptOptions`

```ts
interface EncryptOptions {
  iterations?: number; // default 600_000; clamped to [100_000, 2_000_000]
}
```

### `AppSafeCryptoError`

Typed error thrown by all functions. Inspect `error.code` to differentiate failure modes:

| Code | Meaning |
| --- | --- |
| `EMPTY_PASSWORD` | No password was provided. |
| `INVALID_OPTIONS` | `iterations` is outside the allowed range. |
| `INVALID_PAYLOAD` | The input is not a supported AppSafe payload. |
| `INVALID_PASSWORD_OR_DATA` | AES-GCM authentication failed. |
| `INVALID_TEXT` | Decrypted bytes are not valid UTF-8. |
| `UNSUPPORTED_RUNTIME` | The runtime has no Web Crypto `subtle` API. |

## Usage

### Text round-trip

```ts
import { decryptText, encryptText } from "@asafarim/appsafe";

const encrypted = await encryptText("private note", password);
const plaintext = await decryptText(encrypted, password);
```

### File round-trip

```ts
import { decryptBytes, encryptBytes } from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
const payload = await encryptBytes(input, password);
const original = await decryptBytes(payload, password);

// Persist or download the payload:
const blob = new Blob([payload], { type: "application/octet-stream" });
```

### Validate a payload before decrypting

```ts
import { isAppSafePayload } from "@asafarim/appsafe";

const bytes = new Uint8Array(await file.arrayBuffer());
if (!isAppSafePayload(bytes)) {
  throw new Error("Not an AppSafe payload");
}
```

### Custom PBKDF2 iterations

```ts
import { encryptBytes } from "@asafarim/appsafe";

const payload = await encryptBytes(data, password, { iterations: 1_000_000 });
```

## Payload format

The returned `Uint8Array` is a single binary envelope:

```
[ magic "ASAFE" (5) ][ version (1) ][ salt (16) ][ iv (12) ][ iterations (4, big-endian) ][ ciphertext + GCM tag ]
```

The full header is authenticated as AES-GCM additional data, so any modification to the salt, IV, or iteration count causes decryption to fail closed.

## Security notes

- Uses standardized primitives already implemented by modern browsers — no custom crypto.
- A new random salt and 96-bit nonce are generated for every encryption operation.
- Wrong passwords and tampered payloads fail closed via AES-GCM authentication.
- The package never reads files, creates downloads, or makes network requests for you.
- The default 600,000-iteration PBKDF2 work factor can be raised via `EncryptOptions.iterations` (max 2,000,000) when your product needs a different performance/security balance.

## License

MIT.
