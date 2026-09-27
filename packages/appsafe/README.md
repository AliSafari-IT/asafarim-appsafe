# @asafarim/appsafe

A small browser-first encryption package built on the Web Crypto API. It encrypts arbitrary bytes or UTF-8 text with AES-256-GCM using one of two selectable methods:

- **Password mode** — the key is derived from a user-supplied password with PBKDF2-HMAC-SHA-256. The same password encrypts and decrypts.
- **Public-key mode** — data is encrypted for one or more recipient public keys (ECDH P-256 + HKDF-SHA-256 key wrapping). Only a matching private key decrypts.

Passwords, private keys, and plaintext stay in the calling runtime; this package performs no network requests.

## Install

```bash
pnpm add @asafarim/appsafe
# or
npm install @asafarim/appsafe
```

Requires a runtime that provides `globalThis.crypto.subtle` with AES-GCM, PBKDF2, HKDF, and ECDH P-256: all evergreen browsers, Node 20+, and Deno. Both methods, including key generation, work in the browser.

## Choosing a method

| Concern | Password mode | Public-key mode |
| --- | --- | --- |
| Who can encrypt | Anyone with the password | Anyone with a recipient public key |
| Who can decrypt | Anyone with the password | Only holders of a listed private key |
| Secret material | The password | Private keys only |
| Safe to commit | Ciphertext | Ciphertext and public keys |
| Multiple people | Everyone shares one secret | Up to 16 recipients per payload, each with their own key |
| CI / deployment | Inject the password; the job can also re-encrypt | Encrypt-only jobs need no secret; decrypting jobs receive a private key |
| Rotation | Choose a new password and re-encrypt every artifact | Generate a new key pair, re-encrypt for it, verify, then retire the old key |
| Loss of the secret | Unrecoverable | Unrecoverable unless another listed recipient's key still works |

Use password mode for personal workflows and quick sharing. Use public-key mode for teams, CI, and private application sources committed as ciphertext.

## Password API

### `encryptBytes(input, password, options?): Promise<Uint8Array>`

Encrypts an `ArrayBuffer` or `Uint8Array` and returns a self-describing binary payload.

### `decryptBytes(input, password): Promise<Uint8Array>`

Decrypts a payload produced by `encryptBytes`. Throws `INVALID_PASSWORD_OR_DATA` if the password or payload is wrong, and `MODE_MISMATCH` for a public-key payload.

### `encryptText(input, password, options?)` / `decryptText(input, password)`

UTF-8 wrappers around the byte functions. `decryptText` throws `INVALID_TEXT` if the decrypted bytes are not valid UTF-8.

### `EncryptOptions` and `DEFAULT_PBKDF2_ITERATIONS`

```ts
interface EncryptOptions {
  iterations?: number; // default 600_000; must be within [100_000, 2_000_000]
}
```

## Public-key API

### `generateKeyPair(): Promise<AppSafeKeyPair>`

Generates a P-256 key pair in memory.

```ts
interface AppSafeKeyPair {
  publicKey: string;   // "appsafe-pub-p256:…"          safe to share and commit
  privateKey: string;  // "APPSAFE-PRIVATE-KEY-P256:…"  secret
  fingerprint: string; // 32 hex characters identifying the public key
}
```

### `encryptBytesForRecipients(input, recipients): Promise<Uint8Array>`

Encrypts for one public key or an array of 1–16 public keys. Duplicate keys are ignored. A fresh random content key encrypts the data once, and a separately wrapped copy of that key is stored for each recipient.

### `decryptBytesWithPrivateKey(input, privateKey): Promise<Uint8Array>`

Decrypts a public-key payload. Throws `NO_MATCHING_KEY` if the private key is not a recipient, `INVALID_KEY_OR_DATA` if unwrapping or authentication fails, and `MODE_MISMATCH` for a password payload.

### `encryptTextForRecipients(input, recipients)` / `decryptTextWithPrivateKey(input, privateKey)`

UTF-8 wrappers around the public-key byte functions.

### `getPublicKey(privateKey): string` and `getKeyFingerprint(publicKey): Promise<string>`

Derive the public key from a private key, and compute a public key's fingerprint. Fingerprints are public identifiers and never reveal private material. `getKeyFingerprint` rejects private keys so a private key cannot be mistaken for a public one.

## Payload inspection

### `inspectAppSafePayload(input): AppSafePayloadInfo`

Parses and validates the header without decrypting. Throws `INVALID_PAYLOAD` for malformed input.

```ts
type AppSafePayloadInfo =
  | { mode: "password"; version: 1; iterations: number }
  | {
      mode: "public-key";
      version: 2;
      algorithm: "ECDH-P256+HKDF-SHA256+A256GCM";
      recipients: string[]; // recipient fingerprints
    };
```

### `isAppSafePayload(input): boolean`

Returns `true` when `inspectAppSafePayload` would succeed.

## Errors

Every function throws `AppSafeCryptoError` with a typed `code`. Messages never contain passwords, keys, or plaintext.

| Code | Meaning |
| --- | --- |
| `EMPTY_PASSWORD` | No password was provided. |
| `INVALID_OPTIONS` | Iterations are out of range, or the recipient count is not 1–16. |
| `INVALID_PAYLOAD` | The input is not a supported, complete AppSafe payload. |
| `INVALID_PASSWORD_OR_DATA` | Password-mode authentication failed. |
| `INVALID_KEY` | A key is malformed, not on the curve, or the wrong kind (public vs private). |
| `NO_MATCHING_KEY` | The private key is not a recipient of the payload. |
| `INVALID_KEY_OR_DATA` | Public-key unwrapping or authentication failed. |
| `MODE_MISMATCH` | A password was used on a public-key payload, or vice versa. |
| `INVALID_TEXT` | Decrypted bytes are not valid UTF-8. |
| `UNSUPPORTED_RUNTIME` | The runtime lacks the required Web Crypto support. |

## Recipes

### Password text round-trip

```ts
import { decryptText, encryptText } from "@asafarim/appsafe";

const encrypted = await encryptText("private note", password);
const plaintext = await decryptText(encrypted, password);
```

### Password file round-trip

```ts
import { decryptBytes, encryptBytes } from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
const payload = await encryptBytes(input, password);
const original = await decryptBytes(payload, password);

const blob = new Blob([payload], { type: "application/octet-stream" });
```

### Public-key round-trip

```ts
import {
  decryptBytesWithPrivateKey,
  encryptBytesForRecipients,
  generateKeyPair,
} from "@asafarim/appsafe";

const { publicKey, privateKey } = await generateKeyPair();
const payload = await encryptBytesForRecipients(input, publicKey);
const original = await decryptBytesWithPrivateKey(payload, privateKey);
```

### Multiple recipients

```ts
import { encryptTextForRecipients } from "@asafarim/appsafe";

const payload = await encryptTextForRecipients(note, [ownerPublicKey, deployPublicKey]);
```

### Detect the mode and handle failures

```ts
import {
  AppSafeCryptoError,
  decryptBytes,
  decryptBytesWithPrivateKey,
  inspectAppSafePayload,
} from "@asafarim/appsafe";

try {
  const info = inspectAppSafePayload(payload);
  const plaintext = info.mode === "password"
    ? await decryptBytes(payload, password)
    : await decryptBytesWithPrivateKey(payload, privateKey);
} catch (error) {
  if (error instanceof AppSafeCryptoError) {
    console.warn(error.code);
  }
}
```

## Payload formats

Both formats begin with the `ASAFE` magic and a version byte, so decryption selects the method from the payload itself rather than guessing.

### Version 1 — password

```
[ "ASAFE" (5) ][ 0x01 (1) ][ salt (16) ][ iv (12) ][ iterations (4, big-endian) ][ ciphertext + GCM tag ]
```

The full header is AES-GCM additional data. Version-1 payloads created by earlier releases remain fully supported.

### Version 2 — public key

```
[ "ASAFE" (5) ][ 0x02 (1) ][ algorithm 0x01 (1) ][ recipient count (1) ][ content iv (12) ]
[ recipient stanza × count ][ ciphertext + GCM tag ]

recipient stanza (141 bytes):
[ key id (16) ][ ephemeral P-256 public key (65) ][ wrap iv (12) ][ wrapped content key + tag (48) ]
```

For each recipient:

1. Generate an ephemeral P-256 key pair and compute ECDH with the recipient public key.
2. Derive a wrap key with HKDF-SHA-256 (salt: ephemeral public key ‖ recipient public key; info: `AppSafe v2 ECDH-P256 HKDF-SHA-256 A256GCM key wrap`).
3. Wrap the random 256-bit content key with AES-256-GCM, authenticating the header prefix, key id, and ephemeral public key.

The content is encrypted once with AES-256-GCM, and the entire header — version, algorithm, recipient count, IV, and every stanza — is its additional data. The key id is the first 16 bytes of SHA-256 over the recipient's uncompressed public key; it is displayed as the key fingerprint.

The construction follows the ECIES / JWE `ECDH-ES+A256KW` pattern using only standard Web Crypto primitives. It uses the same recipient/identity model as [Age](https://age-encryption.org/), but it is **not Age-compatible**: Age relies on X25519 and ChaCha20-Poly1305, which are not uniformly available through Web Crypto.

### Key text format

```
appsafe-pub-p256:<base64url of the 65-byte uncompressed public point>
APPSAFE-PRIVATE-KEY-P256:<base64url of the public point followed by the 32-byte private scalar>
```

Leading and trailing whitespace is ignored.

## Security notes

- Uses standardized primitives already implemented by browsers — no custom cryptography.
- Every operation uses fresh random salts, IVs, content keys, and ephemeral keys.
- Wrong passwords, wrong private keys, truncated payloads, and any modification to the header or ciphertext fail closed with a typed error.
- The package never reads files, stores keys, creates downloads, or makes network requests. Key storage is the caller's responsibility; the [`@asafarim/appsafe-cli`](../appsafe-cli) package manages key files.
- Losing the password, or every private key a payload was encrypted for, makes that payload unrecoverable. Back up private keys and encrypt for a second recovery key where appropriate.
- The PBKDF2 work factor can be raised via `EncryptOptions.iterations` (max 2,000,000).

## License

MIT.
