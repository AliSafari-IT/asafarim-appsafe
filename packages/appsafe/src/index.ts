const MAGIC = new Uint8Array([0x41, 0x53, 0x41, 0x46, 0x45]);
const PASSWORD_VERSION = 1;
const PUBLIC_KEY_VERSION = 2;
const P256_ALGORITHM = 1;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const HEADER_LENGTH = MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH + 4;
const AUTH_TAG_LENGTH = 16;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 2_000_000;
const RECIPIENT_PREFIX_LENGTH = MAGIC.length + 3;
const RECIPIENT_HEADER_LENGTH = RECIPIENT_PREFIX_LENGTH + IV_LENGTH;
const KEY_ID_LENGTH = 16;
const PUBLIC_KEY_LENGTH = 65;
const PRIVATE_SCALAR_LENGTH = 32;
const CONTENT_KEY_LENGTH = 32;
const WRAPPED_KEY_LENGTH = CONTENT_KEY_LENGTH + AUTH_TAG_LENGTH;
const STANZA_LENGTH = KEY_ID_LENGTH + PUBLIC_KEY_LENGTH + IV_LENGTH + WRAPPED_KEY_LENGTH;
const PUBLIC_KEY_PREFIX = "appsafe-pub-p256:";
const PRIVATE_KEY_PREFIX = "APPSAFE-PRIVATE-KEY-P256:";
const KEY_WRAP_INFO = "AppSafe v2 ECDH-P256 HKDF-SHA-256 A256GCM key wrap";
const EC_PARAMS = { name: "ECDH", namedCurve: "P-256" } as const;

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
export const MAX_RECIPIENTS = 16;
export const PUBLIC_KEY_ALGORITHM = "ECDH-P256+HKDF-SHA256+A256GCM";

export type ByteSource = ArrayBuffer | Uint8Array;

export type AppSafeEncryptionMode = "password" | "public-key";

export type AppSafeCryptoErrorCode =
  | "EMPTY_PASSWORD"
  | "INVALID_OPTIONS"
  | "INVALID_PAYLOAD"
  | "INVALID_PASSWORD_OR_DATA"
  | "INVALID_KEY"
  | "INVALID_KEY_OR_DATA"
  | "NO_MATCHING_KEY"
  | "MODE_MISMATCH"
  | "INVALID_TEXT"
  | "UNSUPPORTED_RUNTIME";

export class AppSafeCryptoError extends Error {
  readonly code: AppSafeCryptoErrorCode;

  constructor(code: AppSafeCryptoErrorCode, message: string) {
    super(message);
    this.name = "AppSafeCryptoError";
    this.code = code;
  }
}

export interface EncryptOptions {
  iterations?: number;
}

export interface AppSafeKeyPair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

export type AppSafePayloadInfo =
  | { mode: "password"; version: 1; iterations: number }
  | {
      mode: "public-key";
      version: 2;
      algorithm: typeof PUBLIC_KEY_ALGORITHM;
      recipients: string[];
    };

interface RecipientStanza {
  keyId: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  wrapIv: Uint8Array;
  wrappedKey: Uint8Array;
}

function getWebCrypto(): Crypto {
  if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
    throw new AppSafeCryptoError(
      "UNSUPPORTED_RUNTIME",
      "This runtime does not provide the Web Crypto API."
    );
  }

  return globalThis.crypto;
}

function toBytes(input: ByteSource): Uint8Array {
  if (input instanceof ArrayBuffer) {
    return new Uint8Array(input.slice(0));
  }

  return new Uint8Array(input);
}

function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    return undefined;
  }

  try {
    return Uint8Array.from(
      atob(value.replaceAll("-", "+").replaceAll("_", "/")),
      (character) => character.charCodeAt(0)
    );
  } catch {
    return undefined;
  }
}

function assertPassword(password: string): void {
  if (typeof password !== "string" || password.length === 0) {
    throw new AppSafeCryptoError(
      "EMPTY_PASSWORD",
      "An encryption password is required."
    );
  }
}

function getIterations(options?: EncryptOptions): number {
  const iterations = options?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;

  if (
    !Number.isSafeInteger(iterations) ||
    iterations < MIN_ITERATIONS ||
    iterations > MAX_ITERATIONS
  ) {
    throw new AppSafeCryptoError(
      "INVALID_OPTIONS",
      `PBKDF2 iterations must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}.`
    );
  }

  return iterations;
}

function randomBytes(length: number, cryptoApi: Crypto): Uint8Array {
  const bytes = new Uint8Array(length);
  cryptoApi.getRandomValues(bytes);
  return bytes;
}

function payloadVersion(bytes: Uint8Array): number | undefined {
  return bytes.length > MAGIC.length && MAGIC.every((byte, index) => bytes[index] === byte)
    ? bytes[MAGIC.length]
    : undefined;
}

function invalidPayload(message = "The data is not a supported AppSafe payload."): AppSafeCryptoError {
  return new AppSafeCryptoError("INVALID_PAYLOAD", message);
}

function modeMismatch(expected: AppSafeEncryptionMode): AppSafeCryptoError {
  return new AppSafeCryptoError(
    "MODE_MISMATCH",
    expected === "password"
      ? "This payload is encrypted for a public key; decrypt it with a private key."
      : "This payload is password-encrypted; decrypt it with its password."
  );
}

function createHeader(
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number
): Uint8Array {
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(MAGIC, 0);
  header[5] = PASSWORD_VERSION;
  header.set(salt, 6);
  header.set(iv, 6 + SALT_LENGTH);
  new DataView(header.buffer).setUint32(HEADER_LENGTH - 4, iterations);
  return header;
}

function readHeader(encrypted: Uint8Array): {
  header: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
  iterations: number;
} {
  const version = payloadVersion(encrypted);

  if (version === PUBLIC_KEY_VERSION) {
    throw modeMismatch("password");
  }

  if (encrypted.length < HEADER_LENGTH + AUTH_TAG_LENGTH) {
    throw invalidPayload("The encrypted data is incomplete.");
  }

  if (version !== PASSWORD_VERSION) {
    throw invalidPayload();
  }

  const header = encrypted.slice(0, HEADER_LENGTH);
  const iterations = new DataView(header.buffer).getUint32(HEADER_LENGTH - 4);

  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw invalidPayload("The encrypted data has an invalid key-derivation setting.");
  }

  return {
    header,
    salt: header.slice(6, 6 + SALT_LENGTH),
    iv: header.slice(6 + SALT_LENGTH, 6 + SALT_LENGTH + IV_LENGTH),
    iterations,
  };
}

function readRecipientHeader(encrypted: Uint8Array): {
  header: Uint8Array;
  iv: Uint8Array;
  stanzas: RecipientStanza[];
} {
  const version = payloadVersion(encrypted);

  if (version === PASSWORD_VERSION) {
    throw modeMismatch("public-key");
  }

  if (version !== PUBLIC_KEY_VERSION || encrypted.length < RECIPIENT_HEADER_LENGTH) {
    throw invalidPayload();
  }

  const count = encrypted[7];
  const headerLength = RECIPIENT_HEADER_LENGTH + count * STANZA_LENGTH;

  if (encrypted[6] !== P256_ALGORITHM || count < 1 || count > MAX_RECIPIENTS) {
    throw invalidPayload("The encrypted data uses an unsupported recipient envelope.");
  }

  if (encrypted.length < headerLength + AUTH_TAG_LENGTH) {
    throw invalidPayload("The encrypted data is incomplete.");
  }

  const header = encrypted.slice(0, headerLength);
  const stanzas = Array.from({ length: count }, (_, index) => {
    let offset = RECIPIENT_HEADER_LENGTH + index * STANZA_LENGTH;
    const take = (length: number) => header.slice(offset, (offset += length));
    return {
      keyId: take(KEY_ID_LENGTH),
      ephemeralPublicKey: take(PUBLIC_KEY_LENGTH),
      wrapIv: take(IV_LENGTH),
      wrappedKey: take(WRAPPED_KEY_LENGTH),
    };
  });

  return {
    header,
    iv: header.slice(RECIPIENT_PREFIX_LENGTH, RECIPIENT_HEADER_LENGTH),
    stanzas,
  };
}

async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
  cryptoApi: Crypto
): Promise<CryptoKey> {
  const passwordKey = await cryptoApi.subtle.importKey(
    "raw",
    asBufferSource(new TextEncoder().encode(password)),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return cryptoApi.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asBufferSource(salt),
      iterations,
      hash: "SHA-256",
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function aesGcm(
  operation: "encrypt" | "decrypt",
  key: CryptoKey,
  iv: Uint8Array,
  additionalData: Uint8Array,
  data: Uint8Array,
  cryptoApi: Crypto
): Promise<Uint8Array> {
  return new Uint8Array(
    await cryptoApi.subtle[operation](
      {
        name: "AES-GCM",
        iv: asBufferSource(iv),
        additionalData: asBufferSource(additionalData),
        tagLength: 128,
      },
      key,
      asBufferSource(data)
    )
  );
}

function invalidKey(kind: "public" | "private"): AppSafeCryptoError {
  return new AppSafeCryptoError(
    "INVALID_KEY",
    `The ${kind} key is not a valid AppSafe P-256 ${kind} key.`
  );
}

function parseKeyText(
  key: string,
  prefix: string,
  length: number,
  kind: "public" | "private"
): Uint8Array {
  const value = typeof key === "string" ? key.trim() : "";
  const bytes = value.startsWith(prefix) ? fromBase64Url(value.slice(prefix.length)) : undefined;

  if (!bytes || bytes.length !== length || bytes[0] !== 0x04) {
    throw invalidKey(kind);
  }

  return bytes;
}

function parsePublicKey(key: string): Uint8Array {
  return parseKeyText(key, PUBLIC_KEY_PREFIX, PUBLIC_KEY_LENGTH, "public");
}

function parsePrivateKey(key: string): { publicKey: Uint8Array; scalar: Uint8Array } {
  const bytes = parseKeyText(
    key,
    PRIVATE_KEY_PREFIX,
    PUBLIC_KEY_LENGTH + PRIVATE_SCALAR_LENGTH,
    "private"
  );
  return {
    publicKey: bytes.slice(0, PUBLIC_KEY_LENGTH),
    scalar: bytes.slice(PUBLIC_KEY_LENGTH),
  };
}

function formatPublicKey(publicKey: Uint8Array): string {
  return `${PUBLIC_KEY_PREFIX}${toBase64Url(publicKey)}`;
}

async function importPublicKey(publicKey: Uint8Array, cryptoApi: Crypto): Promise<CryptoKey> {
  return cryptoApi.subtle.importKey("raw", asBufferSource(publicKey), EC_PARAMS, false, []);
}

async function importPrivateKey(
  publicKey: Uint8Array,
  scalar: Uint8Array,
  cryptoApi: Crypto
): Promise<CryptoKey> {
  try {
    return await cryptoApi.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x: toBase64Url(publicKey.slice(1, 33)),
        y: toBase64Url(publicKey.slice(33)),
        d: toBase64Url(scalar),
        ext: false,
      },
      EC_PARAMS,
      false,
      ["deriveBits"]
    );
  } catch {
    throw invalidKey("private");
  }
}

async function keyIdFor(publicKey: Uint8Array, cryptoApi: Crypto): Promise<Uint8Array> {
  const digest = await cryptoApi.subtle.digest("SHA-256", asBufferSource(publicKey));
  return new Uint8Array(digest).slice(0, KEY_ID_LENGTH);
}

async function deriveWrapKey(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  ephemeralPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  cryptoApi: Crypto
): Promise<CryptoKey> {
  const secret = await cryptoApi.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256
  );
  const hkdfKey = await cryptoApi.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);

  return cryptoApi.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asBufferSource(concatBytes(ephemeralPublicKey, recipientPublicKey)),
      info: asBufferSource(new TextEncoder().encode(KEY_WRAP_INFO)),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function stanzaAdditionalData(
  header: Uint8Array,
  keyId: Uint8Array,
  ephemeralPublicKey: Uint8Array
): Uint8Array {
  return concatBytes(header.slice(0, RECIPIENT_PREFIX_LENGTH), keyId, ephemeralPublicKey);
}

async function importContentKey(contentKey: Uint8Array, cryptoApi: Crypto): Promise<CryptoKey> {
  return cryptoApi.subtle.importKey(
    "raw",
    asBufferSource(contentKey),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

function decodeText(plaintext: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    throw new AppSafeCryptoError(
      "INVALID_TEXT",
      "The decrypted data is not valid UTF-8 text."
    );
  }
}

export function isAppSafePayload(input: ByteSource): boolean {
  try {
    inspectAppSafePayload(input);
    return true;
  } catch {
    return false;
  }
}

export function inspectAppSafePayload(input: ByteSource): AppSafePayloadInfo {
  const bytes = toBytes(input);

  if (payloadVersion(bytes) === PUBLIC_KEY_VERSION) {
    return {
      mode: "public-key",
      version: 2,
      algorithm: PUBLIC_KEY_ALGORITHM,
      recipients: readRecipientHeader(bytes).stanzas.map((stanza) => toHex(stanza.keyId)),
    };
  }

  return { mode: "password", version: 1, iterations: readHeader(bytes).iterations };
}

export async function encryptBytes(
  input: ByteSource,
  password: string,
  options?: EncryptOptions
): Promise<Uint8Array> {
  assertPassword(password);
  const iterations = getIterations(options);
  const cryptoApi = getWebCrypto();
  const plaintext = toBytes(input);
  const salt = randomBytes(SALT_LENGTH, cryptoApi);
  const iv = randomBytes(IV_LENGTH, cryptoApi);
  const header = createHeader(salt, iv, iterations);
  const key = await deriveKey(password, salt, iterations, cryptoApi);
  return concatBytes(header, await aesGcm("encrypt", key, iv, header, plaintext, cryptoApi));
}

export async function decryptBytes(
  input: ByteSource,
  password: string
): Promise<Uint8Array> {
  assertPassword(password);
  const cryptoApi = getWebCrypto();
  const encrypted = toBytes(input);
  const { header, salt, iv, iterations } = readHeader(encrypted);
  const key = await deriveKey(password, salt, iterations, cryptoApi);

  try {
    return await aesGcm("decrypt", key, iv, header, encrypted.slice(HEADER_LENGTH), cryptoApi);
  } catch {
    throw new AppSafeCryptoError(
      "INVALID_PASSWORD_OR_DATA",
      "The password or encrypted data is invalid."
    );
  }
}

export async function encryptText(
  input: string,
  password: string,
  options?: EncryptOptions
): Promise<Uint8Array> {
  return encryptBytes(new TextEncoder().encode(input), password, options);
}

export async function decryptText(
  input: ByteSource,
  password: string
): Promise<string> {
  return decodeText(await decryptBytes(input, password));
}

export async function generateKeyPair(): Promise<AppSafeKeyPair> {
  const cryptoApi = getWebCrypto();
  const pair = await cryptoApi.subtle.generateKey(EC_PARAMS, true, ["deriveBits"]);
  const publicKey = new Uint8Array(await cryptoApi.subtle.exportKey("raw", pair.publicKey));
  const { d } = await cryptoApi.subtle.exportKey("jwk", pair.privateKey);
  const scalar = d ? fromBase64Url(d) : undefined;

  if (!scalar || scalar.length !== PRIVATE_SCALAR_LENGTH) {
    throw new AppSafeCryptoError(
      "UNSUPPORTED_RUNTIME",
      "This runtime could not export a P-256 private key."
    );
  }

  return {
    publicKey: formatPublicKey(publicKey),
    privateKey: `${PRIVATE_KEY_PREFIX}${toBase64Url(concatBytes(publicKey, scalar))}`,
    fingerprint: toHex(await keyIdFor(publicKey, cryptoApi)),
  };
}

export function getPublicKey(privateKey: string): string {
  return formatPublicKey(parsePrivateKey(privateKey).publicKey);
}

export async function getKeyFingerprint(publicKey: string): Promise<string> {
  return toHex(await keyIdFor(parsePublicKey(publicKey), getWebCrypto()));
}

export async function encryptBytesForRecipients(
  input: ByteSource,
  recipients: string | readonly string[]
): Promise<Uint8Array> {
  const cryptoApi = getWebCrypto();
  const plaintext = toBytes(input);
  const unique = new Map<string, { publicKey: Uint8Array; keyId: Uint8Array }>();

  for (const recipient of typeof recipients === "string" ? [recipients] : recipients) {
    const publicKey = parsePublicKey(recipient);
    const keyId = await keyIdFor(publicKey, cryptoApi);
    unique.set(toHex(keyId), { publicKey, keyId });
  }

  if (unique.size < 1 || unique.size > MAX_RECIPIENTS) {
    throw new AppSafeCryptoError(
      "INVALID_OPTIONS",
      `Between 1 and ${MAX_RECIPIENTS} recipient public keys are required.`
    );
  }

  const contentKey = randomBytes(CONTENT_KEY_LENGTH, cryptoApi);
  const iv = randomBytes(IV_LENGTH, cryptoApi);
  const header = new Uint8Array(RECIPIENT_HEADER_LENGTH + unique.size * STANZA_LENGTH);
  header.set(MAGIC, 0);
  header.set([PUBLIC_KEY_VERSION, P256_ALGORITHM, unique.size], MAGIC.length);
  header.set(iv, RECIPIENT_PREFIX_LENGTH);

  let offset = RECIPIENT_HEADER_LENGTH;
  for (const { publicKey, keyId } of unique.values()) {
    let recipientKey: CryptoKey;
    try {
      recipientKey = await importPublicKey(publicKey, cryptoApi);
    } catch {
      throw invalidKey("public");
    }

    const ephemeral = await cryptoApi.subtle.generateKey(EC_PARAMS, false, ["deriveBits"]);
    const ephemeralPublicKey = new Uint8Array(
      await cryptoApi.subtle.exportKey("raw", ephemeral.publicKey)
    );
    const wrapKey = await deriveWrapKey(
      ephemeral.privateKey,
      recipientKey,
      ephemeralPublicKey,
      publicKey,
      cryptoApi
    );
    const wrapIv = randomBytes(IV_LENGTH, cryptoApi);
    const wrappedKey = await aesGcm(
      "encrypt",
      wrapKey,
      wrapIv,
      stanzaAdditionalData(header, keyId, ephemeralPublicKey),
      contentKey,
      cryptoApi
    );

    for (const part of [keyId, ephemeralPublicKey, wrapIv, wrappedKey]) {
      header.set(part, offset);
      offset += part.length;
    }
  }

  const key = await importContentKey(contentKey, cryptoApi);
  return concatBytes(header, await aesGcm("encrypt", key, iv, header, plaintext, cryptoApi));
}

export async function decryptBytesWithPrivateKey(
  input: ByteSource,
  privateKey: string
): Promise<Uint8Array> {
  const cryptoApi = getWebCrypto();
  const { publicKey, scalar } = parsePrivateKey(privateKey);
  const encrypted = toBytes(input);
  const { header, iv, stanzas } = readRecipientHeader(encrypted);
  const keyId = await keyIdFor(publicKey, cryptoApi);
  const stanza = stanzas.find((candidate) => sameBytes(candidate.keyId, keyId));

  if (!stanza) {
    throw new AppSafeCryptoError(
      "NO_MATCHING_KEY",
      "The private key is not a recipient of this payload."
    );
  }

  const ownKey = await importPrivateKey(publicKey, scalar, cryptoApi);

  try {
    const wrapKey = await deriveWrapKey(
      ownKey,
      await importPublicKey(stanza.ephemeralPublicKey, cryptoApi),
      stanza.ephemeralPublicKey,
      publicKey,
      cryptoApi
    );
    const contentKey = await aesGcm(
      "decrypt",
      wrapKey,
      stanza.wrapIv,
      stanzaAdditionalData(header, stanza.keyId, stanza.ephemeralPublicKey),
      stanza.wrappedKey,
      cryptoApi
    );
    const key = await importContentKey(contentKey, cryptoApi);
    return await aesGcm("decrypt", key, iv, header, encrypted.slice(header.length), cryptoApi);
  } catch {
    throw new AppSafeCryptoError(
      "INVALID_KEY_OR_DATA",
      "The private key or encrypted data is invalid."
    );
  }
}

export async function encryptTextForRecipients(
  input: string,
  recipients: string | readonly string[]
): Promise<Uint8Array> {
  return encryptBytesForRecipients(new TextEncoder().encode(input), recipients);
}

export async function decryptTextWithPrivateKey(
  input: ByteSource,
  privateKey: string
): Promise<string> {
  return decodeText(await decryptBytesWithPrivateKey(input, privateKey));
}
