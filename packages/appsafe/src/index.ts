const MAGIC = new Uint8Array([0x41, 0x53, 0x41, 0x46, 0x45]);
const VERSION = 1;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const HEADER_LENGTH = MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH + 4;
const AUTH_TAG_LENGTH = 16;
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 2_000_000;

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;

export type ByteSource = ArrayBuffer | Uint8Array;

export type AppSafeCryptoErrorCode =
  | "EMPTY_PASSWORD"
  | "INVALID_OPTIONS"
  | "INVALID_PAYLOAD"
  | "INVALID_PASSWORD_OR_DATA"
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

function createHeader(
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number
): Uint8Array {
  const header = new Uint8Array(HEADER_LENGTH);
  header.set(MAGIC, 0);
  header[5] = VERSION;
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
  if (encrypted.length < HEADER_LENGTH + AUTH_TAG_LENGTH) {
    throw new AppSafeCryptoError(
      "INVALID_PAYLOAD",
      "The encrypted data is incomplete."
    );
  }

  const header = encrypted.slice(0, HEADER_LENGTH);
  const hasMagic = MAGIC.every((byte, index) => header[index] === byte);

  if (!hasMagic || header[5] !== VERSION) {
    throw new AppSafeCryptoError(
      "INVALID_PAYLOAD",
      "The data is not a supported AppSafe payload."
    );
  }

  const iterations = new DataView(header.buffer).getUint32(HEADER_LENGTH - 4);

  if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw new AppSafeCryptoError(
      "INVALID_PAYLOAD",
      "The encrypted data has an invalid key-derivation setting."
    );
  }

  return {
    header,
    salt: header.slice(6, 6 + SALT_LENGTH),
    iv: header.slice(6 + SALT_LENGTH, 6 + SALT_LENGTH + IV_LENGTH),
    iterations,
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

export function isAppSafePayload(input: ByteSource): boolean {
  const bytes = toBytes(input);
  return (
    bytes.length >= HEADER_LENGTH + AUTH_TAG_LENGTH &&
    MAGIC.every((byte, index) => bytes[index] === byte) &&
    bytes[5] === VERSION
  );
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
  const ciphertext = new Uint8Array(
    await cryptoApi.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: asBufferSource(iv),
        additionalData: asBufferSource(header),
        tagLength: 128,
      },
      key,
      asBufferSource(plaintext)
    )
  );
  const payload = new Uint8Array(header.length + ciphertext.length);
  payload.set(header, 0);
  payload.set(ciphertext, header.length);
  return payload;
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
    return new Uint8Array(
      await cryptoApi.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: asBufferSource(iv),
          additionalData: asBufferSource(header),
          tagLength: 128,
        },
        key,
        asBufferSource(encrypted.slice(HEADER_LENGTH))
      )
    );
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
  const plaintext = await decryptBytes(input, password);

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    throw new AppSafeCryptoError(
      "INVALID_TEXT",
      "The decrypted data is not valid UTF-8 text."
    );
  }
}
