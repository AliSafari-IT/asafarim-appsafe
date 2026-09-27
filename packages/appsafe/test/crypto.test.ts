import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AppSafeCryptoError,
  type AppSafeCryptoErrorCode,
  decryptBytes,
  decryptBytesWithPrivateKey,
  decryptText,
  decryptTextWithPrivateKey,
  encryptBytes,
  encryptBytesForRecipients,
  encryptText,
  encryptTextForRecipients,
  generateKeyPair,
  getKeyFingerprint,
  getPublicKey,
  inspectAppSafePayload,
  isAppSafePayload,
} from "../src/index.js";

const LEGACY_PASSWORD_PAYLOAD =
  "QVNBRkUBooCWI+VTD+VxDEZnTLYVbQRd0ZyHMtegGxaM8QABhqDWCluvXbz+k4qppW2u2HA2MKNUto1r/7hLQ4yptzQ+iwkp";

function hasCode(code: AppSafeCryptoErrorCode) {
  return (error: unknown) => error instanceof AppSafeCryptoError && error.code === code;
}

test("round trips text and arbitrary bytes", async () => {
  const text = "AppSafe keeps this text in the browser.";
  const encryptedText = await encryptText(text, "correct horse battery staple");

  assert.equal(isAppSafePayload(encryptedText), true);
  assert.equal(
    await decryptText(encryptedText, "correct horse battery staple"),
    text
  );

  const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
  const encryptedBytes = await encryptBytes(bytes, "binary-password");
  assert.deepEqual(
    Array.from(await decryptBytes(encryptedBytes, "binary-password")),
    Array.from(bytes)
  );
});

test("rejects a wrong password and tampered payload", async () => {
  const encrypted = await encryptText("authenticated", "secret-password");

  await assert.rejects(
    () => decryptText(encrypted, "wrong-password"),
    hasCode("INVALID_PASSWORD_OR_DATA")
  );

  const tampered = new Uint8Array(encrypted);
  tampered[tampered.length - 1] ^= 1;

  await assert.rejects(
    () => decryptBytes(tampered, "secret-password"),
    hasCode("INVALID_PASSWORD_OR_DATA")
  );
});

test("decrypts a legacy version-1 password payload", async () => {
  const payload = Uint8Array.from(atob(LEGACY_PASSWORD_PAYLOAD), (character) =>
    character.charCodeAt(0)
  );

  assert.deepEqual(inspectAppSafePayload(payload), {
    mode: "password",
    version: 1,
    iterations: 100_000,
  });
  assert.equal(await decryptText(payload, "legacy-password"), "AppSafe v1 fixture");
});

test("generates key pairs and derives public keys and fingerprints", async () => {
  const pair = await generateKeyPair();

  assert.match(pair.publicKey, /^appsafe-pub-p256:[A-Za-z0-9_-]+$/);
  assert.match(pair.privateKey, /^APPSAFE-PRIVATE-KEY-P256:[A-Za-z0-9_-]+$/);
  assert.match(pair.fingerprint, /^[0-9a-f]{32}$/);
  assert.equal(getPublicKey(`${pair.privateKey}\n`), pair.publicKey);
  assert.equal(await getKeyFingerprint(pair.publicKey), pair.fingerprint);
  await assert.rejects(() => getKeyFingerprint(pair.privateKey), hasCode("INVALID_KEY"));
  assert.throws(() => getPublicKey(pair.publicKey), hasCode("INVALID_KEY"));
  assert.notEqual((await generateKeyPair()).fingerprint, pair.fingerprint);
});

test("round trips text and bytes for public-key recipients", async () => {
  const pair = await generateKeyPair();
  const encryptedText = await encryptTextForRecipients("for the key holder", pair.publicKey);

  assert.equal(isAppSafePayload(encryptedText), true);
  assert.deepEqual(inspectAppSafePayload(encryptedText), {
    mode: "public-key",
    version: 2,
    algorithm: "ECDH-P256+HKDF-SHA256+A256GCM",
    recipients: [pair.fingerprint],
  });
  assert.equal(
    await decryptTextWithPrivateKey(encryptedText, pair.privateKey),
    "for the key holder"
  );

  const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
  const encryptedBytes = await encryptBytesForRecipients(bytes.buffer, [pair.publicKey]);
  assert.deepEqual(
    Array.from(await decryptBytesWithPrivateKey(encryptedBytes, pair.privateKey)),
    Array.from(bytes)
  );
});

test("encrypts for multiple recipients and de-duplicates keys", async () => {
  const first = await generateKeyPair();
  const second = await generateKeyPair();
  const encrypted = await encryptTextForRecipients("team secret", [
    first.publicKey,
    second.publicKey,
    first.publicKey,
  ]);
  const info = inspectAppSafePayload(encrypted);

  assert.equal(info.mode, "public-key");
  assert.deepEqual(
    info.mode === "public-key" ? info.recipients : [],
    [first.fingerprint, second.fingerprint]
  );
  assert.equal(await decryptTextWithPrivateKey(encrypted, first.privateKey), "team secret");
  assert.equal(await decryptTextWithPrivateKey(encrypted, second.privateKey), "team secret");
});

test("rejects wrong private keys and tampered public-key payloads", async () => {
  const pair = await generateKeyPair();
  const other = await generateKeyPair();
  const encrypted = await encryptTextForRecipients("authenticated", pair.publicKey);

  await assert.rejects(
    () => decryptTextWithPrivateKey(encrypted, other.privateKey),
    hasCode("NO_MATCHING_KEY")
  );

  for (const index of [7 + 1, 20 + 16 + 1, 20 + 16 + 65 + 12 + 1, encrypted.length - 1]) {
    const tampered = new Uint8Array(encrypted);
    tampered[index] ^= 1;
    await assert.rejects(
      () => decryptBytesWithPrivateKey(tampered, pair.privateKey),
      hasCode("INVALID_KEY_OR_DATA")
    );
  }

  const wrongKeyId = new Uint8Array(encrypted);
  wrongKeyId[20] ^= 1;
  await assert.rejects(
    () => decryptBytesWithPrivateKey(wrongKeyId, pair.privateKey),
    hasCode("NO_MATCHING_KEY")
  );

  const unsupportedAlgorithm = new Uint8Array(encrypted);
  unsupportedAlgorithm[6] = 9;
  await assert.rejects(
    () => decryptBytesWithPrivateKey(unsupportedAlgorithm, pair.privateKey),
    hasCode("INVALID_PAYLOAD")
  );

  await assert.rejects(
    () => decryptBytesWithPrivateKey(encrypted.slice(0, 170), pair.privateKey),
    hasCode("INVALID_PAYLOAD")
  );
  assert.equal(isAppSafePayload(encrypted.slice(0, 170)), false);
  await assert.rejects(
    () => decryptBytesWithPrivateKey(encrypted.slice(0, -1), pair.privateKey),
    hasCode("INVALID_KEY_OR_DATA")
  );
});

test("identifies each mode and refuses cross-mode decryption", async () => {
  const pair = await generateKeyPair();
  const passwordPayload = await encryptText("password mode", "password");
  const publicKeyPayload = await encryptTextForRecipients("public-key mode", pair.publicKey);

  await assert.rejects(
    () => decryptText(publicKeyPayload, "password"),
    hasCode("MODE_MISMATCH")
  );
  await assert.rejects(
    () => decryptTextWithPrivateKey(passwordPayload, pair.privateKey),
    hasCode("MODE_MISMATCH")
  );
  assert.equal(inspectAppSafePayload(passwordPayload).mode, "password");
  assert.equal(inspectAppSafePayload(publicKeyPayload).mode, "public-key");
});

test("rejects malformed keys without echoing key material", async () => {
  const pair = await generateKeyPair();
  const invalidPublicKey = `${pair.publicKey.slice(0, -4)}AAAA`;

  for (const [operation, secret] of [
    [() => encryptTextForRecipients("x", "not-a-key"), "not-a-key"],
    [() => encryptTextForRecipients("x", invalidPublicKey), invalidPublicKey],
    [() => encryptTextForRecipients("x", pair.privateKey), pair.privateKey],
    [() => decryptTextWithPrivateKey(new Uint8Array(), pair.publicKey), pair.publicKey],
  ] as const) {
    await assert.rejects(operation, (error) => {
      return (
        hasCode("INVALID_KEY")(error) &&
        !(error as Error).message.includes(secret.slice(-16))
      );
    });
  }

  await assert.rejects(() => encryptTextForRecipients("x", []), hasCode("INVALID_OPTIONS"));
});
