import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AppSafeCryptoError,
  decryptBytes,
  decryptText,
  encryptBytes,
  encryptText,
  isAppSafePayload,
} from "../src/index.js";

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

  await assert.rejects(() => decryptText(encrypted, "wrong-password"), (error) => {
    return (
      error instanceof AppSafeCryptoError &&
      error.code === "INVALID_PASSWORD_OR_DATA"
    );
  });

  const tampered = new Uint8Array(encrypted);
  tampered[tampered.length - 1] ^= 1;

  await assert.rejects(() => decryptBytes(tampered, "secret-password"), (error) => {
    return (
      error instanceof AppSafeCryptoError &&
      error.code === "INVALID_PASSWORD_OR_DATA"
    );
  });
});
