"use client";

import { useCallback, useState } from "react";
import {
  AppSafeCryptoError,
  type AppSafeCryptoErrorCode,
  decryptText,
  decryptTextWithPrivateKey,
  encryptText,
  encryptTextForRecipients,
  generateKeyPair,
} from "@asafarim/appsafe";

type LabCheck = {
  label: string;
  mode: "password" | "public-key" | "both";
  expected: AppSafeCryptoErrorCode;
};

type LabOutcome = {
  actual: string;
  passed: boolean;
};

const LAB_CHECKS: LabCheck[] = [
  { label: "Wrong password", mode: "password", expected: "INVALID_PASSWORD_OR_DATA" },
  { label: "Tampered password payload", mode: "password", expected: "INVALID_PASSWORD_OR_DATA" },
  { label: "Wrong private key", mode: "public-key", expected: "NO_MATCHING_KEY" },
  { label: "Tampered public-key payload", mode: "public-key", expected: "INVALID_KEY_OR_DATA" },
  { label: "Truncated payload", mode: "both", expected: "INVALID_PAYLOAD" },
  { label: "Password used on a public-key payload", mode: "both", expected: "MODE_MISMATCH" },
  { label: "Malformed public key", mode: "public-key", expected: "INVALID_KEY" },
];

function flipLastByte(bytes: Uint8Array): Uint8Array {
  const copy = bytes.slice();
  copy[copy.length - 1] ^= 1;
  return copy;
}

export function FailureLab() {
  const [outcomes, setOutcomes] = useState<LabOutcome[] | null>(null);
  const [running, setRunning] = useState(false);

  const runChecks = useCallback(async () => {
    setRunning(true);

    try {
      const owner = await generateKeyPair();
      const stranger = await generateKeyPair();
      const passwordPayload = await encryptText("failure lab", "correct-password", {
        iterations: 100_000,
      });
      const keyPayload = await encryptTextForRecipients("failure lab", owner.publicKey);
      const attempts: Array<() => Promise<unknown>> = [
        () => decryptText(passwordPayload, "wrong-password"),
        () => decryptText(flipLastByte(passwordPayload), "correct-password"),
        () => decryptTextWithPrivateKey(keyPayload, stranger.privateKey),
        () => decryptTextWithPrivateKey(flipLastByte(keyPayload), owner.privateKey),
        () => decryptTextWithPrivateKey(keyPayload.slice(0, 64), owner.privateKey),
        () => decryptText(keyPayload, "correct-password"),
        () => encryptTextForRecipients("failure lab", "appsafe-pub-p256:not-a-real-key"),
      ];
      const next: LabOutcome[] = [];

      for (const [index, attempt] of attempts.entries()) {
        try {
          await attempt();
          next.push({ actual: "succeeded unexpectedly", passed: false });
        } catch (error) {
          const actual = error instanceof AppSafeCryptoError ? error.code : "unexpected error";
          next.push({ actual, passed: actual === LAB_CHECKS[index].expected });
        }
      }

      setOutcomes(next);
    } finally {
      setRunning(false);
    }
  }, []);

  return (
    <div className="demo-card">
      <div className="demo-lab-heading">
        <p>
          Each check creates fresh, throwaway keys and payloads in this tab, then
          tries to break them. Every failure must be a typed{" "}
          <code>AppSafeCryptoError</code> — never partial plaintext.
        </p>
        <button
          className="demo-button demo-button-primary"
          type="button"
          onClick={() => void runChecks()}
          disabled={running}
        >
          {running ? "Running…" : outcomes ? "Run again" : "Run failure checks"}
        </button>
      </div>
      <ul className="demo-lab-list">
        {LAB_CHECKS.map((check, index) => {
          const outcome = outcomes?.[index];
          return (
            <li className="demo-lab-row" key={check.label}>
              <span className="demo-lab-label">
                <strong>{check.label}</strong>
                <small>{check.mode === "both" ? "either mode" : `${check.mode} mode`}</small>
              </span>
              <code>{check.expected}</code>
              <span
                className={`demo-lab-status ${
                  outcome ? (outcome.passed ? "demo-lab-status-pass" : "demo-lab-status-fail") : ""
                }`}
              >
                {outcome ? (outcome.passed ? "failed closed" : outcome.actual) : "not run"}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
