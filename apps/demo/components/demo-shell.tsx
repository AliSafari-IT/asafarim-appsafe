"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
} from "react";
import {
  AppSafeCryptoError,
  DEFAULT_PBKDF2_ITERATIONS,
  type AppSafeEncryptionMode,
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
  inspectAppSafePayload,
  isAppSafePayload,
} from "@asafarim/appsafe";
import { FailureLab } from "./failure-lab";
import { MethodComparison, MethodGuide } from "./method-guide";

type DemoMode = "text" | "file";
type BusyState = "encrypting" | "decrypting" | "generating" | null;
type Notice = {
  kind: "success" | "error" | "info";
  text: string;
};
type Artifact = {
  bytes: Uint8Array;
  name: string;
};
type DemoShellProps = {
  version: string;
};
type Recipe = {
  title: string;
  code: string;
};

const APP_SAFE_EXTENSION = ".appsafe";
const RECIPES: Recipe[] = [
  {
    title: "Password / text round-trip",
    code: `import { decryptText, encryptText } from "@asafarim/appsafe";

const encrypted = await encryptText("private note", password);
const plaintext = await decryptText(encrypted, password);`,
  },
  {
    title: "Password / file round-trip",
    code: `import { decryptBytes, encryptBytes } from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
const encrypted = await encryptBytes(input, password);
const plaintext = await decryptBytes(encrypted, password);`,
  },
  {
    title: "Public key / generate a key pair",
    code: `import { generateKeyPair } from "@asafarim/appsafe";

const { publicKey, privateKey, fingerprint } = await generateKeyPair();
// publicKey  -> safe to commit or share (for example .appsafe/key.pub)
// privateKey -> secret: store it privately, never commit or log it`,
  },
  {
    title: "Public key / file round-trip",
    code: `import {
  decryptBytesWithPrivateKey,
  encryptBytesForRecipients,
} from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
// Anyone with the public key can encrypt...
const encrypted = await encryptBytesForRecipients(input, publicKey);
// ...only the private-key holder can decrypt.
const plaintext = await decryptBytesWithPrivateKey(encrypted, privateKey);`,
  },
  {
    title: "Public key / multiple recipients",
    code: `import { encryptTextForRecipients } from "@asafarim/appsafe";

const encrypted = await encryptTextForRecipients(note, [
  ownerPublicKey,
  deployPublicKey,
]);
// Each recipient decrypts with its own private key.`,
  },
  {
    title: "Detect the mode, then decrypt",
    code: `import {
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
    console.warn(error.code); // e.g. NO_MATCHING_KEY, never the key itself
  }
}`,
  },
];
const CLI_RECIPE = `# Public-key mode for a private app folder (CLI)
appsafe init --mode public-key   # config: .appsafe/key.pub + .appsafe/key.txt
appsafe keygen                   # private key is added to .gitignore
appsafe encrypt                  # needs only the public key
appsafe decrypt                  # needs the private key
appsafe rekey                    # migrate password artifacts to the configured mode`;

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function hexPreview(bytes: Uint8Array): string {
  return Array.from(bytes.slice(0, 16), (byte) => byte.toString(16).padStart(2, "0")).join(" ");
}

function describePayload(bytes: Uint8Array): string {
  try {
    const info = inspectAppSafePayload(bytes);
    return info.mode === "password"
      ? `AppSafe v1 / password / ${info.iterations.toLocaleString("en-US")} rounds`
      : `AppSafe v2 / public key / ${info.recipients.length} recipient${info.recipients.length === 1 ? "" : "s"}`;
  } catch {
    return "Not a valid AppSafe payload";
  }
}

function downloadBytes(data: Uint8Array, fileName: string, type: string): void {
  const blob = new Blob([data.slice().buffer as ArrayBuffer], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function outputName(fileName: string): string {
  if (fileName.toLowerCase().endsWith(APP_SAFE_EXTENSION)) {
    return fileName.slice(0, -APP_SAFE_EXTENSION.length) || "decrypted.bin";
  }

  return `decrypted-${fileName}`;
}

const ERROR_MESSAGES: Partial<Record<AppSafeCryptoError["code"], string>> = {
  INVALID_PASSWORD_OR_DATA: "The password or encrypted payload is invalid.",
  INVALID_KEY_OR_DATA: "The private key or encrypted payload is invalid.",
  NO_MATCHING_KEY: "This private key is not a recipient of the payload.",
  MODE_MISMATCH: "The payload uses the other encryption method. Switch methods to decrypt it.",
  INVALID_KEY: "The key is not a valid AppSafe key of the expected kind.",
  INVALID_PAYLOAD: "This is not a supported AppSafe payload.",
  INVALID_TEXT: "The decrypted bytes are not valid UTF-8 text.",
};

function operationError(error: unknown): string {
  const message = error instanceof AppSafeCryptoError ? ERROR_MESSAGES[error.code] : undefined;
  return message
    ? `${message} (${(error as AppSafeCryptoError).code})`
    : "The operation could not be completed in this browser.";
}

function AppMark() {
  return (
    <svg viewBox="0 0 48 48" aria-hidden="true" className="demo-mark-icon">
      <path d="M24 5 39 10.5V21c0 10.2-6.2 18.1-15 22C14.2 39.1 9 31.2 9 21V10.5z" />
      <path d="m15.5 23.8 5.3 5.3 11.7-12.2" />
    </svg>
  );
}

function NpmIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="demo-social-icon">
      <path d="M3 6h18v12h-6V9h-3v9H3z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="demo-social-icon demo-social-icon-filled">
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2.17c-3.2.7-3.87-1.36-3.87-1.36-.53-1.34-1.3-1.7-1.3-1.7-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.67 1.24 3.32.95.1-.74.4-1.24.72-1.53-2.55-.29-5.23-1.27-5.23-5.67 0-1.25.45-2.27 1.18-3.07-.12-.29-.51-1.45.11-3.03 0 0 .96-.31 3.16 1.17a10.98 10.98 0 0 1 5.76 0c2.2-1.48 3.16-1.17 3.16-1.17.62 1.58.23 2.74.11 3.03.73.8 1.18 1.82 1.18 3.07 0 4.41-2.69 5.38-5.25 5.66.41.36.77 1.07.77 2.16v3.2c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="demo-inline-icon">
      <path d="M5 12h13M13 6l6 6-6 6" />
    </svg>
  );
}

export function DemoShell({ version }: DemoShellProps) {
  const [method, setMethod] = useState<AppSafeEncryptionMode>("password");
  const [mode, setMode] = useState<DemoMode>("text");
  const [password, setPassword] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [textValue, setTextValue] = useState("This note never leaves the browser.");
  const [textPayload, setTextPayload] = useState<Uint8Array | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePayload, setFilePayload] = useState<Artifact | null>(null);
  const [decryptedFile, setDecryptedFile] = useState<Artifact | null>(null);
  const [busy, setBusy] = useState<BusyState>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const encryptedFileInputRef = useRef<HTMLInputElement>(null);
  const usesPassword = method === "password";
  const canEncrypt = usesPassword ? password.length > 0 : publicKey.trim().length > 0;
  const canDecrypt = usesPassword ? password.length > 0 : privateKey.trim().length > 0;
  const encryptLabel = usesPassword ? "encrypt" : "encrypt…ForRecipients";
  const decryptLabel = usesPassword ? "decrypt" : "decrypt…WithPrivateKey";

  useEffect(() => {
    let current = true;
    if (!publicKey.trim()) {
      setFingerprint(null);
      return;
    }
    getKeyFingerprint(publicKey)
      .then((value) => current && setFingerprint(value))
      .catch(() => current && setFingerprint("invalid public key"));
    return () => {
      current = false;
    };
  }, [publicKey]);

  const run = useCallback(async (state: Exclude<BusyState, null>, operation: () => Promise<void>) => {
    setBusy(state);
    setNotice(null);
    try {
      await operation();
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, []);

  const generateDemoKeys = useCallback(
    () =>
      run("generating", async () => {
        const pair = await generateKeyPair();
        setPublicKey(pair.publicKey);
        setPrivateKey(pair.privateKey);
        setShowPrivateKey(false);
        setNotice({
          kind: "success",
          text: `Generated an ephemeral P-256 key pair (${pair.fingerprint}). It exists only in this tab's memory.`,
        });
      }),
    [run]
  );

  const encryptDemoText = useCallback(
    () =>
      run("encrypting", async () => {
        const payload = usesPassword
          ? await encryptText(textValue, password)
          : await encryptTextForRecipients(textValue, publicKey);
        setTextPayload(payload);
        downloadBytes(payload, `message.txt${APP_SAFE_EXTENSION}`, "application/octet-stream");
        setNotice({
          kind: "success",
          text: `Encrypted ${formatBytes(payload.byteLength)} locally with ${usesPassword ? "encryptText()" : "encryptTextForRecipients()"} and downloaded the payload.`,
        });
      }),
    [password, publicKey, run, textValue, usesPassword]
  );

  const decryptDemoText = useCallback(
    () =>
      run("decrypting", async () => {
        if (!textPayload) {
          return;
        }
        setTextValue(
          usesPassword
            ? await decryptText(textPayload, password)
            : await decryptTextWithPrivateKey(textPayload, privateKey)
        );
        setNotice({
          kind: "success",
          text: `Decrypted locally with ${usesPassword ? "decryptText()" : "decryptTextWithPrivateKey()"}.`,
        });
      }),
    [password, privateKey, run, textPayload, usesPassword]
  );

  const readPayloadFile = useCallback(async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";

    if (!file) {
      return null;
    }

    const bytes = new Uint8Array(await file.arrayBuffer());

    if (!isAppSafePayload(bytes)) {
      setNotice({ kind: "error", text: "Choose a valid .appsafe payload." });
      return null;
    }

    setNotice({ kind: "info", text: `${file.name}: ${describePayload(bytes)}.` });
    return { bytes, name: file.name };
  }, []);

  const handleEncryptedTextFile = useCallback(
    async (event: ChangeEvent<HTMLInputElement>) => {
      const artifact = await readPayloadFile(event);
      if (artifact) {
        setTextPayload(artifact.bytes);
      }
    },
    [readPayloadFile]
  );

  const handleSourceFile = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(event.target.files?.[0] ?? null);
    setFilePayload(null);
    setDecryptedFile(null);
    event.target.value = "";
    setNotice(null);
  }, []);

  const handleEncryptedFile = useCallback(
    async (event: ChangeEvent<HTMLInputElement>) => {
      const artifact = await readPayloadFile(event);
      if (artifact) {
        setFilePayload(artifact);
        setDecryptedFile(null);
      }
    },
    [readPayloadFile]
  );

  const encryptDemoFile = useCallback(
    () =>
      run("encrypting", async () => {
        if (!selectedFile) {
          return;
        }
        const input = new Uint8Array(await selectedFile.arrayBuffer());
        const payload = usesPassword
          ? await encryptBytes(input, password)
          : await encryptBytesForRecipients(input, publicKey);
        const artifact = {
          bytes: payload,
          name: `${selectedFile.name}${APP_SAFE_EXTENSION}`,
        };
        setFilePayload(artifact);
        setDecryptedFile(null);
        downloadBytes(payload, artifact.name, "application/octet-stream");
        setNotice({
          kind: "success",
          text: `Encrypted ${selectedFile.name} locally and downloaded the payload.`,
        });
      }),
    [password, publicKey, run, selectedFile, usesPassword]
  );

  const decryptDemoFile = useCallback(
    () =>
      run("decrypting", async () => {
        if (!filePayload) {
          return;
        }
        const bytes = usesPassword
          ? await decryptBytes(filePayload.bytes, password)
          : await decryptBytesWithPrivateKey(filePayload.bytes, privateKey);
        const artifact = { bytes, name: outputName(filePayload.name) };
        setDecryptedFile(artifact);
        downloadBytes(bytes, artifact.name, "application/octet-stream");
        setNotice({
          kind: "success",
          text: `Decrypted ${filePayload.name} locally and downloaded the result.`,
        });
      }),
    [filePayload, password, privateKey, run, usesPassword]
  );

  return (
    <main className="demo-shell">
      <header className="demo-header demo-width">
        <a className="demo-brand" href="#top" aria-label="AppSafe package playground home">
          <span className="demo-brand-mark">
            <AppMark />
          </span>
          <span>AppSafe</span>
          <span className="demo-brand-slash">/</span>
          <span className="demo-brand-muted">playground</span>
        </a>
        <div className="demo-header-actions">
          <nav className="demo-project-links" aria-label="Project links">
            <a
              className="demo-icon-button"
              href="https://www.npmjs.com/package/@asafarim/appsafe"
              target="_blank"
              rel="noreferrer"
              aria-label="Open AppSafe on npm"
              title="AppSafe on npm"
            >
              <NpmIcon />
            </a>
            <a
              className="demo-icon-button"
              href="https://github.com/AliSafari-IT/asafarim-appsafe"
              target="_blank"
              rel="noreferrer"
              aria-label="Open AppSafe on GitHub"
              title="AppSafe on GitHub"
            >
              <GitHubIcon />
            </a>
          </nav>
          <nav className="demo-nav" aria-label="Demo navigation">
            <a href="#playground">Playground</a>
            <a className="demo-nav-secondary" href="#methods">Methods</a>
            <a className="demo-nav-secondary" href="#failures">Failures</a>
            <a href="#api">API examples</a>
            <span className="demo-version">v{version}</span>
          </nav>
        </div>
      </header>

      <section className="demo-hero demo-width" id="top">
        <div className="demo-hero-copy">
          <p className="demo-eyebrow">NPM PACKAGE / HANDS-ON EXAMPLE</p>
          <h1>See the package work.</h1>
          <p className="demo-hero-description">
            A small, public playground for <code>@asafarim/appsafe</code>. Encrypt
            with a shared password or for a public key, then decrypt with the
            matching secret — the same calls you would ship in your own app.
          </p>
          <div className="demo-hero-actions">
            <a className="demo-button demo-button-primary" href="#playground">
              Try the playground
              <ArrowIcon />
            </a>
            <span className="demo-local-label">No server / no upload</span>
          </div>
          <div className="demo-chip-row" aria-label="Package properties">
            <span className="demo-chip">Web Crypto API</span>
            <span className="demo-chip">AES-256-GCM</span>
            <span className="demo-chip">PBKDF2 or ECDH P-256</span>
            <span className="demo-chip">TypeScript</span>
          </div>
        </div>
        <div className="demo-terminal" aria-label="Package overview">
          <div className="demo-terminal-bar">
            <span className="terminal-dot terminal-dot-red" />
            <span className="terminal-dot terminal-dot-yellow" />
            <span className="terminal-dot terminal-dot-green" />
            <span className="terminal-path">appsafe-demo</span>
          </div>
          <div className="demo-terminal-body">
            <p><span className="terminal-comment">// password mode</span></p>
            <p><span className="terminal-purple">await</span> encryptBytes(file, password);</p>
            <p>&nbsp;</p>
            <p><span className="terminal-comment">// public-key mode</span></p>
            <p><span className="terminal-purple">await</span> encryptBytesForRecipients(file, publicKey);</p>
            <p><span className="terminal-comment">// stays in this browser tab</span></p>
          </div>
          <div className="demo-terminal-footer">
            <span>PBKDF2 / SHA-256</span>
            <span>{DEFAULT_PBKDF2_ITERATIONS.toLocaleString("en-US")} rounds</span>
          </div>
        </div>
      </section>

      <section className="demo-section demo-width" id="playground">
        <div className="demo-section-heading">
          <div>
            <p className="demo-eyebrow">01 / LIVE PLAYGROUND</p>
            <h2>Use the public package directly.</h2>
          </div>
          <p>
            This demo has no owner gate because its purpose is to document the
            reusable npm API. Every transform and every generated key stays in
            browser memory.
          </p>
        </div>

        <div className="demo-card">
          <div className="demo-tab-bar">
            <div className="demo-mode-tabs" role="tablist" aria-label="Encryption method">
              {(["password", "public-key"] as const).map((value) => (
                <button
                  key={value}
                  className={`demo-mode-tab ${method === value ? "demo-mode-tab-active" : ""}`}
                  type="button"
                  role="tab"
                  aria-selected={method === value}
                  onClick={() => {
                    setMethod(value);
                    setNotice(null);
                  }}
                >
                  {value === "password" ? "Password" : "Public / private key"}
                </button>
              ))}
            </div>
            <div className="demo-mode-tabs" role="tablist" aria-label="Demo input type">
              {(["text", "file"] as const).map((value) => (
                <button
                  key={value}
                  className={`demo-mode-tab ${mode === value ? "demo-mode-tab-active" : ""}`}
                  type="button"
                  role="tab"
                  aria-selected={mode === value}
                  onClick={() => {
                    setMode(value);
                    setNotice(null);
                  }}
                >
                  {value === "text" ? "Text API" : "File API"}
                </button>
              ))}
            </div>
          </div>

          {usesPassword ? (
            <div className="demo-control-bar">
              <div className="demo-password-control">
                <label className="demo-field-label" htmlFor="demo-password">
                  Operation password <span className="demo-badge demo-badge-secret">secret</span>
                </label>
                <input
                  id="demo-password"
                  className="demo-input"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Only used by this browser tab"
                  autoComplete="new-password"
                />
              </div>
              <div className="demo-security-note">
                <span className="demo-security-dot" />
                <span>Not sent over the network</span>
              </div>
            </div>
          ) : (
            <div className="demo-control-bar demo-key-bar">
              <div className="demo-key-grid">
                <div>
                  <label className="demo-field-label" htmlFor="demo-public-key">
                    Recipient public key <span className="demo-badge demo-badge-safe">safe to share</span>
                  </label>
                  <input
                    id="demo-public-key"
                    className="demo-input demo-input-mono"
                    value={publicKey}
                    onChange={(event) => setPublicKey(event.target.value)}
                    placeholder="appsafe-pub-p256:… (encrypts)"
                    spellCheck="false"
                    autoComplete="off"
                  />
                  <small className="demo-key-meta">
                    Fingerprint: {fingerprint ?? "—"}
                  </small>
                </div>
                <div>
                  <label className="demo-field-label" htmlFor="demo-private-key">
                    Private key <span className="demo-badge demo-badge-secret">secret</span>
                  </label>
                  <div className="demo-inline-control">
                    <input
                      id="demo-private-key"
                      className="demo-input demo-input-mono"
                      type={showPrivateKey ? "text" : "password"}
                      value={privateKey}
                      onChange={(event) => setPrivateKey(event.target.value)}
                      placeholder="APPSAFE-PRIVATE-KEY-P256:… (decrypts)"
                      spellCheck="false"
                      autoComplete="off"
                    />
                    <button
                      className="demo-copy-button"
                      type="button"
                      onClick={() => setShowPrivateKey((value) => !value)}
                      disabled={!privateKey}
                    >
                      {showPrivateKey ? "Hide" : "Show"}
                    </button>
                  </div>
                  <small className="demo-key-meta">
                    Ephemeral: cleared on reload, never stored or transmitted.
                  </small>
                </div>
              </div>
              <button
                className="demo-button demo-button-secondary"
                type="button"
                onClick={() => void generateDemoKeys()}
                disabled={busy !== null}
              >
                {busy === "generating" ? "Generating…" : "generateKeyPair()"}
              </button>
            </div>
          )}

          {mode === "text" ? (
            <div className="demo-playground-grid">
              <div className="demo-editor-panel">
                <label className="demo-field-label" htmlFor="demo-text">
                  Plaintext input
                </label>
                <textarea
                  id="demo-text"
                  className="demo-textarea"
                  value={textValue}
                  onChange={(event) => setTextValue(event.target.value)}
                  placeholder="Type a note, JSON, or UTF-8 data…"
                  spellCheck="false"
                />
                <div className="demo-button-row">
                  <button
                    className="demo-button demo-button-primary"
                    type="button"
                    onClick={() => void encryptDemoText()}
                    disabled={busy !== null || !textValue || !canEncrypt}
                  >
                    {busy === "encrypting" ? "Encrypting…" : `${encryptLabel.replace("…", "Text")}()`}
                  </button>
                  <button
                    className="demo-button demo-button-secondary"
                    type="button"
                    onClick={() => void decryptDemoText()}
                    disabled={busy !== null || !textPayload || !canDecrypt}
                  >
                    {busy === "decrypting" ? "Decrypting…" : `${decryptLabel.replace("…", "Text")}()`}
                  </button>
                </div>
              </div>
              <div className="demo-result-panel">
                <div className="demo-result-heading">
                  <span className="demo-field-label">Encrypted payload</span>
                  <span className="demo-result-status">
                    {textPayload ? "ready" : "waiting"}
                  </span>
                </div>
                <div className="demo-payload-box">
                  {textPayload ? (
                    <>
                      <strong>{formatBytes(textPayload.byteLength)}</strong>
                      <span>{hexPreview(textPayload)} …</span>
                      <small>{describePayload(textPayload)} / authenticated</small>
                    </>
                  ) : (
                    <span>Encrypt text to inspect the payload bytes.</span>
                  )}
                </div>
                <input
                  ref={encryptedFileInputRef}
                  className="demo-visually-hidden"
                  type="file"
                  accept={APP_SAFE_EXTENSION}
                  onChange={(event) => void handleEncryptedTextFile(event)}
                />
                <button
                  className="demo-button demo-button-quiet demo-button-full"
                  type="button"
                  onClick={() => encryptedFileInputRef.current?.click()}
                >
                  Choose .appsafe payload
                </button>
                <p className="demo-help-text">
                  Payloads are self-describing: <code>inspectAppSafePayload()</code>{" "}
                  reports the mode, so decrypting with the wrong method fails
                  with <code>MODE_MISMATCH</code> instead of guessing.
                </p>
              </div>
            </div>
          ) : (
            <div className="demo-playground-grid">
              <div className="demo-editor-panel">
                <span className="demo-field-label">Source file</span>
                <input
                  ref={fileInputRef}
                  className="demo-visually-hidden"
                  type="file"
                  onChange={handleSourceFile}
                />
                <button
                  className="demo-file-picker"
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <span className="demo-file-picker-icon">+</span>
                  <span>
                    <strong>{selectedFile ? selectedFile.name : "Choose one file"}</strong>
                    <small>
                      {selectedFile ? formatBytes(selectedFile.size) : "The file stays in browser memory"}
                    </small>
                  </span>
                </button>
                <div className="demo-button-row">
                  <button
                    className="demo-button demo-button-primary"
                    type="button"
                    onClick={() => void encryptDemoFile()}
                    disabled={busy !== null || !selectedFile || !canEncrypt}
                  >
                    {busy === "encrypting" ? "Encrypting…" : `${encryptLabel.replace("…", "Bytes")}()`}
                  </button>
                  <button
                    className="demo-button demo-button-secondary"
                    type="button"
                    onClick={() => void decryptDemoFile()}
                    disabled={busy !== null || !filePayload || !canDecrypt}
                  >
                    {busy === "decrypting" ? "Decrypting…" : `${decryptLabel.replace("…", "Bytes")}()`}
                  </button>
                </div>
                <input
                  className="demo-visually-hidden"
                  id="encrypted-file-picker"
                  type="file"
                  accept={APP_SAFE_EXTENSION}
                  onChange={(event) => void handleEncryptedFile(event)}
                />
                <label className="demo-upload-link" htmlFor="encrypted-file-picker">
                  Or choose an existing .appsafe payload
                </label>
              </div>
              <div className="demo-result-panel">
                <div className="demo-result-heading">
                  <span className="demo-field-label">Round-trip state</span>
                  <span className="demo-result-status">
                    {decryptedFile ? "decrypted" : filePayload ? "encrypted" : "waiting"}
                  </span>
                </div>
                <div className="demo-file-state-list">
                  <div className="demo-file-state-row">
                    <span>Payload</span>
                    <strong>{filePayload ? formatBytes(filePayload.bytes.byteLength) : "—"}</strong>
                  </div>
                  <div className="demo-file-state-row">
                    <span>Format check</span>
                    <strong>{filePayload ? describePayload(filePayload.bytes) : "—"}</strong>
                  </div>
                  <div className="demo-file-state-row">
                    <span>Plaintext</span>
                    <strong>{decryptedFile ? formatBytes(decryptedFile.bytes.byteLength) : "—"}</strong>
                  </div>
                </div>
                {decryptedFile ? (
                  <button
                    className="demo-button demo-button-quiet demo-button-full"
                    type="button"
                    onClick={() => downloadBytes(decryptedFile.bytes, decryptedFile.name, "application/octet-stream")}
                  >
                    Download decrypted file
                  </button>
                ) : null}
                <p className="demo-help-text">
                  The same byte functions work with images, PDFs, archives, or
                  any other file a browser can read. Folders are a CLI feature.
                </p>
              </div>
            </div>
          )}

          {notice ? (
            <p className={`demo-notice demo-notice-${notice.kind}`} role="status">
              {notice.text}
            </p>
          ) : null}
        </div>
      </section>

      <section className="demo-section demo-width" id="methods">
        <div className="demo-section-heading">
          <div>
            <p className="demo-eyebrow">02 / TWO METHODS</p>
            <h2>Same core, different custody.</h2>
          </div>
          <p>
            Both methods finish with AES-256-GCM over an authenticated,
            versioned header. They differ in where the key comes from and who
            must keep a secret.
          </p>
        </div>
        <MethodGuide />
        <div className="demo-subsection">
          <h3>When to choose each method</h3>
          <MethodComparison />
        </div>
      </section>

      <section className="demo-section demo-width" id="failures">
        <div className="demo-section-heading">
          <div>
            <p className="demo-eyebrow">03 / FAILURE LAB</p>
            <h2>Wrong inputs fail closed.</h2>
          </div>
          <p>
            Authentication covers the header, every recipient entry, and the
            ciphertext. Run the checks to see the exact error codes your app
            should handle.
          </p>
        </div>
        <FailureLab />
      </section>

      <section className="demo-section demo-width" id="api">
        <div className="demo-section-heading">
          <div>
            <p className="demo-eyebrow">04 / COPYABLE RECIPES</p>
            <h2>A few calls are enough.</h2>
          </div>
          <p>
            Install the package, supply a password or keys you manage, and keep
            the returned bytes wherever your app needs them.
          </p>
        </div>
        <div className="demo-code-grid">
          {RECIPES.map((recipe) => (
            <CodeCard key={recipe.title} title={recipe.title} code={recipe.code} />
          ))}
        </div>
        <div className="demo-subsection">
          <CodeCard title="CLI / encrypt a private app folder" code={CLI_RECIPE} />
        </div>
      </section>

      <section className="demo-principles demo-width" aria-label="Runtime support">
        <div className="demo-principle">
          <span className="demo-principle-index">A / BROWSER CORE</span>
          <h3>Both methods</h3>
          <code>pnpm add @asafarim/appsafe</code>
          <p>
            Password and public-key encryption, key generation, and payload
            inspection run anywhere Web Crypto supports AES-GCM, PBKDF2, HKDF,
            and ECDH P-256: evergreen browsers, Node 20+, and Deno.
          </p>
        </div>
        <div className="demo-principle">
          <span className="demo-principle-index">B / CLI ONLY</span>
          <h3>Files and folders</h3>
          <code>pnpm add -D @asafarim/appsafe-cli</code>
          <p>
            Key files, folder archives, per-target modes, <code>.gitignore</code>{" "}
            management, and <code>rekey</code> migration need a filesystem, so
            they live in the Node.js CLI.
          </p>
        </div>
        <div className="demo-principle">
          <span className="demo-principle-index">C / FORMAT</span>
          <h3>Not Age-compatible</h3>
          <code>ECDH-P256+HKDF-SHA256+A256GCM</code>
          <p>
            Uses the same recipient/identity model as Age, built only from Web
            Crypto primitives. Age files and keys cannot be read or written.
          </p>
        </div>
      </section>

      <footer className="demo-footer demo-width">
        <span>@asafarim/appsafe / package playground</span>
        <span>Client-side by design</span>
      </footer>
    </main>
  );
}

type CodeCardProps = {
  title: string;
  code: string;
};

function CodeCard({ title, code }: CodeCardProps) {
  const [copied, setCopied] = useState(false);

  const copyCode = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }, [code]);

  return (
    <article className="demo-code-card">
      <div className="demo-code-card-heading">
        <span>{title}</span>
        <button className="demo-copy-button" type="button" onClick={() => void copyCode()}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre>
        <code>{code}</code>
      </pre>
    </article>
  );
}
