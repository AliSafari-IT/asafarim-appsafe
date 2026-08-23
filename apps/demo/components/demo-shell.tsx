"use client";

import {
  useCallback,
  useRef,
  useState,
  type ChangeEvent,
} from "react";
import {
  AppSafeCryptoError,
  DEFAULT_PBKDF2_ITERATIONS,
  decryptBytes,
  decryptText,
  encryptBytes,
  encryptText,
  isAppSafePayload,
} from "@asafarim/appsafe";

type DemoMode = "text" | "file";
type BusyState = "encrypting" | "decrypting" | null;
type Notice = {
  kind: "success" | "error" | "info";
  text: string;
};
type Artifact = {
  bytes: Uint8Array;
  name: string;
};

const APP_SAFE_EXTENSION = ".appsafe";
const TEXT_EXAMPLE = `import { decryptText, encryptText } from "@asafarim/appsafe";

const encrypted = await encryptText("private note", password);
const plaintext = await decryptText(encrypted, password);`;
const FILE_EXAMPLE = `import { decryptBytes, encryptBytes } from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
const encrypted = await encryptBytes(input, password);
const plaintext = await decryptBytes(encrypted, password);`;

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

function operationError(error: unknown): string {
  if (error instanceof AppSafeCryptoError) {
    if (error.code === "INVALID_PASSWORD_OR_DATA") {
      return "The password or encrypted payload is invalid.";
    }

    if (error.code === "INVALID_PAYLOAD") {
      return "This is not a supported AppSafe payload.";
    }

    if (error.code === "INVALID_TEXT") {
      return "The decrypted bytes are not valid UTF-8 text.";
    }
  }

  return "The operation could not be completed in this browser.";
}

function AppMark() {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className="demo-mark-icon">
      <path d="M16 3.5 26 7v7.5c0 6.4-4.2 11.3-10 14-5.8-2.7-10-7.6-10-14V7l10-3.5Z" />
      <path d="m11.5 16 3 3 6-6" />
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

export function DemoShell() {
  const [mode, setMode] = useState<DemoMode>("text");
  const [password, setPassword] = useState("");
  const [textValue, setTextValue] = useState("This note never leaves the browser.");
  const [textPayload, setTextPayload] = useState<Uint8Array | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePayload, setFilePayload] = useState<Artifact | null>(null);
  const [decryptedFile, setDecryptedFile] = useState<Artifact | null>(null);
  const [busy, setBusy] = useState<BusyState>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const encryptedFileInputRef = useRef<HTMLInputElement>(null);

  const encryptDemoText = useCallback(async () => {
    if (!textValue || !password) {
      setNotice({ kind: "error", text: "Enter text and a password first." });
      return;
    }

    setBusy("encrypting");
    setNotice(null);

    try {
      const payload = await encryptText(textValue, password);
      setTextPayload(payload);
      downloadBytes(payload, `message.txt${APP_SAFE_EXTENSION}`, "application/octet-stream");
      setNotice({
        kind: "success",
        text: `Encrypted ${formatBytes(payload.byteLength)} locally and downloaded the payload.`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, textValue]);

  const decryptDemoText = useCallback(async () => {
    if (!textPayload || !password) {
      setNotice({ kind: "error", text: "Create or choose an encrypted payload first." });
      return;
    }

    setBusy("decrypting");
    setNotice(null);

    try {
      setTextValue(await decryptText(textPayload, password));
      setNotice({ kind: "success", text: "Decrypted locally with decryptText()." });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, textPayload]);

  const handleEncryptedTextFile = useCallback(
    async (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      event.target.value = "";

      if (!file) {
        return;
      }

      const bytes = new Uint8Array(await file.arrayBuffer());

      if (!isAppSafePayload(bytes)) {
        setNotice({ kind: "error", text: "Choose a valid .appsafe payload." });
        return;
      }

      setTextPayload(bytes);
      setNotice({ kind: "info", text: `${file.name} is ready for decryptText().` });
    },
    []
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
      const file = event.target.files?.[0];
      event.target.value = "";

      if (!file) {
        return;
      }

      const bytes = new Uint8Array(await file.arrayBuffer());

      if (!isAppSafePayload(bytes)) {
        setNotice({ kind: "error", text: "Choose a valid .appsafe payload." });
        return;
      }

      setFilePayload({ bytes, name: file.name });
      setDecryptedFile(null);
      setNotice({ kind: "info", text: `${file.name} is ready for decryptBytes().` });
    },
    []
  );

  const encryptDemoFile = useCallback(async () => {
    if (!selectedFile || !password) {
      setNotice({ kind: "error", text: "Choose a file and enter a password first." });
      return;
    }

    setBusy("encrypting");
    setNotice(null);

    try {
      const payload = await encryptBytes(
        new Uint8Array(await selectedFile.arrayBuffer()),
        password
      );
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
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, selectedFile]);

  const decryptDemoFile = useCallback(async () => {
    if (!filePayload || !password) {
      setNotice({ kind: "error", text: "Choose an encrypted payload and enter its password." });
      return;
    }

    setBusy("decrypting");
    setNotice(null);

    try {
      const bytes = await decryptBytes(filePayload.bytes, password);
      const artifact = { bytes, name: outputName(filePayload.name) };
      setDecryptedFile(artifact);
      downloadBytes(bytes, artifact.name, "application/octet-stream");
      setNotice({
        kind: "success",
        text: `Decrypted ${filePayload.name} locally and downloaded the result.`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [filePayload, password]);

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
        <nav className="demo-nav" aria-label="Demo navigation">
          <a href="#playground">Playground</a>
          <a href="#api">API examples</a>
          <span className="demo-version">v0.1.0</span>
        </nav>
      </header>

      <section className="demo-hero demo-width" id="top">
        <div className="demo-hero-copy">
          <p className="demo-eyebrow">NPM PACKAGE / HANDS-ON EXAMPLE</p>
          <h1>See the package work.</h1>
          <p className="demo-hero-description">
            A small, public playground for <code>@asafarim/appsafe</code>. Run the
            same text and byte-level calls you would ship in your own browser app.
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
            <p><span className="terminal-purple">import</span> &#123; encryptBytes &#125;</p>
            <p><span className="terminal-purple">from</span> <span className="terminal-green">&quot;@asafarim/appsafe&quot;</span>;</p>
            <p>&nbsp;</p>
            <p><span className="terminal-purple">const</span> payload = <span className="terminal-purple">await</span> encryptBytes(file, password);</p>
            <p><span className="terminal-comment">// stays in this browser tab</span></p>
          </div>
          <div className="demo-terminal-footer">
            <span>PBKDF2 / SHA-256</span>
            <span>{DEFAULT_PBKDF2_ITERATIONS.toLocaleString()} rounds</span>
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
            reusable npm API. All transforms still happen in browser memory.
          </p>
        </div>

        <div className="demo-card">
          <div className="demo-mode-tabs" role="tablist" aria-label="Demo input type">
            <button
              className={`demo-mode-tab ${mode === "text" ? "demo-mode-tab-active" : ""}`}
              type="button"
              role="tab"
              aria-selected={mode === "text"}
              onClick={() => {
                setMode("text");
                setNotice(null);
              }}
            >
              Text API
            </button>
            <button
              className={`demo-mode-tab ${mode === "file" ? "demo-mode-tab-active" : ""}`}
              type="button"
              role="tab"
              aria-selected={mode === "file"}
              onClick={() => {
                setMode("file");
                setNotice(null);
              }}
            >
              File API
            </button>
          </div>

          <div className="demo-control-bar">
            <div className="demo-password-control">
              <label className="demo-field-label" htmlFor="demo-password">
                Operation password
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
                    disabled={busy !== null || !textValue || !password}
                  >
                    {busy === "encrypting" ? "Encrypting…" : "encryptText()"}
                  </button>
                  <button
                    className="demo-button demo-button-secondary"
                    type="button"
                    onClick={() => void decryptDemoText()}
                    disabled={busy !== null || !textPayload || !password}
                  >
                    {busy === "decrypting" ? "Decrypting…" : "decryptText()"}
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
                      <small>AppSafe binary envelope / authenticated</small>
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
                  The decrypt call uses the in-memory payload or a payload selected
                  from disk. Both paths use the same package function.
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
                    disabled={busy !== null || !selectedFile || !password}
                  >
                    {busy === "encrypting" ? "Encrypting…" : "encryptBytes()"}
                  </button>
                  <button
                    className="demo-button demo-button-secondary"
                    type="button"
                    onClick={() => void decryptDemoFile()}
                    disabled={busy !== null || !filePayload || !password}
                  >
                    {busy === "decrypting" ? "Decrypting…" : "decryptBytes()"}
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
                    <strong>{filePayload ? "AppSafe v1" : "—"}</strong>
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
                  any other file a browser can read.
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

      <section className="demo-section demo-width" id="api">
        <div className="demo-section-heading">
          <div>
            <p className="demo-eyebrow">02 / COPYABLE RECIPES</p>
            <h2>Three calls are enough.</h2>
          </div>
          <p>
            Install the package, pass a password you manage, and keep the returned
            bytes wherever your browser app needs them.
          </p>
        </div>
        <div className="demo-code-grid">
          <CodeCard title="Text round-trip" code={TEXT_EXAMPLE} />
          <CodeCard title="File round-trip" code={FILE_EXAMPLE} />
        </div>
      </section>

      <section className="demo-principles demo-width">
        <div className="demo-principle">
          <span className="demo-principle-index">A /</span>
          <h3>Install</h3>
          <code>pnpm add @asafarim/appsafe</code>
          <p>Works in browser runtimes with Web Crypto support.</p>
        </div>
        <div className="demo-principle">
          <span className="demo-principle-index">B /</span>
          <h3>Encrypt</h3>
          <code>await encryptBytes(data, password)</code>
          <p>Returns a portable Uint8Array payload with authenticated metadata.</p>
        </div>
        <div className="demo-principle">
          <span className="demo-principle-index">C /</span>
          <h3>Decrypt</h3>
          <code>await decryptBytes(payload, password)</code>
          <p>Wrong passwords and modified payloads fail closed.</p>
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
