"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
} from "react";
import {
  AppSafeCryptoError,
  decryptBytes,
  decryptText,
  encryptBytes,
  encryptText,
} from "@asafarim/appsafe";
import { zipSync } from "fflate";

type GateState = "checking" | "locked" | "unlocked";
type ToolMode = "files" | "text";
type BusyState = "encrypting" | "decrypting" | null;
type Notice = {
  kind: "success" | "error" | "info";
  text: string;
};

const APP_SAFE_EXTENSION = ".appsafe";

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function filePath(file: File): string {
  return file.webkitRelativePath || file.name;
}

function isZipPayload(data: Uint8Array): boolean {
  return data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b;
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

function downloadText(text: string, fileName: string): void {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

function getDecryptedName(fileName: string, data: Uint8Array): string {
  const baseName = fileName.toLowerCase().endsWith(APP_SAFE_EXTENSION)
    ? fileName.slice(0, -APP_SAFE_EXTENSION.length)
    : `decrypted-${fileName}`;

  if (isZipPayload(data) && !baseName.toLowerCase().endsWith(".zip")) {
    return `${baseName || "folder"}.zip`;
  }

  return baseName || "decrypted.bin";
}

function operationError(error: unknown): string {
  if (error instanceof AppSafeCryptoError) {
    if (error.code === "INVALID_PASSWORD_OR_DATA") {
      return "The password or encrypted data is invalid.";
    }

    if (error.code === "INVALID_PAYLOAD") {
      return "This file is not a supported AppSafe payload.";
    }

    if (error.code === "INVALID_TEXT") {
      return "The decrypted payload is not valid UTF-8 text.";
    }
  }

  return "The operation could not be completed in this browser.";
}

function AppIcon() {
  return (
    <svg viewBox="0 0 48 48" aria-hidden="true" className="app-icon">
      <path d="M24 5 39 10.5V21c0 10.2-6.2 18.1-15 22C14.2 39.1 9 31.2 9 21V10.5z" />
      <path d="m15.5 23.8 5.3 5.3 11.7-12.2" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="inline-icon">
      <rect x="4" y="10" width="16" height="11" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="inline-icon">
      <path d="M5 12h13M13 6l6 6-6 6" />
    </svg>
  );
}

function NpmIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="social-icon">
      <path d="M3 6h18v12h-6V9h-3v9H3z" />
    </svg>
  );
}

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="social-icon social-icon-filled">
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2.17c-3.2.7-3.87-1.36-3.87-1.36-.53-1.34-1.3-1.7-1.3-1.7-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.67 1.24 3.32.95.1-.74.4-1.24.72-1.53-2.55-.29-5.23-1.27-5.23-5.67 0-1.25.45-2.27 1.18-3.07-.12-.29-.51-1.45.11-3.03 0 0 .96-.31 3.16 1.17a10.98 10.98 0 0 1 5.76 0c2.2-1.48 3.16-1.17 3.16-1.17.62 1.58.23 2.74.11 3.03.73.8 1.18 1.82 1.18 3.07 0 4.41-2.69 5.38-5.25 5.66.41.36.77 1.07.77 2.16v3.2c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  );
}

export function AppSafeShell() {
  const [gateState, setGateState] = useState<GateState>("checking");
  const [accessCode, setAccessCode] = useState("");
  const [gateError, setGateError] = useState("");
  const [gateBusy, setGateBusy] = useState(false);

  useEffect(() => {
    let active = true;

    async function loadGateStatus() {
      try {
        const response = await fetch("/api/gate/status", {
          credentials: "include",
          cache: "no-store",
        });
        const body = (await response.json().catch(() => null)) as {
          unlocked?: unknown;
        } | null;

        if (active) {
          setGateState(body?.unlocked === true ? "unlocked" : "locked");
        }
      } catch {
        if (active) {
          setGateState("locked");
        }
      }
    }

    void loadGateStatus();

    return () => {
      active = false;
    };
  }, []);

  const handleUnlock = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setGateError("");

      if (!accessCode || gateBusy) {
        return;
      }

      setGateBusy(true);

      try {
        const response = await fetch("/api/gate/verify", {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ code: accessCode }),
        });
        const body = (await response.json().catch(() => null)) as {
          unlocked?: unknown;
        } | null;

        setAccessCode("");

        if (response.ok && body?.unlocked === true) {
          setGateState("unlocked");
        } else {
          setGateError("That code did not unlock the workspace.");
        }
      } catch {
        setGateError("The gate service is unavailable. Try again shortly.");
      } finally {
        setGateBusy(false);
      }
    },
    [accessCode, gateBusy]
  );

  const handleLock = useCallback(async () => {
    setGateState("locked");
    setAccessCode("");
    setGateError("");

    try {
      await fetch("/api/gate/lock", {
        method: "POST",
        credentials: "include",
      });
    } catch {
      return;
    }
  }, []);

  return (
    <main className="app-shell">
      <header className="site-header content-width">
        <a className="brand" href="#top" aria-label="AppSafe home">
          <span className="brand-mark">
            <AppIcon />
          </span>
          <span>AppSafe</span>
        </a>
        <div className="site-header-actions">
          <nav className="project-links" aria-label="Project links">
            <a
              className="icon-button"
              href="https://www.npmjs.com/package/@asafarim/appsafe"
              target="_blank"
              rel="noreferrer"
              aria-label="Open AppSafe on npm"
              title="AppSafe on npm"
            >
              <NpmIcon />
            </a>
            <a
              className="icon-button"
              href="https://github.com/AliSafari-IT/asafarim-appsafe"
              target="_blank"
              rel="noreferrer"
              aria-label="Open AppSafe on GitHub"
              title="AppSafe on GitHub"
            >
              <GitHubIcon />
            </a>
          </nav>
          <div className="header-meta">
            <a className="header-link" href="/how-to">
              How to use
            </a>
            <span className="header-label">Browser-local security</span>
            <span className={`gate-status gate-status-${gateState}`}>
              <span className="status-dot" />
              {gateState === "unlocked" ? "Workspace unlocked" : "Owner access required"}
            </span>
          </div>
        </div>
      </header>

      <section className="hero content-width" id="top">
        <div className="hero-copy">
          <p className="eyebrow">Private by default</p>
          <h1>
            Your files stay
            <span className="headline-accent"> yours.</span>
          </h1>
          <p className="hero-description">
            A focused encryption workspace for files, folders, and everyday data.
            Encrypt in the browser, keep your password separate, and move the
            resulting payload wherever you need it.
          </p>
          <div className="hero-actions">
            <a className="button button-primary" href="#workspace">
              Open workspace
              <ArrowIcon />
            </a>
            <span className="hero-proof">
              <LockIcon />
              Nothing uploaded
            </span>
          </div>
        </div>
        <div className="hero-panel" aria-label="AppSafe encryption summary">
          <div className="hero-panel-topline">
            <span className="signal signal-green" />
            <span>Local processing active</span>
          </div>
          <div className="cipher-visual">
            <span className="cipher-ring cipher-ring-back" />
            <span className="cipher-ring cipher-ring-front" />
            <span className="cipher-core">
              <LockIcon />
            </span>
          </div>
          <div className="hero-panel-bottomline">
            <span>AES-256-GCM</span>
            <span>PBKDF2 / SHA-256</span>
          </div>
        </div>
      </section>

      <section className="trust-strip content-width" aria-label="AppSafe properties">
        <div className="trust-item">
          <span className="trust-number">01</span>
          <span>
            <strong>Zero upload</strong>
            <small>Plaintext stays on-device</small>
          </span>
        </div>
        <div className="trust-item">
          <span className="trust-number">02</span>
          <span>
            <strong>One owner gate</strong>
            <small>Private workspace access</small>
          </span>
        </div>
        <div className="trust-item">
          <span className="trust-number">03</span>
          <span>
            <strong>Portable output</strong>
            <small>Download an authenticated payload</small>
          </span>
        </div>
      </section>

      <section className="workspace-section content-width" id="workspace">
        <div className="section-heading">
          <div>
            <p className="eyebrow">The private workspace</p>
            <h2>Ready when you are.</h2>
          </div>
          <p>
            The interface is public. The working tools remain behind the owner
            access gate.
          </p>
        </div>

        {gateState === "unlocked" ? (
          <EncryptionWorkspace onLock={handleLock} />
        ) : (
          <GatePanel
            accessCode={accessCode}
            error={gateError}
            initializing={gateState === "checking"}
            busy={gateBusy}
            onAccessCodeChange={setAccessCode}
            onSubmit={handleUnlock}
          />
        )}
      </section>

      <section className="principles-section content-width">
        <div className="section-heading section-heading-compact">
          <div>
            <p className="eyebrow">Why AppSafe</p>
            <h2>Simple boundaries. Strong primitives.</h2>
          </div>
        </div>
        <div className="principles-grid">
          <article className="principle-card">
            <span className="principle-index">A /</span>
            <h3>Your password is yours.</h3>
            <p>
              The owner access code only unlocks this interface. Every encryption
              operation uses a separate password that never leaves your browser.
            </p>
          </article>
          <article className="principle-card">
            <span className="principle-index">B /</span>
            <h3>Authenticated, not just hidden.</h3>
            <p>
              AES-GCM detects altered payloads as well as incorrect passwords,
              so corrupted data does not quietly look valid.
            </p>
          </article>
          <article className="principle-card">
            <span className="principle-index">C /</span>
            <h3>Useful without a database.</h3>
            <p>
              The API only manages a short-lived signed gate session. Your files,
              keys, and operation history are never sent to it.
            </p>
          </article>
        </div>
      </section>

      <footer className="site-footer content-width">
        <span>AppSafe / browser-first file security</span>
        <span>Built with Web Crypto API</span>
      </footer>
    </main>
  );
}

type GatePanelProps = {
  accessCode: string;
  error: string;
  initializing: boolean;
  busy: boolean;
  onAccessCodeChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

function GatePanel({
  accessCode,
  error,
  initializing,
  busy,
  onAccessCodeChange,
  onSubmit,
}: GatePanelProps) {
  return (
    <div className="gate-layout">
      <div className="gate-intro">
        <span className="gate-icon">
          <LockIcon />
        </span>
        <p className="eyebrow">Restricted by design</p>
        <h3>Enter the owner code to use the tools.</h3>
        <p>
          AppSafe is intentionally visible to everyone, but only the owner can
          activate file processing in this session.
        </p>
        <ul className="gate-list">
          <li>Verification happens on the Express API.</li>
          <li>Success creates an expiring HttpOnly session cookie.</li>
          <li>The access code is not persisted in the browser.</li>
        </ul>
      </div>
      <form className="gate-card" onSubmit={onSubmit}>
        <div className="card-topline">
          <span>Owner access</span>
          <span className="secure-label">
            <span className="status-dot status-dot-accent" />
            Server checked
          </span>
        </div>
        <label className="field-label" htmlFor="access-code">
          Secret access code
        </label>
        <input
          id="access-code"
          className="text-input"
          type="password"
          value={accessCode}
          onChange={(event) => onAccessCodeChange(event.target.value)}
          placeholder="Enter your private code"
          autoComplete="off"
          autoFocus={!initializing}
          disabled={initializing || busy}
        />
        <p className="field-help">Only a pass/fail response returns to this page.</p>
        {error ? (
          <p className="notice notice-error" role="alert">
            {error}
          </p>
        ) : null}
        <button
          className="button button-primary button-full"
          type="submit"
          disabled={initializing || busy || !accessCode}
        >
          {initializing ? "Checking session…" : busy ? "Verifying…" : "Unlock workspace"}
          {!initializing && !busy ? <ArrowIcon /> : null}
        </button>
        <p className="gate-footnote">Session lifetime is controlled by the API.</p>
      </form>
    </div>
  );
}

type EncryptionWorkspaceProps = {
  onLock: () => void;
};

function EncryptionWorkspace({ onLock }: EncryptionWorkspaceProps) {
  const [mode, setMode] = useState<ToolMode>("files");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [encryptedTextFile, setEncryptedTextFile] = useState<File | null>(null);
  const [textValue, setTextValue] = useState("");
  const [password, setPassword] = useState("");
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState<BusyState>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const encryptedTextInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    folderInputRef.current?.setAttribute("webkitdirectory", "");
  }, []);

  const updateFiles = useCallback((files: File[]) => {
    if (files.length === 0) {
      return;
    }

    setSelectedFiles(files);
    setNotice({
      kind: "info",
      text: `${files.length} item${files.length === 1 ? "" : "s"} ready for local processing.`,
    });
  }, []);

  const handleFileChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      updateFiles(Array.from(event.target.files ?? []));
      event.target.value = "";
    },
    [updateFiles]
  );

  const handleDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      setDragging(false);
      updateFiles(Array.from(event.dataTransfer.files));
    },
    [updateFiles]
  );

  const encryptFiles = useCallback(async () => {
    if (selectedFiles.length === 0 || !password) {
      setNotice({ kind: "error", text: "Choose a file and enter an encryption password." });
      return;
    }

    setBusy("encrypting");
    setNotice(null);

    try {
      const folderSelection =
        selectedFiles.length > 1 || selectedFiles.some((file) => file.webkitRelativePath);
      let input: Uint8Array;
      let outputName: string;

      if (folderSelection) {
        const entries: Record<string, Uint8Array> = {};

        for (const file of selectedFiles) {
          entries[filePath(file)] = new Uint8Array(await file.arrayBuffer());
        }

        input = zipSync(entries, { level: 6 });
        outputName = "folder.appsafe";
      } else {
        input = new Uint8Array(await selectedFiles[0].arrayBuffer());
        outputName = `${selectedFiles[0].name}${APP_SAFE_EXTENSION}`;
      }

      const encrypted = await encryptBytes(input, password);
      downloadBytes(encrypted, outputName, "application/octet-stream");
      setNotice({
        kind: "success",
        text: `Encrypted locally. Downloaded ${outputName}.`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, selectedFiles]);

  const decryptFile = useCallback(async () => {
    if (selectedFiles.length !== 1 || !password) {
      setNotice({
        kind: "error",
        text: "Choose one .appsafe file and enter its encryption password.",
      });
      return;
    }

    setBusy("decrypting");
    setNotice(null);

    try {
      const source = selectedFiles[0];
      const decrypted = await decryptBytes(
        new Uint8Array(await source.arrayBuffer()),
        password
      );
      const outputName = getDecryptedName(source.name, decrypted);
      downloadBytes(decrypted, outputName, isZipPayload(decrypted) ? "application/zip" : "application/octet-stream");
      setNotice({
        kind: "success",
        text: `Decrypted locally. Downloaded ${outputName}.`,
      });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, selectedFiles]);

  const encryptTextData = useCallback(async () => {
    if (!textValue || !password) {
      setNotice({ kind: "error", text: "Enter text and an encryption password first." });
      return;
    }

    setBusy("encrypting");
    setNotice(null);

    try {
      const encrypted = await encryptText(textValue, password);
      downloadBytes(encrypted, `message.txt${APP_SAFE_EXTENSION}`, "application/octet-stream");
      setNotice({ kind: "success", text: "Encrypted locally. Downloaded message.txt.appsafe." });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [password, textValue]);

  const decryptTextData = useCallback(async () => {
    if (!encryptedTextFile || !password) {
      setNotice({
        kind: "error",
        text: "Choose an encrypted text payload and enter its password.",
      });
      return;
    }

    setBusy("decrypting");
    setNotice(null);

    try {
      const decrypted = await decryptText(
        new Uint8Array(await encryptedTextFile.arrayBuffer()),
        password
      );
      setTextValue(decrypted);
      setNotice({ kind: "success", text: "Decrypted locally. The text is ready below." });
    } catch (error) {
      setNotice({ kind: "error", text: operationError(error) });
    } finally {
      setBusy(null);
    }
  }, [encryptedTextFile, password]);

  return (
    <div className="workspace-card">
      <div className="workspace-toolbar">
        <div>
          <div className="workspace-live">
            <span className="signal signal-green" />
            Local workspace active
          </div>
          <h3>Encrypt or decrypt without uploading.</h3>
        </div>
        <button className="button button-quiet" type="button" onClick={onLock}>
          Lock workspace
        </button>
      </div>

      <div className="mode-tabs" role="tablist" aria-label="Encryption input type">
        <button
          className={`mode-tab ${mode === "files" ? "mode-tab-active" : ""}`}
          type="button"
          role="tab"
          aria-selected={mode === "files"}
          onClick={() => {
            setMode("files");
            setNotice(null);
          }}
        >
          Files & folders
        </button>
        <button
          className={`mode-tab ${mode === "text" ? "mode-tab-active" : ""}`}
          type="button"
          role="tab"
          aria-selected={mode === "text"}
          onClick={() => {
            setMode("text");
            setNotice(null);
          }}
        >
          Text & data
        </button>
      </div>

      {mode === "files" ? (
        <div className="tool-grid">
          <div className="tool-main">
            <div
              className={`drop-zone ${dragging ? "drop-zone-dragging" : ""}`}
              onDragEnter={(event) => {
                event.preventDefault();
                setDragging(true);
              }}
              onDragOver={(event) => event.preventDefault()}
              onDragLeave={(event) => {
                if (event.currentTarget === event.target) {
                  setDragging(false);
                }
              }}
              onDrop={handleDrop}
            >
              <span className="drop-icon">
                <svg viewBox="0 0 24 24" aria-hidden="true" className="inline-icon">
                  <path d="M12 16V4M7 9l5-5 5 5M4 19.5h16" />
                </svg>
              </span>
              <h4>Drop files here</h4>
              <p>Files, multiple selections, or a complete folder.</p>
              <div className="drop-actions">
                <input
                  ref={fileInputRef}
                  className="visually-hidden"
                  type="file"
                  multiple
                  onChange={handleFileChange}
                />
                <input
                  ref={folderInputRef}
                  className="visually-hidden"
                  type="file"
                  multiple
                  onChange={handleFileChange}
                />
                <button
                  className="button button-secondary"
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                >
                  Select files
                </button>
                <button
                  className="button button-quiet"
                  type="button"
                  onClick={() => folderInputRef.current?.click()}
                >
                  Select folder
                </button>
              </div>
            </div>

            {selectedFiles.length > 0 ? (
              <div className="selected-files">
                <div className="selected-files-heading">
                  <span>
                    Selected {selectedFiles.length === 1 ? "file" : "items"}
                  </span>
                  <button
                    className="text-button"
                    type="button"
                    onClick={() => setSelectedFiles([])}
                  >
                    Clear
                  </button>
                </div>
                <div className="file-list">
                  {selectedFiles.slice(0, 5).map((file) => (
                    <div className="file-row" key={`${filePath(file)}-${file.lastModified}`}>
                      <span className="file-type">{file.name.split(".").pop()?.toUpperCase() || "FILE"}</span>
                      <span className="file-name">{filePath(file)}</span>
                      <span className="file-size">{formatBytes(file.size)}</span>
                    </div>
                  ))}
                  {selectedFiles.length > 5 ? (
                    <div className="file-more">+ {selectedFiles.length - 5} more items</div>
                  ) : null}
                </div>
              </div>
            ) : null}
          </div>

          <div className="tool-side">
            <PasswordField password={password} onChange={setPassword} />
            <div className="action-stack">
              <button
                className="button button-primary button-full"
                type="button"
                onClick={() => void encryptFiles()}
                disabled={busy !== null || selectedFiles.length === 0 || !password}
              >
                {busy === "encrypting" ? "Encrypting locally…" : "Encrypt selected"}
              </button>
              <button
                className="button button-secondary button-full"
                type="button"
                onClick={() => void decryptFile()}
                disabled={busy !== null || selectedFiles.length !== 1 || !password}
              >
                {busy === "decrypting" ? "Decrypting locally…" : "Decrypt .appsafe"}
              </button>
            </div>
            <p className="side-help">
              Folder selections are zipped in memory, then encrypted. The zip is
              downloaded only after encryption finishes.
            </p>
          </div>
        </div>
      ) : (
        <div className="tool-grid text-tool-grid">
          <div className="tool-main">
            <label className="field-label" htmlFor="text-data">
              UTF-8 text or data
            </label>
            <textarea
              id="text-data"
              className="text-area"
              value={textValue}
              onChange={(event) => setTextValue(event.target.value)}
              placeholder="Paste a note, JSON object, or any text you want to protect…"
              spellCheck="false"
            />
            <div className="text-output-actions">
              <button
                className="button button-quiet"
                type="button"
                onClick={() => downloadText(textValue, "decrypted.txt")}
                disabled={!textValue}
              >
                Download decrypted text
              </button>
              <span className="text-meta">UTF-8 / browser memory</span>
            </div>
          </div>
          <div className="tool-side">
            <PasswordField password={password} onChange={setPassword} />
            <div className="action-stack">
              <button
                className="button button-primary button-full"
                type="button"
                onClick={() => void encryptTextData()}
                disabled={busy !== null || !textValue || !password}
              >
                {busy === "encrypting" ? "Encrypting locally…" : "Encrypt text"}
              </button>
              <input
                ref={encryptedTextInputRef}
                className="visually-hidden"
                type="file"
                accept={APP_SAFE_EXTENSION}
                onChange={(event) => {
                  setEncryptedTextFile(event.target.files?.[0] ?? null);
                  event.target.value = "";
                }}
              />
              <button
                className="button button-secondary button-full"
                type="button"
                onClick={() => encryptedTextInputRef.current?.click()}
              >
                {encryptedTextFile ? "Replace encrypted file" : "Choose encrypted file"}
              </button>
              {encryptedTextFile ? (
                <p className="file-picked">{encryptedTextFile.name}</p>
              ) : null}
              <button
                className="button button-secondary button-full"
                type="button"
                onClick={() => void decryptTextData()}
                disabled={busy !== null || !encryptedTextFile || !password}
              >
                {busy === "decrypting" ? "Decrypting locally…" : "Decrypt text"}
              </button>
            </div>
            <p className="side-help">
              Text encryption downloads an AppSafe payload. Choose that payload
              again to decrypt it back into the editor.
            </p>
          </div>
        </div>
      )}

      {notice ? (
        <p className={`notice notice-${notice.kind}`} role="status">
          {notice.text}
        </p>
      ) : null}
    </div>
  );
}

type PasswordFieldProps = {
  password: string;
  onChange: (value: string) => void;
};

function PasswordField({ password, onChange }: PasswordFieldProps) {
  return (
    <div className="password-field">
      <label className="field-label" htmlFor="operation-password">
        Operation password
      </label>
      <input
        id="operation-password"
        className="text-input"
        type="password"
        value={password}
        onChange={(event) => onChange(event.target.value)}
        placeholder="Separate from the owner code"
        autoComplete="new-password"
      />
      <p className="field-help">
        This password derives the AES-256 key and never goes to the API.
      </p>
    </div>
  );
}
