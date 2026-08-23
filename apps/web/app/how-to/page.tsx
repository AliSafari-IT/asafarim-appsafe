import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "How to use AppSafe",
  description:
    "Usage examples for the @asafarim/appsafe crypto package and its Node.js CLI.",
};

type CodeExample = {
  index: string;
  title: string;
  description: string;
  code: string;
};

const coreExamples: CodeExample[] = [
  {
    index: "01",
    title: "Install the package",
    description: "Add the browser-first crypto package to any modern JavaScript project.",
    code: `pnpm add @asafarim/appsafe
# or
npm install @asafarim/appsafe`,
  },
  {
    index: "02",
    title: "Encrypt text",
    description: "Text helpers encode UTF-8 data and return the authenticated AppSafe payload.",
    code: `import { decryptText, encryptText } from "@asafarim/appsafe";

const encrypted = await encryptText("private note", password);
const plaintext = await decryptText(encrypted, password);`,
  },
  {
    index: "03",
    title: "Encrypt arbitrary bytes",
    description: "Use Uint8Array or ArrayBuffer when the data is not text.",
    code: `import { decryptBytes, encryptBytes } from "@asafarim/appsafe";

const data = new Uint8Array([0, 1, 2, 255]);
const payload = await encryptBytes(data, password);
const original = await decryptBytes(payload, password);`,
  },
  {
    index: "04",
    title: "Process a browser file",
    description: "Read a selected File locally and persist the encrypted bytes as a download or Blob.",
    code: `import { encryptBytes } from "@asafarim/appsafe";

const input = new Uint8Array(await file.arrayBuffer());
const payload = await encryptBytes(input, password);
const blob = new Blob([payload], {
  type: "application/octet-stream",
});`,
  },
  {
    index: "05",
    title: "Validate a payload",
    description: "Perform a cheap magic-header check before attempting decryption.",
    code: `import { isAppSafePayload } from "@asafarim/appsafe";

const bytes = new Uint8Array(await file.arrayBuffer());
if (!isAppSafePayload(bytes)) {
  throw new Error("Not an AppSafe payload");
}`,
  },
  {
    index: "06",
    title: "Tune PBKDF2",
    description: "Raise the work factor when your product needs a different performance and security balance.",
    code: `import { encryptBytes } from "@asafarim/appsafe";

const payload = await encryptBytes(data, password, {
  iterations: 1_000_000,
});`,
  },
  {
    index: "07",
    title: "Handle typed errors",
    description: "Use AppSafeCryptoError.code to distinguish invalid payloads, passwords, text, and runtime support.",
    code: `import {
  AppSafeCryptoError,
  decryptBytes,
} from "@asafarim/appsafe";

try {
  await decryptBytes(payload, password);
} catch (error) {
  if (
    error instanceof AppSafeCryptoError &&
    error.code === "INVALID_PASSWORD_OR_DATA"
  ) {
    showError("The password or payload is invalid.");
  }
}`,
  },
  {
    index: "08",
    title: "Use exported types and constants",
    description: "The package also exports the ByteSource and EncryptOptions types plus the default work factor.",
    code: `import {
  DEFAULT_PBKDF2_ITERATIONS,
  type ByteSource,
  type EncryptOptions,
} from "@asafarim/appsafe";

const data: ByteSource = new Uint8Array([1, 2, 3]);
const options: EncryptOptions = {
  iterations: DEFAULT_PBKDF2_ITERATIONS,
};`,
  },
];

const cliExamples: CodeExample[] = [
  {
    index: "01",
    title: "Install the CLI",
    description: "The CLI is a Node.js filesystem layer around the same AppSafe crypto core.",
    code: `pnpm add -D @asafarim/appsafe-cli`,
  },
  {
    index: "02",
    title: "Create a configuration",
    description: "Generate a starter configuration with placeholders. Existing configuration files are never overwritten.",
    code: `appsafe init
appsafe init --config path/to/appsafe.config.json
appsafe init --dry-run`,
  },
  {
    index: "03",
    title: "Configure targets",
    description: "Paths are relative to the configuration file. Folder targets become encrypted ZIP archives beside their sources.",
    code: `{
  "version": 1,
  "targets": [
    {
      "source": "./private-config",
      "encrypted": "./private-config.appsafe",
      "type": "directory"
    },
    {
      "source": "./.env.production",
      "encrypted": "./.env.production.appsafe",
      "type": "file"
    }
  ],
  "encryption": {
    "iterations": 600000
  },
  "gitignore": {
    "file": "./.gitignore",
    "ignoreSources": true
  }
}`,
  },
  {
    index: "04",
    title: "Encrypt, decrypt, and check",
    description: "Encrypt configured targets, restore them later, or inspect target status without changing files.",
    code: `appsafe encrypt --config appsafe.config.json
appsafe decrypt --config appsafe.config.json
appsafe check --config appsafe.config.json`,
  },
  {
    index: "05",
    title: "Preview and replace safely",
    description: "Dry runs do not read passwords or write files. Existing outputs require an explicit force flag.",
    code: `appsafe encrypt --config appsafe.config.json --dry-run
appsafe encrypt --config appsafe.config.json --force
appsafe decrypt --config appsafe.config.json --force`,
  },
  {
    index: "06",
    title: "Automate password input",
    description: "Keep passwords out of configuration files. Use an explicit environment variable in automation or the hidden interactive prompt locally.",
    code: `# PowerShell
$env:APPSAFE_PASSWORD = "your-password"
appsafe encrypt --password-env APPSAFE_PASSWORD

# POSIX shell
APPSAFE_PASSWORD="your-password" \\
  appsafe encrypt --password-env APPSAFE_PASSWORD

# Any shell with stdin
printf '%s\\n' "$APPSAFE_PASSWORD" | \\
  appsafe encrypt --password-stdin`,
  },
];

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

function CodeExampleCard({ example }: { example: CodeExample }) {
  return (
    <article className="how-to-card">
      <div className="how-to-card-index">{example.index} /</div>
      <h3>{example.title}</h3>
      <p>{example.description}</p>
      <pre className="how-to-code"><code>{example.code}</code></pre>
    </article>
  );
}

export default function HowToPage() {
  return (
    <main className="app-shell how-to-shell">
      <header className="site-header content-width how-to-header">
        <a className="brand" href="/" aria-label="AppSafe workspace home">
          <span className="brand-mark">A</span>
          <span>AppSafe</span>
          <span className="how-to-brand-label">/ how-to</span>
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
          <nav className="how-to-nav" aria-label="How-to navigation">
            <a className="header-link" href="/" aria-label="Return to the AppSafe workspace">
              Workspace
            </a>
            <a className="header-link" href="#core" aria-current="page">
              Packages
            </a>
          </nav>
        </div>
      </header>

      <section className="how-to-hero content-width">
        <p className="eyebrow">Implementation guide</p>
        <h1>Use AppSafe from browser to terminal.</h1>
        <p className="how-to-lede">
          The core package handles authenticated encryption in browser-native
          runtimes. The CLI adds local files, folders, configuration, and Git
          hygiene without changing the crypto boundary.
        </p>
        <div className="how-to-hero-meta" aria-label="Package guide scope">
          <span>01 / Browser API</span>
          <span>02 / Node.js CLI</span>
          <span>03 / Local by design</span>
        </div>
      </section>

      <nav className="how-to-index content-width" aria-label="Page sections">
        <a href="#core">
          <span>01</span>
          Core package
        </a>
        <a href="#cli">
          <span>02</span>
          CLI package
        </a>
        <a href="#boundaries">
          <span>03</span>
          Safety boundaries
        </a>
      </nav>

      <section className="how-to-section content-width" id="core">
        <div className="section-heading">
          <div>
            <p className="eyebrow">@asafarim/appsafe</p>
            <h2>Browser-first encryption primitives.</h2>
          </div>
          <p>
            Import the functions you need. Passwords and plaintext stay in the
            calling runtime, and the package performs no network requests.
          </p>
        </div>
        <div className="how-to-grid">
          {coreExamples.map((example) => (
            <CodeExampleCard key={example.title} example={example} />
          ))}
        </div>
        <div className="how-to-api-summary">
          <p className="how-to-summary-label">Complete runtime API</p>
          <div className="how-to-api-list">
            <code>encryptBytes</code>
            <code>decryptBytes</code>
            <code>encryptText</code>
            <code>decryptText</code>
            <code>isAppSafePayload</code>
            <code>DEFAULT_PBKDF2_ITERATIONS</code>
            <code>AppSafeCryptoError</code>
          </div>
        </div>
      </section>

      <section className="how-to-section content-width" id="cli">
        <div className="section-heading">
          <div>
            <p className="eyebrow">@asafarim/appsafe-cli</p>
            <h2>Repeatable local file workflows.</h2>
          </div>
          <p>
            Use the CLI for files and folders that live on disk. It creates
            encrypted siblings and updates Git ignore rules after success.
          </p>
        </div>
        <div className="how-to-grid">
          {cliExamples.map((example) => (
            <CodeExampleCard key={example.title} example={example} />
          ))}
        </div>
      </section>

      <section className="how-to-section content-width" id="boundaries">
        <div className="section-heading section-heading-compact">
          <div>
            <p className="eyebrow">Operating boundaries</p>
            <h2>What each layer is responsible for.</h2>
          </div>
        </div>
        <div className="how-to-boundary-grid">
          <article className="how-to-boundary-card">
            <span className="principle-index">CORE /</span>
            <h3>Portable authenticated payloads</h3>
            <p>
              AES-256-GCM protects bytes with a random salt and nonce. PBKDF2
              derives the key from the password, and modified payloads fail
              closed.
            </p>
          </article>
          <article className="how-to-boundary-card">
            <span className="principle-index">CLI /</span>
            <h3>Explicit filesystem operations</h3>
            <p>
              The CLI reads configured paths, archives folders, writes outputs
              atomically, rejects symbolic links, and never removes sources
              automatically.
            </p>
          </article>
          <article className="how-to-boundary-card">
            <span className="principle-index">GIT /</span>
            <h3>Ignore only after encryption</h3>
            <p>
              Source paths are added to the configured .gitignore only after
              every target has encrypted successfully. Encrypted siblings remain
              available to commit.
            </p>
          </article>
        </div>
      </section>

      <footer className="site-footer content-width">
        <span>AppSafe / usage guide</span>
        <a className="header-link" href="/">
          Return to workspace
        </a>
      </footer>
    </main>
  );
}
