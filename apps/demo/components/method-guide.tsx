import { DEFAULT_PBKDF2_ITERATIONS } from "@asafarim/appsafe";

type FlowStep = {
  title: string;
  detail: string;
  secret?: boolean;
};

type EnvelopeSegment = {
  label: string;
  size: string;
};

type Flow = {
  eyebrow: string;
  title: string;
  steps: FlowStep[];
  envelope: EnvelopeSegment[];
  secrets: string[];
  shareable: string[];
};

const ROUNDS = DEFAULT_PBKDF2_ITERATIONS.toLocaleString("en-US");

const FLOWS: Flow[] = [
  {
    eyebrow: "PASSWORD MODE / ENVELOPE v1",
    title: "One shared secret encrypts and decrypts.",
    steps: [
      { title: "Password", detail: "Typed or injected at runtime.", secret: true },
      { title: "Random salt + PBKDF2-HMAC-SHA-256", detail: `${ROUNDS} iterations by default.` },
      { title: "AES-256-GCM key", detail: "Derived per payload; never stored." },
      { title: "Encrypt with a random 96-bit IV", detail: "The header is authenticated as additional data." },
    ],
    envelope: [
      { label: "ASAFE", size: "5" },
      { label: "v1", size: "1" },
      { label: "salt", size: "16" },
      { label: "iv", size: "12" },
      { label: "iterations", size: "4" },
      { label: "ciphertext + tag", size: "n + 16" },
    ],
    secrets: ["The password (anyone holding it can decrypt and re-encrypt)."],
    shareable: ["Encrypted .appsafe payloads."],
  },
  {
    eyebrow: "PUBLIC-KEY MODE / ENVELOPE v2",
    title: "A public key encrypts; only its private key decrypts.",
    steps: [
      { title: "Random 256-bit content key", detail: "Encrypts the data once with AES-256-GCM." },
      { title: "Ephemeral P-256 key × recipient public key", detail: "ECDH shared secret, fresh for each recipient." },
      { title: "HKDF-SHA-256 wrap key", detail: "Bound to both public keys and the envelope version." },
      { title: "Wrap the content key per recipient", detail: "AES-256-GCM; the whole header is then authenticated." },
      { title: "Private key unwraps", detail: "Selected by its fingerprint in the header.", secret: true },
    ],
    envelope: [
      { label: "ASAFE", size: "5" },
      { label: "v2", size: "1" },
      { label: "alg", size: "1" },
      { label: "count", size: "1" },
      { label: "iv", size: "12" },
      { label: "recipient × n", size: "141 each" },
      { label: "ciphertext + tag", size: "n + 16" },
    ],
    secrets: ["Each private key (.appsafe/key.txt)."],
    shareable: ["Public keys (.appsafe/key.pub).", "Key fingerprints.", "Encrypted .appsafe payloads."],
  },
];

const COMPARISON: Array<[string, string, string]> = [
  ["Who can encrypt", "Anyone with the password", "Anyone with a public key"],
  ["Who can decrypt", "Anyone with the password", "Only holders of a listed private key"],
  ["Secret material", "The password", "Private keys only"],
  ["Safe to commit", "Ciphertext", "Ciphertext and public keys"],
  ["Multiple people", "Everyone shares one secret", "Up to 16 recipients, each with their own key"],
  ["CI and deployment", "Inject the password; the job can also re-encrypt", "Encrypt-only jobs need no secret; decrypting jobs get a private key"],
  ["Rotation", "Choose a new password and re-encrypt every artifact", "Generate a new key, re-encrypt for it, verify, then retire the old key"],
  ["Recovery if the secret is lost", "Unrecoverable", "Unrecoverable unless another recipient's key still works"],
  ["Best for", "Personal use, quick sharing, small teams", "Teams, CI, committed private apps, least-privilege access"],
];

export function MethodGuide() {
  return (
    <div className="demo-flow-grid">
      {FLOWS.map((flow) => (
        <article className="demo-flow-card" key={flow.eyebrow}>
          <p className="demo-eyebrow">{flow.eyebrow}</p>
          <h3>{flow.title}</h3>
          <ol className="demo-flow-steps">
            {flow.steps.map((step) => (
              <li
                className={step.secret ? "demo-flow-step demo-flow-step-secret" : "demo-flow-step"}
                key={step.title}
              >
                <strong>{step.title}</strong>
                <span>{step.detail}</span>
              </li>
            ))}
          </ol>
          <div className="demo-envelope" aria-label="Envelope layout in bytes">
            {flow.envelope.map((segment) => (
              <span className="demo-envelope-segment" key={segment.label}>
                <strong>{segment.label}</strong>
                <small>{segment.size}</small>
              </span>
            ))}
          </div>
          <div className="demo-custody">
            <div>
              <span className="demo-badge demo-badge-secret">Keep secret</span>
              <ul>
                {flow.secrets.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
            <div>
              <span className="demo-badge demo-badge-safe">Safe to commit</span>
              <ul>
                {flow.shareable.map((item) => <li key={item}>{item}</li>)}
              </ul>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

export function MethodComparison() {
  return (
    <div className="demo-table-wrap">
      <table className="demo-compare-table">
        <thead>
          <tr>
            <th scope="col">Concern</th>
            <th scope="col">Password mode</th>
            <th scope="col">Public-key mode</th>
          </tr>
        </thead>
        <tbody>
          {COMPARISON.map(([concern, password, publicKey]) => (
            <tr key={concern}>
              <th scope="row">{concern}</th>
              <td>{password}</td>
              <td>{publicKey}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
