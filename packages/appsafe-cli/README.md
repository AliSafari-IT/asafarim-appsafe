# @asafarim/appsafe-cli

A Node.js CLI for encrypting configured files and folders with `@asafarim/appsafe`.

The CLI is intentionally separate from the browser-first crypto package. It adds local filesystem access, folder archiving, password input, key files, and `.gitignore` management without adding Node-specific APIs to the reusable crypto core.

Two encryption methods are supported and can be selected globally or per target:

- **Password mode** (default) — one shared password encrypts and decrypts.
- **Public-key mode** — a committed public key encrypts; only the matching private key decrypts.

## Requirements

- Node.js 20 or newer
- A JSON configuration file created with `appsafe init` or supplied manually

## Install

```bash
pnpm add -D @asafarim/appsafe-cli
```

The package provides the `appsafe` executable and programmatic Node.js exports.

## Choosing a method

| Concern | Password mode | Public-key mode |
| --- | --- | --- |
| Who can encrypt | Anyone with the password | Anyone with the public key file |
| Who can decrypt | Anyone with the password | Only holders of a configured private key |
| What to commit | `.appsafe` artifacts and the config | `.appsafe` artifacts, the config, and `.appsafe/key.pub` |
| Never commit | The password | `.appsafe/key.txt` (and decrypted sources) |
| Automation | Needs the password for both directions | Encryption needs no secret; decryption needs a private key |
| Rotation | `appsafe rekey` with a new password | New key pair, `appsafe rekey`, verify, then retire the old key |
| Recovery | Lost password = lost data | Lost private key = lost data, unless another recipient key exists |

## Quick start: public-key mode for a private app

```bash
appsafe init --mode public-key   # creates a version-2 config
appsafe keygen                   # .appsafe/key.pub + .appsafe/key.txt; ignores the private key
# edit appsafe.config.json targets
appsafe encrypt                  # uses only the public key
git add .appsafe/key.pub appsafe.config.json apps/future-private-app.appsafe .gitignore
appsafe decrypt                  # uses the private key
```

Resulting layout:

```text
.appsafe/key.pub                 # safe to commit
.appsafe/key.txt                 # private; ignored and never committed
apps/future-private-app.appsafe  # encrypted artifact committed
apps/future-private-app/         # decrypted local working tree; ignored
```

Encrypt a new private application before its first commit so plaintext never enters Git history.

## Configuration

`appsafe init` creates `appsafe.config.json` with placeholders only when that file does not already exist. Use `--config <path>` for a different location, `--mode public-key` for a public-key starter, or `--dry-run` to preview.

### Version 1 (password only)

Existing version-1 configurations keep working unchanged:

```json
{
  "version": 1,
  "targets": [
    { "source": "./private-config", "encrypted": "./private-config.appsafe", "type": "directory" },
    { "source": "./.env.production", "type": "file" }
  ],
  "encryption": { "iterations": 600000 },
  "gitignore": { "file": "./.gitignore", "ignoreSources": true }
}
```

### Version 2 (selectable modes)

Version 2 adds an `encryption.mode` default and optional per-target `encryption` overrides:

```json
{
  "version": 2,
  "encryption": {
    "mode": "public-key",
    "publicKeyFile": "./.appsafe/key.pub",
    "privateKeyFile": "./.appsafe/key.txt"
  },
  "targets": [
    {
      "source": "./apps/future-private-app",
      "encrypted": "./apps/future-private-app.appsafe",
      "type": "directory"
    },
    {
      "source": "./apps/example/private-file.ts",
      "type": "file",
      "encryption": { "mode": "password", "iterations": 600000 }
    }
  ],
  "gitignore": { "file": "./.gitignore", "ignoreSources": true }
}
```

| Field | Applies to | Description |
| --- | --- | --- |
| `mode` | both | `"password"` (default) or `"public-key"`. |
| `iterations` | password | PBKDF2 iterations, 100,000–2,000,000. |
| `publicKeyFile` | public-key | Path to one recipient public key. |
| `publicKeyFiles` | public-key | Array of recipient public key paths (up to 16). Use instead of `publicKeyFile` for multiple recipients. |
| `privateKeyFile` | public-key | Default private key path used by `decrypt`, `rekey`, and `check`. It is a path, never key material. |

Target settings override global settings field by field. Validation rejects unknown modes, public-key targets without a public key, `iterations` in public-key mode, key files set alongside an explicit password mode, both `publicKeyFile` and `publicKeyFiles`, and version-2 fields in a version-1 config.

Paths are resolved relative to the configuration file. `encrypted` defaults to `source + ".appsafe"`, and `restore` defaults to `source`. Folder targets are archived as ZIP data in memory before encryption, and the artifact must be outside the source directory. Set `type` explicitly when decrypting a regular file that itself contains ZIP data.

Never put passwords or private-key contents in the configuration file.

### Gitignore management

Automatic ignoring is enabled by default. After every target encrypts successfully, `encrypt` adds each source and each configured `privateKeyFile` inside the gitignore directory to `.gitignore`. `keygen` adds the private key before writing it. Public keys and `.appsafe` artifacts stay trackable. Set `"gitignore": false`, `"ignoreSources": false`, or a target's `"ignore": false` to opt out.

## Commands

```bash
appsafe init [--mode password|public-key]
appsafe keygen [--public-key-out <file>] [--private-key-out <file>] [--gitignore <file> | --no-gitignore]
appsafe encrypt [--public-key-file <file>]...
appsafe decrypt [--private-key-file <file> | --private-key-stdin | --private-key-env <name>]
appsafe rekey
appsafe check
```

All commands accept `--config <file>`; `--dry-run` validates and previews without reading secrets or writing files; `--force` is required to replace existing encrypted or restored outputs.

### `keygen`

Writes `.appsafe/key.pub` and `.appsafe/key.txt` by default. The private key file is created with mode `0600` and contains the key plus comment lines with its fingerprint and public key. `keygen` never overwrites an existing private key, even with `--force`; `--force` only replaces an existing public key. Back up the private key before encrypting anything for it.

### `encrypt` and `decrypt`

Each target uses its configured mode. `decrypt` reads the mode from each artifact's header, so mixed configurations work and mode detection never guesses. Only the secrets that are actually needed are requested: no password prompt when every target uses public keys, and no private key when every artifact is password-encrypted.

### `rekey` (migration and rotation)

`rekey` decrypts each existing artifact with its current credentials and re-encrypts it with the target's configured mode and keys:

- password → public-key: switch the config to public-key mode, then `appsafe rekey --password-env OLD`.
- public-key → password: switch the config, then `appsafe rekey --private-key-file old.txt --new-password-env NEW`.
- password rotation: `appsafe rekey --password-env OLD --new-password-env NEW`.
- key rotation: point `publicKeyFile(s)` at the new key, then `appsafe rekey --private-key-file old.txt`.

All artifacts are decrypted and re-encrypted in memory before any file is replaced, and each replacement is atomic. Password outputs are always verified by decrypting them again. Public-key outputs are verified when the supplied private key is one of the new recipients; otherwise the output reports that verification was skipped. Commit or back up artifacts before rekeying so the previous version stays recoverable, and use `--dry-run` to preview mode changes.

### `check`

Validates the config and prints, per target: the configured mode, path status, whether each public key is valid (with fingerprint), whether the private key file exists and is valid, the artifact's payload mode and recipients, and whether the configured private key can decrypt it. Secrets are never printed.

## Secret inputs

| Secret | Interactive | Automation |
| --- | --- | --- |
| Password | Prompted without echo (confirmed when encrypting) | `--password-stdin` or `--password-env <name>` |
| New password (`rekey`) | Prompted and confirmed | `--new-password-env <name>` |
| Private key | `privateKeyFile` from the config | `--private-key-file <file>`, `--private-key-stdin`, or `--private-key-env <name>` |
| Recipients | `publicKeyFile(s)` from the config | `--public-key-file <file>` (repeatable) |

Secrets are never accepted as literal command-line values, because process arguments are visible to other users and shell history. Only one secret can be read from stdin per invocation.

## CI and deployment

Encrypt in CI without any secret:

```yaml
- run: pnpm appsafe encrypt --force
```

Decrypt on a deployment host with a private key from a secret store:

```yaml
- run: pnpm appsafe decrypt --private-key-env APPSAFE_PRIVATE_KEY
  env:
    APPSAFE_PRIVATE_KEY: ${{ secrets.APPSAFE_PRIVATE_KEY }}
```

Password mode automation:

```bash
printf '%s\n' "$APPSAFE_PASSWORD" | appsafe decrypt --password-stdin
appsafe decrypt --password-env APPSAFE_PASSWORD
```

Give each environment its own key pair and encrypt for every environment that needs access (`publicKeyFiles`), so one key can be revoked by re-encrypting without it.

## Key custody, backup, loss, and rotation

- **Custody:** the private key is the only secret in public-key mode. Keep it out of the repository, restrict file permissions, and store copies in a password manager or secret store.
- **Backup:** encrypt for a second offline recovery key (`publicKeyFiles`) so losing one key does not lose data.
- **Loss:** without the password, or without any listed private key, an artifact cannot be decrypted. There is no recovery mechanism.
- **Compromise or rotation:** generate a new key pair, update `publicKeyFile(s)`, run `appsafe rekey` with the old private key, verify with `appsafe check` and a test decrypt, provision the new private key where it is needed, then retire the old key. Artifacts remaining in Git history are still readable with the old key, so treat a compromised key's past ciphertext as exposed.

## Use it as a library

```ts
import {
  decryptConfiguredTargets,
  encryptConfiguredTargets,
  generateKeyFiles,
  loadConfig,
  rekeyConfiguredTargets,
} from "@asafarim/appsafe-cli";

await generateKeyFiles(".appsafe/key.pub", ".appsafe/key.txt");
const loaded = await loadConfig("appsafe.config.json");

await encryptConfiguredTargets(loaded.config, loaded.path, { password });
await decryptConfiguredTargets(loaded.config, loaded.path, { password, privateKey });
```

The credentials argument accepts a password string (as in earlier releases) or `{ password, newPassword, privateKey, publicKeys }` with key text. The exported API also includes `inspectConfiguredTargets`, `resolveConfiguredTargets`, `readPublicKeyFile`, `readPrivateKeyFile`, `extractKey`, `initializeConfig`, and `updateGitignore`.

## Safety behavior

- File outputs are written through a temporary file and renamed into place.
- Folder restores are built in a temporary sibling directory before replacement.
- `init` never overwrites an existing configuration file, and `keygen` never overwrites a private key.
- Existing outputs are never replaced unless `--force` is supplied.
- Symbolic links are rejected for configured sources, folder contents, encrypted inputs, and restore paths.
- Archive extraction rejects absolute paths, parent-directory traversal, duplicate entries, and unsafe path components.
- A private key placed in a public key file is rejected instead of being used or committed.
- Sources are never deleted automatically.
- Passwords and private keys are not logged, printed, or stored by the CLI.
