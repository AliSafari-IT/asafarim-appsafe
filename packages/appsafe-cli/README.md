# @asafarim/appsafe-cli

A Node.js CLI for encrypting configured files and folders with `@asafarim/appsafe`.

The CLI is intentionally separate from the browser-first crypto package. It adds local filesystem access, folder archiving, password input, and `.gitignore` management without adding Node-specific APIs to the reusable crypto core.

## Requirements

- Node.js 20 or newer
- A JSON configuration file created with `appsafe init` or supplied manually

## Install

```bash
pnpm add -D @asafarim/appsafe-cli
```

The package provides the `appsafe` executable and programmatic Node.js exports.

## Use it as a library

Use the same configuration workflow from another Node.js application:

```ts
import {
  encryptConfiguredTargets,
  initializeConfig,
  loadConfig,
} from "@asafarim/appsafe-cli";

await initializeConfig("appsafe.config.json");
const loaded = await loadConfig("appsafe.config.json");
await encryptConfiguredTargets(loaded.config, loaded.path, password);
```

The exported API also includes `decryptConfiguredTargets`, `inspectConfiguredTargets`, `updateGitignore`, and `resolveConfiguredTargets`. Passwords are supplied at runtime and are not stored by the package.

## Configuration

Create a starter configuration with:

```bash
appsafe init
```

This creates `appsafe.config.json` with placeholder values only when that file does not already exist. Existing configuration files are left unchanged. Use `appsafe init --config path/to/appsafe.config.json` for a different location, or `--dry-run` to preview creation without writing.

Edit the generated placeholders before encrypting. The resulting configuration has this shape:

```json
{
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
}
```

`source`, `encrypted`, and `restore` paths are resolved relative to the configuration file. `encrypted` defaults to `source + ".appsafe"`, and `restore` defaults to `source`.

Use `type: "directory"` for folders. Folders are archived as ZIP data in memory before encryption. The encrypted artifact must be outside the source directory; the recommended layout places it beside the source so the source can be ignored without also ignoring the encrypted artifact.

The `type` field is optional during encryption because the CLI checks the filesystem. Set it explicitly when decrypting, especially when a regular file itself contains ZIP data.

Automatic source ignoring is enabled by default. Set `"gitignore": false` or `"ignoreSources": false` to disable it. A target can also opt out with `"ignore": false`.

Do not put passwords in the configuration file.

## Commands

```bash
appsafe init
appsafe encrypt --config appsafe.config.json
appsafe decrypt --config appsafe.config.json
appsafe check --config appsafe.config.json
```

`encrypt` adds each successful source to the configured `.gitignore` file. It updates `.gitignore` only after every target has been encrypted successfully, and repeated runs do not duplicate entries.

Use a dry run to validate paths and preview outputs without reading a password or writing files:

```bash
appsafe encrypt --config appsafe.config.json --dry-run
```

Existing outputs are protected by default. Use `--force` only when replacement is intended:

```bash
appsafe encrypt --config appsafe.config.json --force
appsafe decrypt --config appsafe.config.json --force
```

For automation, supply the password explicitly through stdin or a named environment variable:

```bash
printf '%s\n' "$APPSAFE_PASSWORD" | appsafe encrypt --password-stdin
appsafe encrypt --password-env APPSAFE_PASSWORD
```

Without either option, the CLI prompts without echo and asks for confirmation during encryption.

## Safety behavior

- File outputs are written through a temporary file and renamed into place.
- Folder restores are built in a temporary sibling directory before replacement.
- `init` never overwrites an existing configuration file.
- Existing outputs are never replaced unless `--force` is supplied.
- Symbolic links are rejected for configured sources, folder contents, encrypted inputs, and restore paths.
- Archive extraction rejects absolute paths, parent-directory traversal, duplicate entries, and unsafe path components.
- Sources are never deleted automatically.
- Passwords are not logged or stored by the CLI.
