#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { relative, resolve, sep } from "node:path";
import {
  AppSafeCliError,
  DEFAULT_PRIVATE_KEY_FILE,
  DEFAULT_PUBLIC_KEY_FILE,
  configFileExists,
  decryptConfiguredTargets,
  encryptConfiguredTargets,
  extractKey,
  generateKeyFiles,
  initializeConfig,
  inspectConfiguredTargets,
  loadConfig,
  readPrivateKeyFile,
  readPublicKeyFile,
  rekeyConfiguredTargets,
  resolveConfiguredTargets,
  type AppSafeCredentials,
  type AppSafeEncryptionMode,
  type AppSafeKeyStatus,
  type LoadedAppSafeConfig,
} from "./index.js";

const VERSION = "0.5.0";
const DEFAULT_CONFIG_FILE = "appsafe.config.json";
const INVOCATION_DIRECTORY = resolve(process.env.INIT_CWD ?? process.cwd());
const COMMANDS = ["init", "keygen", "encrypt", "decrypt", "rekey", "check"] as const;

type Command = (typeof COMMANDS)[number] | "help";
type SecretCommand = "encrypt" | "decrypt" | "rekey";

interface CliOptions {
  configFile: string;
  force: boolean;
  dryRun: boolean;
  passwordStdin: boolean;
  passwordEnvironment?: string;
  newPasswordEnvironment?: string;
  publicKeyFiles: string[];
  privateKeyFile?: string;
  privateKeyStdin: boolean;
  privateKeyEnvironment?: string;
  mode: AppSafeEncryptionMode;
  publicKeyOut: string;
  privateKeyOut: string;
  gitignoreFile?: string;
  gitignore: boolean;
  help: boolean;
  version: boolean;
}

interface ParsedArguments {
  command: Command;
  options: CliOptions;
}

const USAGE = `Usage:
  appsafe init [options]
  appsafe keygen [options]
  appsafe encrypt [options]
  appsafe decrypt [options]
  appsafe rekey [options]
  appsafe check [options]

Commands:
  init                          Create a starter config if one does not exist.
  keygen                        Generate a public/private key pair.
  encrypt                       Encrypt configured files and folders.
  decrypt                       Decrypt configured files and folders.
  rekey                         Re-encrypt existing artifacts with the configured mode and keys.
  check                         Validate the config and show target, key, and payload status.

General options:
  -c, --config <file>           Config file (default: appsafe.config.json).
      --dry-run                 Validate and show changes without writing files.
      --force                   Replace existing encrypted or restored outputs.
  -h, --help                    Show this help.
      --version                 Show the CLI version.

Password mode (encrypt, decrypt, rekey):
      --password-stdin          Read the password from stdin.
      --password-env <name>     Read the password from the named environment variable.
      --new-password-env <name> Read the new password for rekey from the named variable.

Public-key mode:
      --public-key-file <file>  Encrypt for this public key instead of the configured keys.
                                Repeat for multiple recipients (encrypt, rekey).
      --private-key-file <file> Decrypt with this private key file (decrypt, rekey).
      --private-key-stdin       Read the private key from stdin (decrypt, rekey).
      --private-key-env <name>  Read the private key from the named environment variable.

init options:
      --mode <mode>             Starter config mode: password (default) or public-key.

keygen options:
      --public-key-out <file>   Public key path (default: ${DEFAULT_PUBLIC_KEY_FILE}).
      --private-key-out <file>  Private key path (default: ${DEFAULT_PRIVATE_KEY_FILE}).
      --gitignore <file>        Gitignore file that receives the private key entry (default: .gitignore).
      --no-gitignore            Do not update a gitignore file.

Passwords are prompted without echo when no explicit password source is given.
Private keys are read from the configured privateKeyFile unless another source is given.
Secrets are never accepted as command-line values.
`;

const OPTION_COMMANDS: Record<string, readonly Command[]> = {
  "--password-stdin": ["encrypt", "decrypt", "rekey"],
  "--password-env": ["encrypt", "decrypt", "rekey"],
  "--new-password-env": ["rekey"],
  "--public-key-file": ["encrypt", "rekey"],
  "--private-key-file": ["decrypt", "rekey"],
  "--private-key-stdin": ["decrypt", "rekey"],
  "--private-key-env": ["decrypt", "rekey"],
  "--mode": ["init"],
  "--public-key-out": ["keygen"],
  "--private-key-out": ["keygen"],
  "--gitignore": ["keygen"],
  "--no-gitignore": ["keygen"],
};

function usageError(message: string): AppSafeCliError {
  return new AppSafeCliError(`${message}\n\n${USAGE}`);
}

function requireOptionValue(argv: string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("-")) {
    throw usageError(`${option} requires a value.`);
  }
  return value;
}

function parseArguments(argv: string[]): ParsedArguments {
  const first = argv[0];
  const options: CliOptions = {
    configFile: DEFAULT_CONFIG_FILE,
    force: false,
    dryRun: false,
    passwordStdin: false,
    publicKeyFiles: [],
    privateKeyStdin: false,
    mode: "password",
    publicKeyOut: DEFAULT_PUBLIC_KEY_FILE,
    privateKeyOut: DEFAULT_PRIVATE_KEY_FILE,
    gitignore: true,
    help: false,
    version: false,
  };

  if (first === undefined || first === "help" || first === "--help" || first === "-h") {
    options.help = true;
    return { command: "help", options };
  }

  if (first === "--version") {
    options.version = true;
    return { command: "help", options };
  }

  if (!(COMMANDS as readonly string[]).includes(first)) {
    throw usageError(`Unknown command: ${first}`);
  }

  const command = first as Command;
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];
    const allowed = OPTION_COMMANDS[argument];

    if (allowed && !allowed.includes(command)) {
      throw usageError(`The ${command} command does not accept ${argument}.`);
    }

    const value = (): string => requireOptionValue(argv, index++, argument);

    switch (argument) {
      case "-c":
      case "--config":
        options.configFile = value();
        break;
      case "--password-stdin":
        options.passwordStdin = true;
        break;
      case "--password-env":
        options.passwordEnvironment = value();
        break;
      case "--new-password-env":
        options.newPasswordEnvironment = value();
        break;
      case "--public-key-file":
        options.publicKeyFiles.push(value());
        break;
      case "--private-key-file":
        options.privateKeyFile = value();
        break;
      case "--private-key-stdin":
        options.privateKeyStdin = true;
        break;
      case "--private-key-env":
        options.privateKeyEnvironment = value();
        break;
      case "--mode": {
        const mode = value();
        if (mode !== "password" && mode !== "public-key") {
          throw usageError(`--mode must be "password" or "public-key".`);
        }
        options.mode = mode;
        break;
      }
      case "--public-key-out":
        options.publicKeyOut = value();
        break;
      case "--private-key-out":
        options.privateKeyOut = value();
        break;
      case "--gitignore":
        options.gitignoreFile = value();
        break;
      case "--no-gitignore":
        options.gitignore = false;
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--force":
        options.force = true;
        break;
      case "-h":
      case "--help":
        options.help = true;
        break;
      case "--version":
        options.version = true;
        break;
      default:
        throw usageError(`Unknown option: ${argument}`);
    }
  }

  if (options.passwordStdin && options.passwordEnvironment !== undefined) {
    throw usageError("Choose either --password-stdin or --password-env, not both.");
  }

  const privateKeySources = [
    options.privateKeyFile,
    options.privateKeyStdin || undefined,
    options.privateKeyEnvironment,
  ].filter((source) => source !== undefined);

  if (privateKeySources.length > 1) {
    throw usageError("Choose only one of --private-key-file, --private-key-stdin, or --private-key-env.");
  }

  if (options.passwordStdin && options.privateKeyStdin) {
    throw usageError("Only one secret can be read from stdin; use an environment variable for the other.");
  }

  if (options.gitignoreFile !== undefined && !options.gitignore) {
    throw usageError("Choose either --gitignore or --no-gitignore, not both.");
  }

  return { command, options };
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  const value = Buffer.concat(chunks).toString("utf8");
  return value.endsWith("\r\n")
    ? value.slice(0, -2)
    : value.endsWith("\n")
      ? value.slice(0, -1)
      : value;
}

function readEnvironment(name: string, label: string): string {
  const value = process.env[name];
  if (value === undefined) {
    throw new AppSafeCliError(`The ${label} environment variable is not set: ${name}`);
  }
  return value;
}

function promptPassword(label: string): Promise<string> {
  const input = process.stdin;
  const output = process.stdout;

  if (!input.isTTY || !output.isTTY || typeof input.setRawMode !== "function") {
    throw new AppSafeCliError(
      "No password source is available. Use --password-stdin or --password-env in non-interactive shells."
    );
  }

  return new Promise((resolvePassword, rejectPassword) => {
    const wasRaw = input.isRaw;
    let value = "";

    const cleanup = (): void => {
      input.off("data", onData);
      input.setRawMode(wasRaw ?? false);
      input.pause();
      output.write("\n");
    };

    const finish = (error?: Error): void => {
      cleanup();
      if (error) {
        rejectPassword(error);
      } else {
        resolvePassword(value);
      }
    };

    const onData = (chunk: Buffer): void => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") {
          finish(new AppSafeCliError("Password input cancelled."));
          return;
        }
        if (character === "\u0004") {
          finish(new AppSafeCliError("Password input ended before a password was entered."));
          return;
        }
        if (character === "\r" || character === "\n") {
          finish();
          return;
        }
        if (character === "\b" || character === "\u007f") {
          value = value.slice(0, -1);
          continue;
        }
        value += character;
      }
    };

    output.write(label);
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

async function promptConfirmedPassword(label: string): Promise<string> {
  const password = await promptPassword(`${label}: `);
  const confirmation = await promptPassword(`Confirm ${label.toLowerCase()}: `);
  if (password !== confirmation) {
    throw new AppSafeCliError("The passwords do not match.");
  }
  return password;
}

async function getPassword(command: SecretCommand, options: CliOptions): Promise<string> {
  if (options.passwordStdin) {
    return readStdin();
  }

  if (options.passwordEnvironment !== undefined) {
    return readEnvironment(options.passwordEnvironment, "password");
  }

  return command === "encrypt"
    ? promptConfirmedPassword("Password")
    : promptPassword("Password: ");
}

async function getNewPassword(options: CliOptions): Promise<string> {
  return options.newPasswordEnvironment !== undefined
    ? readEnvironment(options.newPasswordEnvironment, "new password")
    : promptConfirmedPassword("New password");
}

async function getPrivateKey(options: CliOptions): Promise<string | undefined> {
  if (options.privateKeyFile !== undefined) {
    return readPrivateKeyFile(resolve(INVOCATION_DIRECTORY, options.privateKeyFile));
  }

  if (options.privateKeyStdin) {
    return extractKey(await readStdin());
  }

  return options.privateKeyEnvironment === undefined
    ? undefined
    : extractKey(readEnvironment(options.privateKeyEnvironment, "private key"));
}

async function getCredentials(
  command: SecretCommand,
  loaded: LoadedAppSafeConfig,
  options: CliOptions
): Promise<AppSafeCredentials> {
  const targets = resolveConfiguredTargets(loaded.config, loaded.path);
  const payloadModes = command === "encrypt"
    ? []
    : (await inspectConfiguredTargets(loaded.config, loaded.path)).map((status) =>
        typeof status.payload === "object" ? status.payload.mode : undefined
      );
  const needsPassword = command === "encrypt"
    ? targets.some((target) => target.encryption.mode === "password")
    : payloadModes.includes("password");
  const explicitPassword = options.passwordStdin || options.passwordEnvironment !== undefined;
  const credentials: AppSafeCredentials = {
    publicKeys: await Promise.all(
      options.publicKeyFiles.map((file) => readPublicKeyFile(resolve(INVOCATION_DIRECTORY, file)))
    ),
    privateKey: await getPrivateKey(options),
  };

  if (needsPassword || explicitPassword) {
    credentials.password = await getPassword(command, options);
  }

  if (command === "rekey" && targets.some((target) => target.encryption.mode === "password")) {
    credentials.newPassword = await getNewPassword(options);
  }

  return credentials;
}

function displayPath(filePath: string): string {
  const relativePath = relative(INVOCATION_DIRECTORY, filePath);
  const isOutsideInvocationDirectory =
    relativePath === ".." || relativePath.startsWith(`..${sep}`);
  const displayed = isOutsideInvocationDirectory ? filePath : relativePath;
  return displayed.replaceAll("\\", "/") || ".";
}

function printOperationResults(
  command: "encrypt" | "decrypt",
  results: Awaited<ReturnType<typeof encryptConfiguredTargets>>,
  dryRun: boolean
): void {
  for (const result of results) {
    const destination = command === "encrypt" ? result.encrypted : result.restore;
    const suffix = dryRun ? " (dry run)" : "";
    process.stdout.write(
      `${command === "encrypt" ? "Encrypted" : "Decrypted"} ${displayPath(result.source)} -> ${displayPath(destination)} [${result.mode}]${suffix}\n`
    );
    if (result.gitignoreEntry) {
      process.stdout.write(`Gitignore entry: ${result.gitignoreEntry}\n`);
    }
  }
}

async function runInit(options: CliOptions): Promise<void> {
  const configPath = resolve(INVOCATION_DIRECTORY, options.configFile);

  if (await configFileExists(configPath)) {
    process.stdout.write(`Config already exists; left unchanged: ${displayPath(configPath)}\n`);
    return;
  }

  if (options.dryRun) {
    process.stdout.write(`Would create ${options.mode} config: ${displayPath(configPath)}\n`);
    return;
  }

  const created = await initializeConfig(configPath, options.mode);
  process.stdout.write(
    created
      ? `Created ${options.mode} config: ${displayPath(configPath)}\n`
      : `Config already exists; left unchanged: ${displayPath(configPath)}\n`
  );
  if (created && options.mode === "public-key") {
    process.stdout.write("Next: run `appsafe keygen` to create the configured key pair.\n");
  }
}

async function runKeygen(options: CliOptions): Promise<void> {
  const result = await generateKeyFiles(
    resolve(INVOCATION_DIRECTORY, options.publicKeyOut),
    resolve(INVOCATION_DIRECTORY, options.privateKeyOut),
    {
      force: options.force,
      dryRun: options.dryRun,
      gitignoreFile: options.gitignore
        ? resolve(INVOCATION_DIRECTORY, options.gitignoreFile ?? ".gitignore")
        : false,
    }
  );
  const verb = options.dryRun ? "Would write" : "Wrote";

  process.stdout.write(`${verb} public key (safe to commit): ${displayPath(result.publicKeyFile)}\n`);
  process.stdout.write(`${verb} private key (keep secret): ${displayPath(result.privateKeyFile)}\n`);
  if (result.fingerprint) {
    process.stdout.write(`Fingerprint: ${result.fingerprint}\n`);
  }
  if (result.gitignoreEntry && result.gitignoreFile) {
    process.stdout.write(`Gitignore entry: ${result.gitignoreEntry} (${displayPath(result.gitignoreFile)})\n`);
  } else {
    process.stdout.write(
      "Warning: the private key is not covered by a managed gitignore entry. Keep it out of version control.\n"
    );
  }
  if (!options.dryRun) {
    process.stdout.write("Back up the private key securely; artifacts encrypted only for it cannot be recovered without it.\n");
  }
}

function describeKey(label: string, key: AppSafeKeyStatus): string {
  const detail = key.status === "valid" ? `valid, fingerprint ${key.fingerprint}` : key.status;
  return `  ${label}: ${displayPath(key.path)} (${detail})\n`;
}

async function runCheck(configFile: string): Promise<void> {
  const loaded = await loadConfig(resolve(INVOCATION_DIRECTORY, configFile));
  const statuses = await inspectConfiguredTargets(loaded.config, loaded.path);

  process.stdout.write(`Config valid: ${displayPath(loaded.path)} (version ${loaded.config.version})\n`);
  for (const status of statuses) {
    process.stdout.write(
      `${displayPath(status.source)} -> ${displayPath(status.encrypted)} ` +
        `(mode: ${status.encryption.mode}, source: ${status.sourceStatus}, encrypted: ${status.encryptedStatus}, restore: ${status.restoreStatus})\n`
    );

    if (status.encryption.mode === "password") {
      process.stdout.write("  password: supplied at runtime (prompt, --password-stdin, or --password-env)\n");
    }
    for (const key of status.publicKeys) {
      process.stdout.write(describeKey("public key", key));
    }
    if (status.privateKey) {
      process.stdout.write(describeKey("private key", status.privateKey));
    } else if (status.encryption.mode === "public-key") {
      process.stdout.write("  private key: not configured (use --private-key-file, --private-key-stdin, or --private-key-env to decrypt)\n");
    }

    if (status.payload === "invalid") {
      process.stdout.write("  payload: not a valid AppSafe payload\n");
    } else if (status.payload?.mode === "password") {
      process.stdout.write(`  payload: password (${status.payload.iterations} PBKDF2 iterations)\n`);
    } else if (status.payload) {
      const privateFingerprint = status.privateKey?.fingerprint;
      const access = privateFingerprint === undefined
        ? ""
        : status.payload.recipients.includes(privateFingerprint)
          ? ", private key is a recipient"
          : ", private key is NOT a recipient";
      process.stdout.write(
        `  payload: public-key for ${status.payload.recipients.join(", ")}${access}\n`
      );
    }

    if (status.payload && status.payload !== "invalid" && status.payload.mode !== status.encryption.mode) {
      process.stdout.write("  note: payload mode differs from the configured mode; run `appsafe rekey` to migrate it\n");
    }
  }
}

async function runRekey(loaded: LoadedAppSafeConfig, options: CliOptions): Promise<void> {
  const credentials = options.dryRun ? {} : await getCredentials("rekey", loaded, options);
  const results = await rekeyConfiguredTargets(loaded.config, loaded.path, credentials, {
    dryRun: options.dryRun,
  });

  for (const result of results) {
    const status = options.dryRun
      ? "dry run"
      : result.verified
        ? "verified"
        : "written; not verified because no recipient private key was supplied";
    process.stdout.write(
      `Re-encrypted ${displayPath(result.encrypted)} (${result.from} -> ${result.to}, ${status})\n`
    );
  }
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  try {
    const parsed = parseArguments(argv);
    const { command, options } = parsed;

    if (options.version) {
      process.stdout.write(`${VERSION}\n`);
      return 0;
    }

    if (options.help || command === "help") {
      process.stdout.write(USAGE);
      return 0;
    }

    if (command === "init") {
      await runInit(options);
      return 0;
    }

    if (command === "keygen") {
      await runKeygen(options);
      return 0;
    }

    if (command === "check") {
      await runCheck(options.configFile);
      return 0;
    }

    const loaded = await loadConfig(resolve(INVOCATION_DIRECTORY, options.configFile));

    if (command === "rekey") {
      await runRekey(loaded, options);
      return 0;
    }

    const credentials = options.dryRun
      ? undefined
      : await getCredentials(command, loaded, options);
    const operationOptions = {
      force: options.force,
      dryRun: options.dryRun,
    };
    const results = command === "encrypt"
      ? await encryptConfiguredTargets(loaded.config, loaded.path, credentials, operationOptions)
      : await decryptConfiguredTargets(loaded.config, loaded.path, credentials, operationOptions);

    printOperationResults(command, results, options.dryRun);
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`Error: ${message}\n`);
    return 1;
  }
}

const invokedFile = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : undefined;

if (invokedFile === import.meta.url) {
  runCli().then((code) => {
    process.exitCode = code;
  });
}
