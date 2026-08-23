#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { relative, resolve, sep } from "node:path";
import {
  AppSafeCliError,
  configFileExists,
  decryptConfiguredTargets,
  encryptConfiguredTargets,
  initializeConfig,
  inspectConfiguredTargets,
  loadConfig,
} from "./index.js";

const VERSION = "0.1.0";
const DEFAULT_CONFIG_FILE = "appsafe.config.json";
const INVOCATION_DIRECTORY = resolve(process.env.INIT_CWD ?? process.cwd());

type Command = "init" | "encrypt" | "decrypt" | "check" | "help";

interface CliOptions {
  configFile: string;
  force: boolean;
  dryRun: boolean;
  passwordStdin: boolean;
  passwordEnvironment?: string;
  help: boolean;
  version: boolean;
}

interface ParsedArguments {
  command: Command;
  options: CliOptions;
}

const USAGE = `Usage:
  appsafe init [options]
  appsafe encrypt [options]
  appsafe decrypt [options]
  appsafe check [options]

Commands:
  init                    Create a starter config if one does not exist.
  encrypt                 Encrypt configured files and folders.
  decrypt                 Decrypt configured files and folders.
  check                   Validate the config and show target status.

Options:
  -c, --config <file>     Config file (default: appsafe.config.json).
      --password-stdin    Read the password from stdin.
      --password-env <n>  Read the password from the named environment variable.
      --dry-run           Validate and show changes without writing files.
      --force              Replace existing encrypted or restored outputs.
  -h, --help              Show this help.
      --version           Show the CLI version.

The password is prompted without echo when no explicit password source is given.
`;

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

  if (first !== "init" && first !== "encrypt" && first !== "decrypt" && first !== "check") {
    throw usageError(`Unknown command: ${first}`);
  }

  const command = first;
  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index];

    switch (argument) {
      case "-c":
      case "--config":
        options.configFile = requireOptionValue(argv, index, argument);
        index += 1;
        break;
      case "--password-stdin":
        options.passwordStdin = true;
        break;
      case "--password-env":
        options.passwordEnvironment = requireOptionValue(argv, index, argument);
        index += 1;
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

  if (
    (command === "init" || command === "check") &&
    (options.passwordStdin || options.passwordEnvironment !== undefined)
  ) {
    throw usageError(`The ${command} command does not read a password.`);
  }

  return { command, options };
}

async function readPasswordFromStdin(): Promise<string> {
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

async function getPassword(command: "encrypt" | "decrypt", options: CliOptions): Promise<string> {
  if (options.passwordStdin) {
    return readPasswordFromStdin();
  }

  if (options.passwordEnvironment !== undefined) {
    const value = process.env[options.passwordEnvironment];
    if (value === undefined) {
      throw new AppSafeCliError(
        `The password environment variable is not set: ${options.passwordEnvironment}`
      );
    }
    return value;
  }

  const password = await promptPassword("Password: ");
  if (command === "encrypt") {
    const confirmation = await promptPassword("Confirm password: ");
    if (password !== confirmation) {
      throw new AppSafeCliError("The passwords do not match.");
    }
  }
  return password;
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
      `${command === "encrypt" ? "Encrypted" : "Decrypted"} ${displayPath(result.source)} -> ${displayPath(destination)}${suffix}\n`
    );
    if (result.gitignoreEntry) {
      process.stdout.write(`Gitignore entry: ${result.gitignoreEntry}\n`);
    }
  }
}

async function runInit(configFile: string, dryRun: boolean): Promise<void> {
  const configPath = resolve(INVOCATION_DIRECTORY, configFile);

  if (await configFileExists(configPath)) {
    process.stdout.write(`Config already exists; left unchanged: ${displayPath(configPath)}\n`);
    return;
  }

  if (dryRun) {
    process.stdout.write(`Would create config: ${displayPath(configPath)}\n`);
    return;
  }

  const created = await initializeConfig(configPath);
  process.stdout.write(
    created
      ? `Created config: ${displayPath(configPath)}\n`
      : `Config already exists; left unchanged: ${displayPath(configPath)}\n`
  );
}

async function runCheck(configFile: string): Promise<void> {
  const loaded = await loadConfig(resolve(INVOCATION_DIRECTORY, configFile));
  const statuses = await inspectConfiguredTargets(loaded.config, loaded.path);

  process.stdout.write(`Config valid: ${displayPath(loaded.path)}\n`);
  for (const status of statuses) {
    process.stdout.write(
      `${displayPath(status.source)} -> ${displayPath(status.encrypted)} ` +
        `(source: ${status.sourceStatus}, encrypted: ${status.encryptedStatus}, restore: ${status.restoreStatus})\n`
    );
  }
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  try {
    const parsed = parseArguments(argv);

    if (parsed.options.version) {
      process.stdout.write(`${VERSION}\n`);
      return 0;
    }

    if (parsed.options.help || parsed.command === "help") {
      process.stdout.write(USAGE);
      return 0;
    }

    if (parsed.command === "init") {
      await runInit(parsed.options.configFile, parsed.options.dryRun);
      return 0;
    }

    if (parsed.command === "check") {
      await runCheck(parsed.options.configFile);
      return 0;
    }

    const loaded = await loadConfig(
      resolve(INVOCATION_DIRECTORY, parsed.options.configFile)
    );
    const password = parsed.options.dryRun
      ? undefined
      : await getPassword(parsed.command, parsed.options);
    const operationOptions = {
      force: parsed.options.force,
      dryRun: parsed.options.dryRun,
    };
    const results = parsed.command === "encrypt"
      ? await encryptConfiguredTargets(loaded.config, loaded.path, password, operationOptions)
      : await decryptConfiguredTargets(loaded.config, loaded.path, password, operationOptions);

    printOperationResults(parsed.command, results, parsed.options.dryRun);
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
