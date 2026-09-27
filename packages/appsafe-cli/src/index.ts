import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  AppSafeCryptoError,
  decryptBytes,
  decryptBytesWithPrivateKey,
  encryptBytes,
  encryptBytesForRecipients,
  generateKeyPair,
  getKeyFingerprint,
  getPublicKey,
  inspectAppSafePayload,
  type AppSafeEncryptionMode,
  type AppSafePayloadInfo,
} from "@asafarim/appsafe";
import { unzipSync, zipSync } from "fflate";

const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 2_000_000;
const ZIP_LEVEL = 6;
const PRIVATE_KEY_FILE_MODE = 0o600;
const INITIAL_CONFIGS: Record<AppSafeEncryptionMode, string> = {
  password: `{
  "version": 1,
  "targets": [
    {
      "source": "./path/to/private-file",
      "encrypted": "./path/to/private-file.appsafe",
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
`,
  "public-key": `{
  "version": 2,
  "encryption": {
    "mode": "public-key",
    "publicKeyFile": "./.appsafe/key.pub",
    "privateKeyFile": "./.appsafe/key.txt"
  },
  "targets": [
    {
      "source": "./path/to/private-app",
      "encrypted": "./path/to/private-app.appsafe",
      "type": "directory"
    }
  ],
  "gitignore": {
    "file": "./.gitignore",
    "ignoreSources": true
  }
}
`,
};

export const APP_SAFE_EXTENSION = ".appsafe";
export const DEFAULT_PUBLIC_KEY_FILE = ".appsafe/key.pub";
export const DEFAULT_PRIVATE_KEY_FILE = ".appsafe/key.txt";

export type { AppSafeEncryptionMode, AppSafePayloadInfo };

export type AppSafeTargetType = "file" | "directory";

export interface AppSafeEncryptionSettings {
  mode?: AppSafeEncryptionMode;
  iterations?: number;
  publicKeyFiles?: string[];
  privateKeyFile?: string;
}

export interface AppSafeTarget {
  source: string;
  encrypted?: string;
  restore?: string;
  type?: AppSafeTargetType;
  ignore?: boolean;
  encryption?: AppSafeEncryptionSettings;
}

export interface AppSafeConfig {
  version: 1 | 2;
  targets: AppSafeTarget[];
  encryption?: AppSafeEncryptionSettings;
  gitignore?: {
    file?: string;
    ignoreSources?: boolean;
  } | false;
}

export interface LoadedAppSafeConfig {
  config: AppSafeConfig;
  path: string;
}

export interface AppSafeResolvedEncryption {
  mode: AppSafeEncryptionMode;
  iterations?: number;
  publicKeyFiles: string[];
  privateKeyFile?: string;
}

export interface AppSafeResolvedTarget {
  source: string;
  encrypted: string;
  restore: string;
  requestedType?: AppSafeTargetType;
  ignore: boolean;
  encryption: AppSafeResolvedEncryption;
}

export interface AppSafeCredentials {
  password?: string;
  newPassword?: string;
  privateKey?: string;
  publicKeys?: string[];
}

export interface AppSafeOperationOptions {
  force?: boolean;
  dryRun?: boolean;
}

export interface AppSafeOperationResult {
  source: string;
  encrypted: string;
  restore: string;
  type: AppSafeTargetType | "unknown";
  mode: AppSafeEncryptionMode;
  bytes: number;
  gitignoreEntry?: string;
}

export interface AppSafeRekeyResult {
  encrypted: string;
  from: AppSafeEncryptionMode | "unknown";
  to: AppSafeEncryptionMode;
  verified: boolean;
}

export type AppSafePathStatus = "missing" | "file" | "directory" | "symlink" | "other";

export interface AppSafeKeyStatus {
  path: string;
  status: "valid" | "missing" | "invalid";
  fingerprint?: string;
}

export interface AppSafeTargetStatus extends AppSafeResolvedTarget {
  sourceStatus: AppSafePathStatus;
  encryptedStatus: AppSafePathStatus;
  restoreStatus: AppSafePathStatus;
  publicKeys: AppSafeKeyStatus[];
  privateKey?: AppSafeKeyStatus;
  payload?: AppSafePayloadInfo | "invalid";
}

export interface AppSafeKeygenOptions {
  force?: boolean;
  dryRun?: boolean;
  gitignoreFile?: string | false;
}

export interface AppSafeKeygenResult {
  publicKeyFile: string;
  privateKeyFile: string;
  fingerprint?: string;
  gitignoreFile?: string;
  gitignoreEntry?: string;
}

export class AppSafeCliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppSafeCliError";
  }
}

type FileStats = Awaited<ReturnType<typeof lstat>>;

type KeyCache = Map<string, Promise<string>>;

type PreparedEncryptTarget = AppSafeResolvedTarget & {
  type: AppSafeTargetType;
  sourceStats: FileStats;
  gitignoreEntry?: string;
};

type PreparedDecryptTarget = AppSafeResolvedTarget & {
  encryptedStats: FileStats;
};

function isErrorWithCode(error: unknown, code: string): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as Error & { code?: unknown }).code === code
  );
}

function isAppSafeCliError(error: unknown): error is AppSafeCliError {
  return error instanceof AppSafeCliError;
}

function wrapFileError(action: string, filePath: string, error: unknown): AppSafeCliError {
  if (isAppSafeCliError(error)) {
    return error;
  }

  const message = error instanceof Error ? error.message : String(error);
  return new AppSafeCliError(`${action} ${filePath}: ${message}`);
}

async function tryLstat(filePath: string): Promise<FileStats | undefined> {
  try {
    return await lstat(filePath);
  } catch (error) {
    if (isErrorWithCode(error, "ENOENT")) {
      return undefined;
    }

    throw wrapFileError("Unable to inspect", filePath, error);
  }
}

function pathKey(filePath: string): string {
  return process.platform === "win32" ? filePath.toLowerCase() : filePath;
}

function samePath(left: string, right: string): boolean {
  return pathKey(resolve(left)) === pathKey(resolve(right));
}

function isWithinPath(parent: string, candidate: string): boolean {
  const child = relative(parent, candidate);
  return child === "" || (!isAbsolute(child) && child !== ".." && !child.startsWith(`..${sep}`));
}

function pathStatus(stats: FileStats | undefined): AppSafePathStatus {
  if (!stats) {
    return "missing";
  }

  if (stats.isSymbolicLink()) {
    return "symlink";
  }

  if (stats.isFile()) {
    return "file";
  }

  if (stats.isDirectory()) {
    return "directory";
  }

  return "other";
}

function parseRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AppSafeCliError(`${label} must be an object.`);
  }

  return value as Record<string, unknown>;
}

function parseOptionalString(
  record: Record<string, unknown>,
  key: string,
  label: string
): string | undefined {
  const value = record[key];

  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "string" || value.trim().length === 0) {
    throw new AppSafeCliError(`${label}.${key} must be a non-empty string.`);
  }

  return value;
}

function parseOptionalStringArray(
  record: Record<string, unknown>,
  key: string,
  label: string
): string[] | undefined {
  const value = record[key];

  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value) || value.length === 0) {
    throw new AppSafeCliError(`${label}.${key} must be a non-empty array of strings.`);
  }

  return value.map((item, index) => {
    if (typeof item !== "string" || item.trim().length === 0) {
      throw new AppSafeCliError(`${label}.${key}[${index}] must be a non-empty string.`);
    }
    return item;
  });
}

function parseOptionalBoolean(
  record: Record<string, unknown>,
  key: string,
  label: string
): boolean | undefined {
  const value = record[key];

  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "boolean") {
    throw new AppSafeCliError(`${label}.${key} must be a boolean.`);
  }

  return value;
}

function parseOptionalNumber(
  record: Record<string, unknown>,
  key: string,
  label: string
): number | undefined {
  const value = record[key];

  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new AppSafeCliError(`${label}.${key} must be a finite number.`);
  }

  return value;
}

function parseEncryptionSettings(value: unknown, label: string): AppSafeEncryptionSettings {
  const record = parseRecord(value, label);
  const mode = parseOptionalString(record, "mode", label);
  const publicKeyFile = parseOptionalString(record, "publicKeyFile", label);
  const publicKeyFiles = parseOptionalStringArray(record, "publicKeyFiles", label);

  if (mode !== undefined && mode !== "password" && mode !== "public-key") {
    throw new AppSafeCliError(`${label}.mode must be "password" or "public-key".`);
  }

  if (publicKeyFile !== undefined && publicKeyFiles !== undefined) {
    throw new AppSafeCliError(
      `Use either ${label}.publicKeyFile or ${label}.publicKeyFiles, not both.`
    );
  }

  return {
    mode: mode as AppSafeEncryptionMode | undefined,
    iterations: parseOptionalNumber(record, "iterations", label),
    publicKeyFiles: publicKeyFiles ?? (publicKeyFile === undefined ? undefined : [publicKeyFile]),
    privateKeyFile: parseOptionalString(record, "privateKeyFile", label),
  };
}

function parseConfig(value: unknown): AppSafeConfig {
  const record = parseRecord(value, "The configuration");

  if (record.version !== 1 && record.version !== 2) {
    throw new AppSafeCliError("The configuration version must be 1 or 2.");
  }

  if (!Array.isArray(record.targets) || record.targets.length === 0) {
    throw new AppSafeCliError("The configuration must contain at least one target.");
  }

  const targets = record.targets.map((value, index) => {
    const label = `targets[${index}]`;
    const target = parseRecord(value, label);
    const source = parseOptionalString(target, "source", label);
    const encrypted = parseOptionalString(target, "encrypted", label);
    const restore = parseOptionalString(target, "restore", label);
    const type = parseOptionalString(target, "type", label);
    const ignore = parseOptionalBoolean(target, "ignore", label);

    if (!source) {
      throw new AppSafeCliError(`${label}.source must be provided.`);
    }

    if (type !== undefined && type !== "file" && type !== "directory") {
      throw new AppSafeCliError(`${label}.type must be "file" or "directory".`);
    }

    return {
      source,
      encrypted,
      restore,
      type: type as AppSafeTargetType | undefined,
      ignore,
      encryption: target.encryption === undefined
        ? undefined
        : parseEncryptionSettings(target.encryption, `${label}.encryption`),
    };
  });

  let gitignore: AppSafeConfig["gitignore"];
  if (record.gitignore === false) {
    gitignore = false;
  } else if (record.gitignore !== undefined) {
    const gitignoreRecord = parseRecord(record.gitignore, "gitignore");
    gitignore = {
      file: parseOptionalString(gitignoreRecord, "file", "gitignore"),
      ignoreSources: parseOptionalBoolean(gitignoreRecord, "ignoreSources", "gitignore"),
    };
  }

  return {
    version: record.version,
    targets,
    encryption: record.encryption === undefined
      ? undefined
      : parseEncryptionSettings(record.encryption, "encryption"),
    gitignore,
  };
}

export async function loadConfig(configFile: string): Promise<LoadedAppSafeConfig> {
  const configPath = resolve(configFile);
  let raw: string;

  try {
    raw = await readFile(configPath, "utf8");
  } catch (error) {
    throw wrapFileError("Unable to read", configPath, error);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new AppSafeCliError(`Invalid JSON in ${configPath}: ${message}`);
  }

  const config = parseConfig(parsed);
  validateEncryptionSettings(config);

  return {
    config,
    path: configPath,
  };
}

export async function configFileExists(configFile: string): Promise<boolean> {
  return (await tryLstat(resolve(configFile))) !== undefined;
}

export async function initializeConfig(
  configFile: string,
  mode: AppSafeEncryptionMode = "password"
): Promise<boolean> {
  const configPath = resolve(configFile);

  if (await configFileExists(configPath)) {
    return false;
  }

  try {
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, INITIAL_CONFIGS[mode], { flag: "wx" });
    return true;
  } catch (error) {
    if (isErrorWithCode(error, "EEXIST")) {
      return false;
    }

    throw wrapFileError("Unable to create", configPath, error);
  }
}

function resolveEncryption(
  config: AppSafeConfig,
  target: AppSafeTarget,
  configDirectory: string
): AppSafeResolvedEncryption {
  const global = config.encryption ?? {};
  const local = target.encryption ?? {};
  const mode = local.mode ?? global.mode ?? "password";
  const privateKeyFile = local.privateKeyFile ?? global.privateKeyFile;

  return {
    mode,
    iterations: mode === "password" ? local.iterations ?? global.iterations : undefined,
    publicKeyFiles: (local.publicKeyFiles ?? global.publicKeyFiles ?? []).map((file) =>
      resolve(configDirectory, file)
    ),
    privateKeyFile: privateKeyFile === undefined
      ? undefined
      : resolve(configDirectory, privateKeyFile),
  };
}

export function resolveConfiguredTargets(
  config: AppSafeConfig,
  configFile: string
): AppSafeResolvedTarget[] {
  const configDirectory = dirname(resolve(configFile));

  return config.targets.map((target) => {
    const source = resolve(configDirectory, target.source);
    const encrypted = resolve(
      configDirectory,
      target.encrypted ?? `${source}${APP_SAFE_EXTENSION}`
    );
    const restore = resolve(configDirectory, target.restore ?? target.source);

    return {
      source,
      encrypted,
      restore,
      requestedType: target.type,
      ignore: target.ignore !== false,
      encryption: resolveEncryption(config, target, configDirectory),
    };
  });
}

function validateEncryptionSettings(config: AppSafeConfig): void {
  const levels: Array<[string, AppSafeEncryptionSettings | undefined]> = [
    ["encryption", config.encryption],
    ...config.targets.map((target, index): [string, AppSafeEncryptionSettings | undefined] => [
      `targets[${index}].encryption`,
      target.encryption,
    ]),
  ];

  for (const [label, settings] of levels) {
    if (!settings) {
      continue;
    }

    const { mode, iterations, publicKeyFiles, privateKeyFile } = settings;
    const hasKeys = publicKeyFiles !== undefined || privateKeyFile !== undefined;

    if (config.version === 1 && (mode !== undefined || hasKeys || label !== "encryption")) {
      throw new AppSafeCliError(
        `${label} uses encryption modes, key files, or target overrides, which require configuration version 2.`
      );
    }

    if (
      iterations !== undefined &&
      (!Number.isSafeInteger(iterations) ||
        iterations < MIN_PBKDF2_ITERATIONS ||
        iterations > MAX_PBKDF2_ITERATIONS)
    ) {
      throw new AppSafeCliError(
        `${label}.iterations must be an integer between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
      );
    }

    if (mode === "password" && hasKeys) {
      throw new AppSafeCliError(`${label} uses password mode and cannot set key files.`);
    }

    if (mode === "public-key" && iterations !== undefined) {
      throw new AppSafeCliError(`${label} uses public-key mode and cannot set iterations.`);
    }
  }

  config.targets.forEach((target, index) => {
    if (
      resolveEncryption(config, target, ".").mode === "public-key" &&
      !(target.encryption?.publicKeyFiles ?? config.encryption?.publicKeyFiles)?.length
    ) {
      throw new AppSafeCliError(
        `targets[${index}] uses public-key mode but no publicKeyFile is configured.`
      );
    }
  });
}

function getGitignorePath(
  config: AppSafeConfig,
  configFile: string
): string | undefined {
  if (config.gitignore === false || config.gitignore?.ignoreSources === false) {
    return undefined;
  }

  return resolve(
    dirname(resolve(configFile)),
    config.gitignore?.file ?? ".gitignore"
  );
}

function gitignoreEntryFor(
  filePath: string,
  directory: boolean,
  gitignorePath: string
): string | undefined {
  const relativePath = relative(dirname(gitignorePath), filePath);

  if (
    relativePath === "" ||
    isAbsolute(relativePath) ||
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`)
  ) {
    return undefined;
  }

  const normalized = relativePath.split(sep).join("/");
  return directory ? `/${normalized}/` : `/${normalized}`;
}

function getGitignoreEntry(
  source: string,
  sourceStats: FileStats,
  gitignorePath: string
): string {
  const entry = gitignoreEntryFor(source, sourceStats.isDirectory(), gitignorePath);

  if (!entry) {
    throw new AppSafeCliError(
      `The source path ${source} must be inside the directory containing ${gitignorePath}.`
    );
  }

  return entry;
}

async function prepareEncryptTargets(
  config: AppSafeConfig,
  configFile: string,
  options: AppSafeOperationOptions
): Promise<{
  targets: PreparedEncryptTarget[];
  gitignorePath?: string;
  gitignoreEntries: string[];
}> {
  validateEncryptionSettings(config);
  const resolvedTargets = resolveConfiguredTargets(config, configFile);
  const prepared: PreparedEncryptTarget[] = [];
  const outputPaths = new Set<string>();

  for (const target of resolvedTargets) {
    const sourceStats = await tryLstat(target.source);

    if (!sourceStats) {
      throw new AppSafeCliError(`The source path does not exist: ${target.source}`);
    }

    if (sourceStats.isSymbolicLink()) {
      throw new AppSafeCliError(`Symbolic-link sources are not supported: ${target.source}`);
    }

    const type: AppSafeTargetType = sourceStats.isDirectory()
      ? "directory"
      : sourceStats.isFile()
        ? "file"
        : (() => {
            throw new AppSafeCliError(`The source path is not a file or directory: ${target.source}`);
          })();

    if (target.requestedType !== undefined && target.requestedType !== type) {
      throw new AppSafeCliError(
        `Target type mismatch for ${target.source}: expected ${target.requestedType}, found ${type}.`
      );
    }

    if (samePath(target.source, target.encrypted)) {
      throw new AppSafeCliError(`The encrypted output cannot equal the source: ${target.source}`);
    }

    if (type === "directory" && isWithinPath(target.source, target.encrypted)) {
      throw new AppSafeCliError(
        `The encrypted output must be outside the source directory: ${target.encrypted}`
      );
    }

    const outputKey = pathKey(target.encrypted);
    if (outputPaths.has(outputKey)) {
      throw new AppSafeCliError(`Multiple targets use the same encrypted output: ${target.encrypted}`);
    }
    outputPaths.add(outputKey);

    const outputStats = await tryLstat(target.encrypted);
    if (outputStats?.isSymbolicLink() || outputStats?.isDirectory()) {
      throw new AppSafeCliError(
        `The encrypted output must be a regular file path: ${target.encrypted}`
      );
    }

    if (outputStats && !options.force && !options.dryRun) {
      throw new AppSafeCliError(
        `The encrypted output already exists: ${target.encrypted}. Use --force to replace it.`
      );
    }

    prepared.push({
      ...target,
      type,
      sourceStats,
    });
  }

  const sourcePaths = new Set(prepared.map((target) => pathKey(target.source)));

  for (const target of prepared) {
    if (sourcePaths.has(pathKey(target.encrypted))) {
      throw new AppSafeCliError(
        `An encrypted output cannot replace a configured source path: ${target.encrypted}`
      );
    }

    if (
      prepared.some(
        (other) =>
          other.type === "directory" &&
          isWithinPath(other.source, target.encrypted)
      )
    ) {
      throw new AppSafeCliError(
        `An encrypted output cannot be inside any configured source directory: ${target.encrypted}`
      );
    }
  }

  const gitignorePath = getGitignorePath(config, configFile);
  const gitignoreEntries: string[] = [];

  if (gitignorePath) {
    for (const target of prepared) {
      if (target.ignore) {
        const entry = getGitignoreEntry(target.source, target.sourceStats, gitignorePath);
        target.gitignoreEntry = entry;
        gitignoreEntries.push(entry);
      }

      const privateKeyEntry = target.encryption.privateKeyFile
        ? gitignoreEntryFor(target.encryption.privateKeyFile, false, gitignorePath)
        : undefined;
      if (privateKeyEntry) {
        gitignoreEntries.push(privateKeyEntry);
      }
    }
  }

  return {
    targets: prepared,
    gitignorePath,
    gitignoreEntries,
  };
}

async function prepareDecryptTargets(
  config: AppSafeConfig,
  configFile: string,
  options: AppSafeOperationOptions
): Promise<PreparedDecryptTarget[]> {
  const resolvedTargets = resolveConfiguredTargets(config, configFile);
  const encryptedPaths = new Set<string>();
  const restorePaths = new Set<string>();
  const prepared: PreparedDecryptTarget[] = [];

  for (const target of resolvedTargets) {
    const encryptedStats = await tryLstat(target.encrypted);

    if (!encryptedStats) {
      throw new AppSafeCliError(`The encrypted file does not exist: ${target.encrypted}`);
    }

    if (encryptedStats.isSymbolicLink() || !encryptedStats.isFile()) {
      throw new AppSafeCliError(`The encrypted path must be a regular file: ${target.encrypted}`);
    }

    if (samePath(target.encrypted, target.restore)) {
      throw new AppSafeCliError(`The restore path cannot equal the encrypted file: ${target.encrypted}`);
    }

    const encryptedKey = pathKey(target.encrypted);
    if (encryptedPaths.has(encryptedKey)) {
      throw new AppSafeCliError(`Multiple targets use the same encrypted file: ${target.encrypted}`);
    }
    encryptedPaths.add(encryptedKey);

    const restoreKey = pathKey(target.restore);
    if (restorePaths.has(restoreKey)) {
      throw new AppSafeCliError(`Multiple targets use the same restore path: ${target.restore}`);
    }
    restorePaths.add(restoreKey);

    const restoreStats = await tryLstat(target.restore);
    if (restoreStats?.isSymbolicLink()) {
      throw new AppSafeCliError(`Symbolic-link restore paths are not supported: ${target.restore}`);
    }

    if (
      restoreStats &&
      target.requestedType !== undefined &&
      ((target.requestedType === "file" && !restoreStats.isFile()) ||
        (target.requestedType === "directory" && !restoreStats.isDirectory()))
    ) {
      throw new AppSafeCliError(
        `The restore path type does not match target ${target.restore}.`
      );
    }

    if (restoreStats && !options.force && !options.dryRun) {
      throw new AppSafeCliError(
        `The restore path already exists: ${target.restore}. Use --force to replace it.`
      );
    }

    prepared.push({
      ...target,
      encryptedStats,
    });
  }

  for (const target of prepared) {
    if (encryptedPaths.has(pathKey(target.restore))) {
      throw new AppSafeCliError(
        `A restore path cannot replace a configured encrypted input: ${target.restore}`
      );
    }

    if (
      target.requestedType === "directory" &&
      prepared.some((other) => isWithinPath(target.restore, other.encrypted))
    ) {
      throw new AppSafeCliError(
        `A folder restore path cannot contain a configured encrypted input: ${target.restore}`
      );
    }
  }

  return prepared;
}

async function readBytes(filePath: string): Promise<Uint8Array> {
  try {
    return new Uint8Array(await readFile(filePath));
  } catch (error) {
    throw wrapFileError("Unable to read", filePath, error);
  }
}

export function extractKey(text: string): string {
  const lines = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

  if (lines.length !== 1) {
    throw new AppSafeCliError("Key input must contain exactly one AppSafe key.");
  }

  return lines[0];
}

async function readKeyFile(filePath: string): Promise<string> {
  const stats = await tryLstat(filePath);

  if (!stats) {
    throw new AppSafeCliError(`The key file does not exist: ${filePath}`);
  }

  if (!stats.isFile()) {
    throw new AppSafeCliError(`The key file must be a regular file: ${filePath}`);
  }

  try {
    return extractKey(await readFile(filePath, "utf8"));
  } catch (error) {
    throw isAppSafeCliError(error)
      ? new AppSafeCliError(`${error.message.slice(0, -1)}: ${filePath}`)
      : wrapFileError("Unable to read", filePath, error);
  }
}

function isPrivateKey(key: string): boolean {
  try {
    getPublicKey(key);
    return true;
  } catch {
    return false;
  }
}

export async function readPublicKeyFile(filePath: string): Promise<string> {
  const key = await readKeyFile(filePath);

  if (isPrivateKey(key)) {
    throw new AppSafeCliError(
      `The public key file contains a private key. Move it somewhere private and never commit it: ${filePath}`
    );
  }

  try {
    await getKeyFingerprint(key);
  } catch {
    throw new AppSafeCliError(`The file is not a valid AppSafe public key: ${filePath}`);
  }

  return key;
}

export async function readPrivateKeyFile(filePath: string): Promise<string> {
  const key = await readKeyFile(filePath);

  if (!isPrivateKey(key)) {
    throw new AppSafeCliError(`The file is not a valid AppSafe private key: ${filePath}`);
  }

  return key;
}

function cachedKey(
  cache: KeyCache,
  filePath: string,
  reader: (filePath: string) => Promise<string>
): Promise<string> {
  const key = pathKey(filePath);
  let value = cache.get(key);

  if (!value) {
    value = reader(filePath);
    cache.set(key, value);
  }

  return value;
}

function toCredentials(value: string | AppSafeCredentials | undefined): AppSafeCredentials {
  return typeof value === "string" ? { password: value } : value ?? {};
}

async function publicKeysFor(
  target: AppSafeResolvedTarget,
  credentials: AppSafeCredentials,
  cache: KeyCache
): Promise<string[]> {
  if (credentials.publicKeys?.length) {
    return credentials.publicKeys.map(extractKey);
  }

  if (target.encryption.publicKeyFiles.length === 0) {
    throw new AppSafeCliError(`No public key is configured for ${target.source}.`);
  }

  return Promise.all(
    target.encryption.publicKeyFiles.map((file) => cachedKey(cache, file, readPublicKeyFile))
  );
}

async function privateKeyFor(
  target: AppSafeResolvedTarget,
  credentials: AppSafeCredentials,
  cache: KeyCache
): Promise<string> {
  if (credentials.privateKey !== undefined) {
    return extractKey(credentials.privateKey);
  }

  if (!target.encryption.privateKeyFile) {
    throw new AppSafeCliError(
      `A private key is required to decrypt ${target.encrypted}. Configure privateKeyFile or supply a private key.`
    );
  }

  return cachedKey(cache, target.encryption.privateKeyFile, readPrivateKeyFile);
}

function inspectPayload(encrypted: Uint8Array, filePath: string): AppSafePayloadInfo {
  try {
    return inspectAppSafePayload(encrypted);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new AppSafeCliError(`${message.slice(0, -1)}: ${filePath}`);
  }
}

async function withTargetContext<T>(filePath: string, operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof AppSafeCryptoError) {
      throw new AppSafeCliError(`${error.message.slice(0, -1)}: ${filePath}`);
    }
    throw error;
  }
}

type PayloadDecryptor = () => Promise<Uint8Array>;

async function prepareDecryption(
  target: AppSafeResolvedTarget,
  encrypted: Uint8Array,
  credentials: AppSafeCredentials,
  cache: KeyCache
): Promise<{ info: AppSafePayloadInfo; decrypt: PayloadDecryptor }> {
  const info = inspectPayload(encrypted, target.encrypted);

  if (info.mode === "password") {
    const password = credentials.password;
    if (password === undefined) {
      throw new AppSafeCliError(`A decryption password is required for ${target.encrypted}.`);
    }
    return {
      info,
      decrypt: () => withTargetContext(target.encrypted, () => decryptBytes(encrypted, password)),
    };
  }

  const privateKey = await privateKeyFor(target, credentials, cache);
  return {
    info,
    decrypt: () =>
      withTargetContext(target.encrypted, () => decryptBytesWithPrivateKey(encrypted, privateKey)),
  };
}

type PayloadEncryptor = (plaintext: Uint8Array) => Promise<Uint8Array>;

async function prepareEncryption(
  target: AppSafeResolvedTarget,
  credentials: AppSafeCredentials,
  cache: KeyCache,
  password = credentials.password
): Promise<PayloadEncryptor> {
  if (target.encryption.mode === "password") {
    if (password === undefined) {
      throw new AppSafeCliError("An encryption password is required.");
    }
    const options = target.encryption.iterations === undefined
      ? undefined
      : { iterations: target.encryption.iterations };
    return (plaintext) => encryptBytes(plaintext, password, options);
  }

  const publicKeys = await publicKeysFor(target, credentials, cache);
  return (plaintext) =>
    withTargetContext(target.source, () => encryptBytesForRecipients(plaintext, publicKeys));
}

async function collectDirectoryEntries(
  root: string
): Promise<Record<string, Uint8Array>> {
  const entries: Record<string, Uint8Array> = {};

  async function visit(directory: string, prefix: string): Promise<void> {
    let children;
    try {
      children = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      throw wrapFileError("Unable to read directory", directory, error);
    }

    children.sort((left, right) => left.name.localeCompare(right.name));

    for (const child of children) {
      const childPath = join(directory, child.name);
      const entryPath = prefix ? `${prefix}/${child.name}` : child.name;

      if (child.isSymbolicLink()) {
        throw new AppSafeCliError(`Symbolic links inside folders are not supported: ${childPath}`);
      }

      if (child.isDirectory()) {
        entries[`${entryPath}/`] = new Uint8Array();
        await visit(childPath, entryPath);
        continue;
      }

      if (!child.isFile()) {
        throw new AppSafeCliError(`Unsupported filesystem entry: ${childPath}`);
      }

      entries[entryPath] = await readBytes(childPath);
    }
  }

  await visit(root, "");
  return entries;
}

async function createFolderArchive(source: string): Promise<Uint8Array> {
  try {
    return zipSync(await collectDirectoryEntries(source), { level: ZIP_LEVEL });
  } catch (error) {
    if (isAppSafeCliError(error)) {
      throw error;
    }

    throw wrapFileError("Unable to archive directory", source, error);
  }
}

async function writeFileAtomic(
  filePath: string,
  data: Uint8Array | string,
  force: boolean,
  mode?: number
): Promise<void> {
  const directory = dirname(filePath);
  const temporaryPath = join(
    directory,
    `.${basename(filePath)}.${randomUUID()}.tmp`
  );
  let backupPath: string | undefined;

  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryPath, data, { flag: "wx", mode });

    const existing = await tryLstat(filePath);
    if (existing) {
      if (existing.isSymbolicLink() || existing.isDirectory()) {
        throw new AppSafeCliError(`The output path is not a regular file: ${filePath}`);
      }

      if (!force) {
        throw new AppSafeCliError(
          `The output path already exists: ${filePath}. Use --force to replace it.`
        );
      }

      backupPath = join(
        directory,
        `.${basename(filePath)}.${randomUUID()}.bak`
      );
      await rename(filePath, backupPath);
    }

    await rename(temporaryPath, filePath);

    if (backupPath) {
      await rm(backupPath, { force: true });
      backupPath = undefined;
    }
  } catch (error) {
    if (backupPath) {
      const current = await tryLstat(filePath);
      if (!current) {
        try {
          await rename(backupPath, filePath);
          backupPath = undefined;
        } catch {
          return Promise.reject(
            wrapFileError("Unable to restore the previous output", filePath, error)
          );
        }
      }
    }

    throw wrapFileError("Unable to write", filePath, error);
  } finally {
    await rm(temporaryPath, { force: true });
    if (backupPath) {
      await rm(backupPath, { force: true });
    }
  }
}

function normalizeArchiveEntry(root: string, entryName: string): {
  path: string;
  directory: boolean;
} {
  const normalized = entryName.replaceAll("\\", "/");
  const directory = normalized.endsWith("/");
  const value = directory ? normalized.slice(0, -1) : normalized;

  if (
    value.length === 0 ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    value.includes("\0")
  ) {
    throw new AppSafeCliError(`Unsafe archive entry: ${entryName}`);
  }

  const parts = value.split("/");
  if (parts.some((part) => part.length === 0 || part === "." || part === "..")) {
    throw new AppSafeCliError(`Unsafe archive entry: ${entryName}`);
  }

  const path = resolve(root, ...parts);
  if (!isWithinPath(root, path) || samePath(root, path)) {
    throw new AppSafeCliError(`Unsafe archive entry: ${entryName}`);
  }

  return { path, directory };
}

async function replaceDirectory(
  temporaryDirectory: string,
  destination: string,
  force: boolean
): Promise<void> {
  const directory = dirname(destination);
  let backupPath: string | undefined;

  try {
    const existing = await tryLstat(destination);
    if (existing) {
      if (existing.isSymbolicLink()) {
        throw new AppSafeCliError(`The restore path is a symbolic link: ${destination}`);
      }

      if (!force) {
        throw new AppSafeCliError(
          `The restore path already exists: ${destination}. Use --force to replace it.`
        );
      }

      backupPath = join(
        directory,
        `.${basename(destination)}.${randomUUID()}.bak`
      );
      await rename(destination, backupPath);
    }

    await rename(temporaryDirectory, destination);

    if (backupPath) {
      await rm(backupPath, { recursive: true, force: true });
      backupPath = undefined;
    }
  } catch (error) {
    if (backupPath) {
      const current = await tryLstat(destination);
      if (!current) {
        try {
          await rename(backupPath, destination);
          backupPath = undefined;
        } catch {
          return Promise.reject(
            wrapFileError("Unable to restore the previous directory", destination, error)
          );
        }
      }
    }

    throw wrapFileError("Unable to restore directory", destination, error);
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
    if (backupPath) {
      await rm(backupPath, { recursive: true, force: true });
    }
  }
}

async function extractFolderArchive(
  archive: Uint8Array,
  destination: string,
  force: boolean
): Promise<void> {
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(archive);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new AppSafeCliError(`Unable to open the encrypted folder archive: ${message}`);
  }

  const parentDirectory = dirname(destination);
  await mkdir(parentDirectory, { recursive: true });
  const temporaryDirectory = await mkdtemp(
    join(parentDirectory, `.${basename(destination)}.appsafe-`)
  );
  const seen = new Set<string>();

  try {
    for (const entryName of Object.keys(entries).sort()) {
      const entry = normalizeArchiveEntry(temporaryDirectory, entryName);
      const key = pathKey(entry.path);

      if (seen.has(key)) {
        throw new AppSafeCliError(`Duplicate archive entry: ${entryName}`);
      }
      seen.add(key);

      if (entry.directory) {
        await mkdir(entry.path, { recursive: true });
        continue;
      }

      await mkdir(dirname(entry.path), { recursive: true });
      await writeFile(entry.path, entries[entryName], { flag: "wx" });
    }
  } catch (error) {
    throw wrapFileError("Unable to extract archive", destination, error);
  }

  await replaceDirectory(temporaryDirectory, destination, force);
}

export function isZipPayload(input: Uint8Array): boolean {
  return (
    input.length >= 4 &&
    input[0] === 0x50 &&
    input[1] === 0x4b &&
    ((input[2] === 0x03 && input[3] === 0x04) ||
      (input[2] === 0x05 && input[3] === 0x06) ||
      (input[2] === 0x07 && input[3] === 0x08))
  );
}

export async function updateGitignore(
  gitignorePath: string,
  entries: string[]
): Promise<string[]> {
  const uniqueEntries = [...new Set(entries)];
  if (uniqueEntries.length === 0) {
    return [];
  }

  let current = "";
  try {
    current = await readFile(gitignorePath, "utf8");
  } catch (error) {
    if (!isErrorWithCode(error, "ENOENT")) {
      throw wrapFileError("Unable to read", gitignorePath, error);
    }
  }

  const eol = current.includes("\r\n") ? "\r\n" : "\n";
  const existingEntries = new Set(
    current
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
  );
  const additions = uniqueEntries.filter((entry) => !existingEntries.has(entry));

  if (additions.length === 0) {
    return [];
  }

  let next = current;
  if (next.length > 0 && !next.endsWith("\n") && !next.endsWith("\r")) {
    next += eol;
  }
  next += `${additions.join(eol)}${eol}`;

  await writeFileAtomic(gitignorePath, next, true);
  return additions;
}

export async function encryptConfiguredTargets(
  config: AppSafeConfig,
  configFile: string,
  credentials: string | AppSafeCredentials | undefined,
  options: AppSafeOperationOptions = {}
): Promise<AppSafeOperationResult[]> {
  const prepared = await prepareEncryptTargets(config, configFile, options);
  const result = (target: PreparedEncryptTarget, bytes: number): AppSafeOperationResult => ({
    source: target.source,
    encrypted: target.encrypted,
    restore: target.restore,
    type: target.type,
    mode: target.encryption.mode,
    bytes,
    gitignoreEntry: target.gitignoreEntry,
  });

  if (options.dryRun) {
    return prepared.targets.map((target) => result(target, 0));
  }

  const resolvedCredentials = toCredentials(credentials);
  const keyCache: KeyCache = new Map();
  const encryptors = await Promise.all(
    prepared.targets.map((target) => prepareEncryption(target, resolvedCredentials, keyCache))
  );
  const results: AppSafeOperationResult[] = [];

  for (const [index, target] of prepared.targets.entries()) {
    const input = target.type === "directory"
      ? await createFolderArchive(target.source)
      : await readBytes(target.source);
    const encrypted = await encryptors[index](input);
    await writeFileAtomic(target.encrypted, encrypted, options.force === true);
    results.push(result(target, encrypted.byteLength));
  }

  if (prepared.gitignorePath && prepared.gitignoreEntries.length > 0) {
    await updateGitignore(prepared.gitignorePath, prepared.gitignoreEntries);
  }

  return results;
}

export async function decryptConfiguredTargets(
  config: AppSafeConfig,
  configFile: string,
  credentials: string | AppSafeCredentials | undefined,
  options: AppSafeOperationOptions = {}
): Promise<AppSafeOperationResult[]> {
  const prepared = await prepareDecryptTargets(config, configFile, options);

  if (options.dryRun) {
    return prepared.map((target) => ({
      source: target.source,
      encrypted: target.encrypted,
      restore: target.restore,
      type: target.requestedType ?? "unknown",
      mode: target.encryption.mode,
      bytes: 0,
    }));
  }

  const resolvedCredentials = toCredentials(credentials);
  const keyCache: KeyCache = new Map();
  const decryptions = [];
  for (const target of prepared) {
    const encrypted = await readBytes(target.encrypted);
    decryptions.push(await prepareDecryption(target, encrypted, resolvedCredentials, keyCache));
  }

  const results: AppSafeOperationResult[] = [];

  for (const [index, target] of prepared.entries()) {
    const { info, decrypt } = decryptions[index];
    const decrypted = await decrypt();
    const type = target.requestedType ?? (isZipPayload(decrypted) ? "directory" : "file");

    if (type === "directory") {
      if (!isZipPayload(decrypted)) {
        throw new AppSafeCliError(
          `The decrypted payload is not a ZIP folder archive: ${target.encrypted}`
        );
      }
      await extractFolderArchive(decrypted, target.restore, options.force === true);
    } else {
      await writeFileAtomic(target.restore, decrypted, options.force === true);
    }

    results.push({
      source: target.source,
      encrypted: target.encrypted,
      restore: target.restore,
      type,
      mode: info.mode,
      bytes: decrypted.byteLength,
    });
  }

  return results;
}

export async function rekeyConfiguredTargets(
  config: AppSafeConfig,
  configFile: string,
  credentials: AppSafeCredentials,
  options: Pick<AppSafeOperationOptions, "dryRun"> = {}
): Promise<AppSafeRekeyResult[]> {
  validateEncryptionSettings(config);
  const targets = resolveConfiguredTargets(config, configFile);
  const encryptedPaths = new Set<string>();
  const payloads: Uint8Array[] = [];

  for (const target of targets) {
    const stats = await tryLstat(target.encrypted);
    if (!stats || stats.isSymbolicLink() || !stats.isFile()) {
      throw new AppSafeCliError(`The encrypted path must be an existing regular file: ${target.encrypted}`);
    }

    const key = pathKey(target.encrypted);
    if (encryptedPaths.has(key)) {
      throw new AppSafeCliError(`Multiple targets use the same encrypted file: ${target.encrypted}`);
    }
    encryptedPaths.add(key);
    payloads.push(await readBytes(target.encrypted));
  }

  if (options.dryRun) {
    return targets.map((target, index) => ({
      encrypted: target.encrypted,
      from: inspectPayload(payloads[index], target.encrypted).mode,
      to: target.encryption.mode,
      verified: false,
    }));
  }

  const keyCache: KeyCache = new Map();
  const ownFingerprint = credentials.privateKey === undefined
    ? undefined
    : await getKeyFingerprint(getPublicKey(extractKey(credentials.privateKey)));
  const replacements: Array<{ result: AppSafeRekeyResult; payload: Uint8Array }> = [];

  for (const [index, target] of targets.entries()) {
    const current = await prepareDecryption(target, payloads[index], credentials, keyCache);
    const newPassword = credentials.newPassword ?? credentials.password;
    const encrypt = await prepareEncryption(target, credentials, keyCache, newPassword);
    const plaintext = await current.decrypt();
    const payload = await encrypt(plaintext);
    const info = inspectAppSafePayload(payload);
    let verified = false;

    if (info.mode === "password" && newPassword !== undefined) {
      verified = sameBytes(await decryptBytes(payload, newPassword), plaintext);
    } else if (info.mode === "public-key" && ownFingerprint && info.recipients.includes(ownFingerprint)) {
      const privateKey = extractKey(credentials.privateKey as string);
      verified = sameBytes(await decryptBytesWithPrivateKey(payload, privateKey), plaintext);
    }

    if (info.mode === "password" && !verified) {
      throw new AppSafeCliError(`Re-encrypted output failed verification: ${target.encrypted}`);
    }

    replacements.push({
      result: { encrypted: target.encrypted, from: current.info.mode, to: info.mode, verified },
      payload,
    });
  }

  for (const { result, payload } of replacements) {
    await writeFileAtomic(result.encrypted, payload, true);
  }

  return replacements.map(({ result }) => result);
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

async function keyStatus(
  filePath: string,
  reader: (filePath: string) => Promise<string>
): Promise<AppSafeKeyStatus> {
  if (!(await tryLstat(filePath))) {
    return { path: filePath, status: "missing" };
  }

  try {
    const key = await reader(filePath);
    return {
      path: filePath,
      status: "valid",
      fingerprint: await getKeyFingerprint(isPrivateKey(key) ? getPublicKey(key) : key),
    };
  } catch {
    return { path: filePath, status: "invalid" };
  }
}

async function payloadStatus(
  filePath: string,
  stats: FileStats | undefined
): Promise<AppSafeTargetStatus["payload"]> {
  if (!stats?.isFile()) {
    return undefined;
  }

  try {
    return inspectAppSafePayload(await readBytes(filePath));
  } catch {
    return "invalid";
  }
}

export async function inspectConfiguredTargets(
  config: AppSafeConfig,
  configFile: string
): Promise<AppSafeTargetStatus[]> {
  const targets = resolveConfiguredTargets(config, configFile);

  return Promise.all(
    targets.map(async (target) => {
      const [sourceStats, encryptedStats, restoreStats] = await Promise.all([
        tryLstat(target.source),
        tryLstat(target.encrypted),
        tryLstat(target.restore),
      ]);

      return {
        ...target,
        sourceStatus: pathStatus(sourceStats),
        encryptedStatus: pathStatus(encryptedStats),
        restoreStatus: pathStatus(restoreStats),
        publicKeys: await Promise.all(
          target.encryption.publicKeyFiles.map((file) => keyStatus(file, readPublicKeyFile))
        ),
        privateKey: target.encryption.privateKeyFile
          ? await keyStatus(target.encryption.privateKeyFile, readPrivateKeyFile)
          : undefined,
        payload: await payloadStatus(target.encrypted, encryptedStats),
      };
    })
  );
}

export async function generateKeyFiles(
  publicKeyFile: string,
  privateKeyFile: string,
  options: AppSafeKeygenOptions = {}
): Promise<AppSafeKeygenResult> {
  const publicPath = resolve(publicKeyFile);
  const privatePath = resolve(privateKeyFile);

  if (samePath(publicPath, privatePath)) {
    throw new AppSafeCliError("The public and private key paths must be different.");
  }

  const [publicStats, privateStats] = await Promise.all([
    tryLstat(publicPath),
    tryLstat(privatePath),
  ]);

  if (privateStats) {
    throw new AppSafeCliError(
      `A private key already exists: ${privatePath}. Keygen never overwrites private keys; move it aside manually after re-encrypting any artifacts that depend on it.`
    );
  }

  if (publicStats && (!publicStats.isFile() || (!options.force && !options.dryRun))) {
    throw new AppSafeCliError(
      `The public key file already exists: ${publicPath}. Use --force to replace it.`
    );
  }

  const gitignoreFile = options.gitignoreFile === false
    ? undefined
    : resolve(options.gitignoreFile ?? ".gitignore");
  const gitignoreEntry = gitignoreFile
    ? gitignoreEntryFor(privatePath, false, gitignoreFile)
    : undefined;
  const result: AppSafeKeygenResult = {
    publicKeyFile: publicPath,
    privateKeyFile: privatePath,
    gitignoreFile: gitignoreEntry ? gitignoreFile : undefined,
    gitignoreEntry,
  };

  if (options.dryRun) {
    return result;
  }

  if (gitignoreFile && gitignoreEntry) {
    await updateGitignore(gitignoreFile, [gitignoreEntry]);
  }

  const pair = await generateKeyPair();
  await writeFileAtomic(
    privatePath,
    [
      "# AppSafe private key. Keep it secret: never commit, log, or share it.",
      `# Fingerprint: ${pair.fingerprint}`,
      `# Public key: ${pair.publicKey}`,
      pair.privateKey,
      "",
    ].join("\n"),
    false,
    PRIVATE_KEY_FILE_MODE
  );
  await writeFileAtomic(
    publicPath,
    [
      "# AppSafe public key. Safe to commit and share with anyone who encrypts for you.",
      `# Fingerprint: ${pair.fingerprint}`,
      pair.publicKey,
      "",
    ].join("\n"),
    options.force === true
  );

  return { ...result, fingerprint: pair.fingerprint };
}
