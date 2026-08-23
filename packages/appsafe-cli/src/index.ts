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
import { decryptBytes, encryptBytes } from "@asafarim/appsafe";
import { unzipSync, zipSync } from "fflate";

const MIN_PBKDF2_ITERATIONS = 100_000;
const MAX_PBKDF2_ITERATIONS = 2_000_000;
const ZIP_LEVEL = 6;
const INITIAL_CONFIG = `{
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
`;

export const APP_SAFE_EXTENSION = ".appsafe";

export type AppSafeTargetType = "file" | "directory";

export interface AppSafeTarget {
  source: string;
  encrypted?: string;
  restore?: string;
  type?: AppSafeTargetType;
  ignore?: boolean;
}

export interface AppSafeConfig {
  version: 1;
  targets: AppSafeTarget[];
  encryption?: {
    iterations?: number;
  };
  gitignore?: {
    file?: string;
    ignoreSources?: boolean;
  } | false;
}

export interface LoadedAppSafeConfig {
  config: AppSafeConfig;
  path: string;
}

export interface AppSafeResolvedTarget {
  source: string;
  encrypted: string;
  restore: string;
  requestedType?: AppSafeTargetType;
  ignore: boolean;
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
  bytes: number;
  gitignoreEntry?: string;
}

export type AppSafePathStatus = "missing" | "file" | "directory" | "symlink" | "other";

export interface AppSafeTargetStatus extends AppSafeResolvedTarget {
  sourceStatus: AppSafePathStatus;
  encryptedStatus: AppSafePathStatus;
  restoreStatus: AppSafePathStatus;
}

export class AppSafeCliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppSafeCliError";
  }
}

type FileStats = Awaited<ReturnType<typeof lstat>>;

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

function parseConfig(value: unknown): AppSafeConfig {
  const record = parseRecord(value, "The configuration");

  if (record.version !== 1) {
    throw new AppSafeCliError("The configuration version must be 1.");
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
    };
  });

  let encryption: AppSafeConfig["encryption"];
  if (record.encryption !== undefined) {
    const encryptionRecord = parseRecord(record.encryption, "encryption");
    encryption = {
      iterations: parseOptionalNumber(encryptionRecord, "iterations", "encryption"),
    };
  }

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
    version: 1,
    targets,
    encryption,
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

export async function initializeConfig(configFile: string): Promise<boolean> {
  const configPath = resolve(configFile);

  if (await configFileExists(configPath)) {
    return false;
  }

  try {
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, INITIAL_CONFIG, { flag: "wx" });
    return true;
  } catch (error) {
    if (isErrorWithCode(error, "EEXIST")) {
      return false;
    }

    throw wrapFileError("Unable to create", configPath, error);
  }
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
    };
  });
}

function validateEncryptionSettings(config: AppSafeConfig): void {
  const iterations = config.encryption?.iterations;

  if (
    iterations !== undefined &&
    (!Number.isSafeInteger(iterations) ||
      iterations < MIN_PBKDF2_ITERATIONS ||
      iterations > MAX_PBKDF2_ITERATIONS)
  ) {
    throw new AppSafeCliError(
      `encryption.iterations must be an integer between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
    );
  }
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

function getGitignoreEntry(
  source: string,
  sourceStats: FileStats,
  gitignorePath: string
): string {
  const gitignoreDirectory = dirname(gitignorePath);
  const relativeSource = relative(gitignoreDirectory, source);

  if (
    relativeSource === "" ||
    isAbsolute(relativeSource) ||
    relativeSource === ".." ||
    relativeSource.startsWith(`..${sep}`)
  ) {
    throw new AppSafeCliError(
      `The source path ${source} must be inside the directory containing ${gitignorePath}.`
    );
  }

  const normalized = relativeSource.split(sep).join("/");
  return sourceStats.isDirectory() ? `/${normalized}/` : `/${normalized}`;
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
  force: boolean
): Promise<void> {
  const directory = dirname(filePath);
  const temporaryPath = join(
    directory,
    `.${basename(filePath)}.${randomUUID()}.tmp`
  );
  let backupPath: string | undefined;

  try {
    await mkdir(directory, { recursive: true });
    await writeFile(temporaryPath, data, { flag: "wx" });

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
  password: string | undefined,
  options: AppSafeOperationOptions = {}
): Promise<AppSafeOperationResult[]> {
  const prepared = await prepareEncryptTargets(config, configFile, options);

  if (options.dryRun) {
    return prepared.targets.map((target) => ({
      source: target.source,
      encrypted: target.encrypted,
      restore: target.restore,
      type: target.type,
      bytes: 0,
      gitignoreEntry: target.gitignoreEntry,
    }));
  }

  if (password === undefined) {
    throw new AppSafeCliError("An encryption password is required.");
  }

  const results: AppSafeOperationResult[] = [];
  const encryptionOptions = config.encryption?.iterations === undefined
    ? undefined
    : { iterations: config.encryption.iterations };

  for (const target of prepared.targets) {
    const input = target.type === "directory"
      ? await createFolderArchive(target.source)
      : await readBytes(target.source);
    const encrypted = await encryptBytes(input, password, encryptionOptions);
    await writeFileAtomic(target.encrypted, encrypted, options.force === true);

    results.push({
      source: target.source,
      encrypted: target.encrypted,
      restore: target.restore,
      type: target.type,
      bytes: encrypted.byteLength,
      gitignoreEntry: target.gitignoreEntry,
    });
  }

  if (prepared.gitignorePath && prepared.gitignoreEntries.length > 0) {
    await updateGitignore(prepared.gitignorePath, prepared.gitignoreEntries);
  }

  return results;
}

export async function decryptConfiguredTargets(
  config: AppSafeConfig,
  configFile: string,
  password: string | undefined,
  options: AppSafeOperationOptions = {}
): Promise<AppSafeOperationResult[]> {
  const prepared = await prepareDecryptTargets(config, configFile, options);

  if (options.dryRun) {
    return prepared.map((target) => ({
      source: target.source,
      encrypted: target.encrypted,
      restore: target.restore,
      type: target.requestedType ?? "unknown",
      bytes: 0,
    }));
  }

  if (password === undefined) {
    throw new AppSafeCliError("A decryption password is required.");
  }

  const results: AppSafeOperationResult[] = [];

  for (const target of prepared) {
    const encrypted = await readBytes(target.encrypted);
    const decrypted = await decryptBytes(encrypted, password);
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
      bytes: decrypted.byteLength,
    });
  }

  return results;
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
      };
    })
  );
}
