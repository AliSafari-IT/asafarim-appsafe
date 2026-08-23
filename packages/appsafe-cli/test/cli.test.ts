import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { runCli } from "../src/cli.js";
import {
  decryptConfiguredTargets,
  encryptConfiguredTargets,
  loadConfig,
  updateGitignore,
} from "../src/index.js";

async function withTemporaryDirectory(
  callback: (directory: string) => Promise<void>
): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "appsafe-cli-"));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("init creates a placeholder config only when it is absent", async () => {
  await withTemporaryDirectory(async (directory) => {
    const configPath = join(directory, "appsafe.config.json");
    const previewPath = join(directory, "preview.config.json");

    assert.equal(await runCli(["init", "--config", configPath]), 0);
    const initialContent = await readFile(configPath, "utf8");
    assert.equal(initialContent.includes("path/to/private-file"), true);
    assert.equal(await runCli(["init", "--config", configPath]), 0);
    assert.equal(await readFile(configPath, "utf8"), initialContent);

    assert.equal(
      await runCli(["init", "--config", previewPath, "--dry-run"]),
      0
    );
    await assert.rejects(() => readFile(previewPath), { code: "ENOENT" });
  });
});

test("encrypts a file, updates gitignore, and restores it", async () => {
  await withTemporaryDirectory(async (directory) => {
    const source = join(directory, ".env.local");
    const configPath = join(directory, "appsafe.config.json");

    await writeFile(source, "APP_SECRET=local-only\n");
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        targets: [{ source: ".env.local", type: "file" }],
        encryption: { iterations: 100_000 },
      })
    );

    const loaded = await loadConfig(configPath);
    const encryptedResults = await encryptConfiguredTargets(
      loaded.config,
      loaded.path,
      "file-password"
    );

    assert.equal(encryptedResults.length, 1);
    assert.equal(encryptedResults[0]?.type, "file");
    assert.equal(encryptedResults[0]?.gitignoreEntry, "/.env.local");
    assert.equal((await stat(`${source}.appsafe`)).isFile(), true);
    assert.equal(await readFile(join(directory, ".gitignore"), "utf8"), "/.env.local\n");

    await rm(source);
    const decryptedResults = await decryptConfiguredTargets(
      loaded.config,
      loaded.path,
      "file-password"
    );

    assert.equal(decryptedResults[0]?.type, "file");
    assert.equal(await readFile(source, "utf8"), "APP_SECRET=local-only\n");
    assert.deepEqual(
      await updateGitignore(join(directory, ".gitignore"), ["/.env.local"]),
      []
    );
  });
});

test("archives a folder, preserves empty directories, and restores it", async () => {
  await withTemporaryDirectory(async (directory) => {
    const source = join(directory, "private-config");
    const nested = join(source, "nested");
    const configPath = join(directory, "appsafe.config.json");

    await mkdir(nested, { recursive: true });
    await mkdir(join(source, "empty"));
    await writeFile(join(nested, "settings.json"), "{\"enabled\":true}\n");
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        targets: [
          {
            source: "private-config",
            encrypted: "private-config.appsafe",
            type: "directory",
          },
        ],
        encryption: { iterations: 100_000 },
      })
    );

    const loaded = await loadConfig(configPath);
    const encryptedResults = await encryptConfiguredTargets(
      loaded.config,
      loaded.path,
      "folder-password"
    );

    assert.equal(encryptedResults[0]?.type, "directory");
    assert.equal((await stat(join(directory, "private-config.appsafe"))).isFile(), true);

    await rm(source, { recursive: true });
    const decryptedResults = await decryptConfiguredTargets(
      loaded.config,
      loaded.path,
      "folder-password"
    );

    assert.equal(decryptedResults[0]?.type, "directory");
    assert.equal(await readFile(join(source, "nested", "settings.json"), "utf8"), "{\"enabled\":true}\n");
    assert.equal((await stat(join(source, "empty"))).isDirectory(), true);
    assert.equal(await readFile(join(directory, ".gitignore"), "utf8"), "/private-config/\n");
  });
});

test("does not allow a folder output inside its source", async () => {
  await withTemporaryDirectory(async (directory) => {
    const source = join(directory, "private");
    const configPath = join(directory, "appsafe.config.json");

    await mkdir(source);
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        targets: [
          {
            source: "private",
            encrypted: "private/encrypted.appsafe",
            type: "directory",
          },
        ],
      })
    );

    const loaded = await loadConfig(configPath);
    await assert.rejects(
      () => encryptConfiguredTargets(loaded.config, loaded.path, "password"),
      /outside the source directory/
    );
  });
});

test("runs the encrypt and decrypt CLI commands with an environment password", async () => {
  await withTemporaryDirectory(async (directory) => {
    const source = join(directory, "config.json");
    const configPath = join(directory, "appsafe.config.json");
    const passwordVariable = "APPSAFE_CLI_TEST_PASSWORD";
    const previousPassword = process.env[passwordVariable];

    await writeFile(source, "local configuration\n");
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        targets: [{ source: "config.json", type: "file" }],
        encryption: { iterations: 100_000 },
      })
    );
    process.env[passwordVariable] = "command-password";

    try {
      assert.equal(
        await runCli([
          "encrypt",
          "--config",
          configPath,
          "--password-env",
          passwordVariable,
        ]),
        0
      );
      await rm(source);
      assert.equal(
        await runCli([
          "decrypt",
          "--config",
          configPath,
          "--password-env",
          passwordVariable,
        ]),
        0
      );
      assert.equal(await readFile(source, "utf8"), "local configuration\n");
    } finally {
      if (previousPassword === undefined) {
        delete process.env[passwordVariable];
      } else {
        process.env[passwordVariable] = previousPassword;
      }
    }
  });
});
