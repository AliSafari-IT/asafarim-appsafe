import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { runCli } from "../src/cli.js";
import {
  decryptConfiguredTargets,
  encryptConfiguredTargets,
  extractKey,
  generateKeyFiles,
  loadConfig,
  rekeyConfiguredTargets,
  resolveConfiguredTargets,
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

async function captureOutput(callback: () => Promise<unknown>): Promise<string> {
  const writes: string[] = [];
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  const capture = ((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;
  process.stdout.write = capture;
  process.stderr.write = capture;
  try {
    await callback();
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
  return writes.join("");
}

async function withEnvironment(
  values: Record<string, string>,
  callback: () => Promise<void>
): Promise<void> {
  const previous = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  try {
    await callback();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

async function writeKeys(
  directory: string,
  name = "key"
): Promise<{ publicKey: string; privateKey: string }> {
  const result = await generateKeyFiles(
    join(directory, ".appsafe", `${name}.pub`),
    join(directory, ".appsafe", `${name}.txt`),
    { gitignoreFile: join(directory, ".gitignore") }
  );
  return {
    publicKey: extractKey(await readFile(result.publicKeyFile, "utf8")),
    privateKey: extractKey(await readFile(result.privateKeyFile, "utf8")),
  };
}

test("keygen writes a key pair, ignores the private key, and never overwrites it", async () => {
  await withTemporaryDirectory(async (directory) => {
    const publicPath = join(directory, "keys", "team.pub");
    const privatePath = join(directory, "keys", "team.txt");
    const args = [
      "keygen",
      "--public-key-out",
      publicPath,
      "--private-key-out",
      privatePath,
      "--gitignore",
      join(directory, ".gitignore"),
    ];

    assert.equal(await runCli([...args, "--dry-run"]), 0);
    await assert.rejects(() => readFile(privatePath), { code: "ENOENT" });

    const output = await captureOutput(async () => assert.equal(await runCli(args), 0));
    const publicKey = extractKey(await readFile(publicPath, "utf8"));
    const privateKey = extractKey(await readFile(privatePath, "utf8"));

    assert.match(publicKey, /^appsafe-pub-p256:/);
    assert.match(privateKey, /^APPSAFE-PRIVATE-KEY-P256:/);
    assert.equal(output.includes(privateKey), false);
    assert.equal(await readFile(join(directory, ".gitignore"), "utf8"), "/keys/team.txt\n");
    if (process.platform !== "win32") {
      assert.equal((await stat(privatePath)).mode & 0o777, 0o600);
    }

    assert.equal(await runCli(args), 1);
    assert.equal(await runCli([...args, "--force"]), 1);
    assert.equal(extractKey(await readFile(privatePath, "utf8")), privateKey);

    await rm(privatePath);
    assert.equal(await runCli(args), 1);
    assert.equal(await runCli([...args, "--force"]), 0);
    assert.notEqual(extractKey(await readFile(publicPath, "utf8")), publicKey);
  });
});

test("encrypts files and folders for a public key and restores them with the private key", async () => {
  await withTemporaryDirectory(async (directory) => {
    const app = join(directory, "apps", "future-private-app");
    const file = join(directory, "apps", "example", "private-file.ts");
    const configPath = join(directory, "appsafe.config.json");

    await mkdir(join(app, "src"), { recursive: true });
    await mkdir(dirname(file), { recursive: true });
    await writeFile(join(app, "src", "index.ts"), "export const secret = true;\n");
    await writeFile(file, "export const privateFile = 1;\n");
    await writeKeys(directory);
    await writeFile(
      configPath,
      JSON.stringify({
        version: 2,
        encryption: {
          mode: "public-key",
          publicKeyFile: "./.appsafe/key.pub",
          privateKeyFile: "./.appsafe/key.txt",
        },
        targets: [
          {
            source: "./apps/future-private-app",
            encrypted: "./apps/future-private-app.appsafe",
            type: "directory",
          },
          { source: "./apps/example/private-file.ts", type: "file" },
        ],
      })
    );

    const loaded = await loadConfig(configPath);
    const encrypted = await encryptConfiguredTargets(loaded.config, loaded.path, undefined);

    assert.deepEqual(encrypted.map((result) => result.mode), ["public-key", "public-key"]);
    assert.deepEqual(
      (await readFile(join(directory, ".gitignore"), "utf8")).split("\n"),
      ["/.appsafe/key.txt", "/apps/future-private-app/", "/apps/example/private-file.ts", ""]
    );

    await rm(app, { recursive: true });
    await rm(file);
    const decrypted = await decryptConfiguredTargets(loaded.config, loaded.path, undefined);

    assert.deepEqual(decrypted.map((result) => result.mode), ["public-key", "public-key"]);
    assert.equal(await readFile(join(app, "src", "index.ts"), "utf8"), "export const secret = true;\n");
    assert.equal(await readFile(file, "utf8"), "export const privateFile = 1;\n");

    await assert.rejects(
      () => encryptConfiguredTargets(loaded.config, loaded.path, undefined),
      /already exists/
    );
    assert.equal(
      (await encryptConfiguredTargets(loaded.config, loaded.path, undefined, { force: true })).length,
      2
    );
  });
});

test("supports per-target modes and detects each payload mode during decryption", async () => {
  await withTemporaryDirectory(async (directory) => {
    const passwordSource = join(directory, "password.env");
    const keySource = join(directory, "key.env");
    const configPath = join(directory, "appsafe.config.json");

    await writeFile(passwordSource, "PASSWORD_MODE=1\n");
    await writeFile(keySource, "KEY_MODE=1\n");
    const { privateKey } = await writeKeys(directory);
    await writeFile(
      configPath,
      JSON.stringify({
        version: 2,
        encryption: { mode: "password", iterations: 100_000 },
        targets: [
          { source: "password.env" },
          {
            source: "key.env",
            encryption: { mode: "public-key", publicKeyFile: "./.appsafe/key.pub" },
          },
        ],
      })
    );

    await withEnvironment(
      { APPSAFE_TEST_PASSWORD: "mixed-password", APPSAFE_TEST_PRIVATE_KEY: privateKey },
      async () => {
        const passwordArgs = ["--config", configPath, "--password-env", "APPSAFE_TEST_PASSWORD"];
        const encryptOutput = await captureOutput(async () =>
          assert.equal(await runCli(["encrypt", ...passwordArgs]), 0)
        );
        assert.match(encryptOutput, /\[password\][\s\S]*\[public-key\]/);

        await rm(passwordSource);
        await rm(keySource);
        const missingKeyOutput = await captureOutput(async () =>
          assert.equal(await runCli(["decrypt", ...passwordArgs]), 1)
        );
        assert.match(missingKeyOutput, /private key is required/);

        const decryptOutput = await captureOutput(async () =>
          assert.equal(
            await runCli([
              "decrypt",
              ...passwordArgs,
              "--private-key-env",
              "APPSAFE_TEST_PRIVATE_KEY",
            ]),
            0
          )
        );

        assert.equal(await readFile(passwordSource, "utf8"), "PASSWORD_MODE=1\n");
        assert.equal(await readFile(keySource, "utf8"), "KEY_MODE=1\n");
        for (const output of [encryptOutput, missingKeyOutput, decryptOutput]) {
          assert.equal(output.includes(privateKey), false);
          assert.equal(output.includes("mixed-password"), false);
        }
      }
    );
  });
});

test("rejects wrong or misplaced keys without printing them", async () => {
  await withTemporaryDirectory(async (directory) => {
    const configPath = join(directory, "appsafe.config.json");

    await writeFile(join(directory, "secret.txt"), "secret\n");
    await writeKeys(directory);
    const other = await writeKeys(directory, "other");
    const config = {
      version: 2,
      encryption: {
        mode: "public-key",
        publicKeyFile: "./.appsafe/key.pub",
        privateKeyFile: "./.appsafe/other.txt",
      },
      targets: [{ source: "secret.txt" }],
    };
    await writeFile(configPath, JSON.stringify(config));

    const loaded = await loadConfig(configPath);
    await encryptConfiguredTargets(loaded.config, loaded.path, undefined);
    await rm(join(directory, "secret.txt"));
    await assert.rejects(
      () => decryptConfiguredTargets(loaded.config, loaded.path, undefined),
      (error: Error) =>
        /not a recipient/.test(error.message) && !error.message.includes(other.privateKey)
    );

    const checkOutput = await captureOutput(() => runCli(["check", "--config", configPath]));
    assert.match(checkOutput, /mode: public-key/);
    assert.match(checkOutput, /private key is NOT a recipient/);
    assert.equal(checkOutput.includes(other.privateKey), false);

    await writeFile(join(directory, ".appsafe", "key.pub"), `${other.privateKey}\n`);
    await writeFile(join(directory, "secret.txt"), "secret\n");
    const errorOutput = await captureOutput(async () =>
      assert.equal(await runCli(["encrypt", "--config", configPath, "--force"]), 1)
    );
    assert.match(errorOutput, /contains a private key/);
    assert.equal(errorOutput.includes(other.privateKey), false);

    await writeFile(
      configPath,
      JSON.stringify({
        ...config,
        encryption: { mode: "public-key", publicKeyFile: "./.appsafe/other.pub" },
      })
    );
    const reloaded = await loadConfig(configPath);
    await encryptConfiguredTargets(reloaded.config, reloaded.path, undefined, { force: true });
    await assert.rejects(
      () => decryptConfiguredTargets(reloaded.config, reloaded.path, undefined, { force: true }),
      /private key is required/
    );
    const restored = await decryptConfiguredTargets(
      reloaded.config,
      reloaded.path,
      { privateKey: other.privateKey },
      { force: true }
    );
    assert.equal(restored[0]?.mode, "public-key");
  });
});

test("validates encryption mode settings", async () => {
  await withTemporaryDirectory(async (directory) => {
    const configPath = join(directory, "appsafe.config.json");
    const cases: Array<[unknown, RegExp]> = [
      [
        { version: 1, encryption: { mode: "public-key", publicKeyFile: "k.pub" }, targets: [{ source: "a" }] },
        /version 2/,
      ],
      [{ version: 1, targets: [{ source: "a", encryption: { iterations: 100_000 } }] }, /version 2/],
      [{ version: 3, targets: [{ source: "a" }] }, /version must be 1 or 2/],
      [{ version: 2, encryption: { mode: "public-key" }, targets: [{ source: "a" }] }, /no publicKeyFile/],
      [
        { version: 2, encryption: { mode: "password", publicKeyFile: "k.pub" }, targets: [{ source: "a" }] },
        /password mode/,
      ],
      [
        {
          version: 2,
          encryption: { mode: "public-key", publicKeyFile: "k.pub", iterations: 100_000 },
          targets: [{ source: "a" }],
        },
        /cannot set iterations/,
      ],
      [
        { version: 2, encryption: { publicKeyFile: "a.pub", publicKeyFiles: ["b.pub"] }, targets: [{ source: "a" }] },
        /not both/,
      ],
      [{ version: 2, encryption: { mode: "age" }, targets: [{ source: "a" }] }, /mode must be/],
      [
        { version: 2, targets: [{ source: "a", encryption: { mode: "public-key" } }] },
        /targets\[0\] uses public-key mode/,
      ],
    ];

    for (const [config, pattern] of cases) {
      await writeFile(configPath, JSON.stringify(config));
      await assert.rejects(() => loadConfig(configPath), pattern);
    }

    await writeFile(
      configPath,
      JSON.stringify({
        version: 2,
        encryption: { publicKeyFiles: ["a.pub", "b.pub"], iterations: 100_000 },
        targets: [{ source: "a" }, { source: "b", encryption: { mode: "public-key" } }],
      })
    );
    const loaded = await loadConfig(configPath);
    const targets = resolveConfiguredTargets(loaded.config, loaded.path);
    assert.deepEqual(targets.map((target) => target.encryption.mode), ["password", "public-key"]);
    assert.equal(targets[1]?.encryption.publicKeyFiles.length, 2);
    assert.equal(targets[1]?.encryption.iterations, undefined);
  });
});

test("init creates a public-key starter config and rejects unrelated options", async () => {
  await withTemporaryDirectory(async (directory) => {
    const configPath = join(directory, "appsafe.config.json");

    assert.equal(await runCli(["init", "--config", configPath, "--mode", "public-key"]), 0);
    const loaded = await loadConfig(configPath);
    assert.equal(loaded.config.version, 2);
    assert.equal(loaded.config.encryption?.mode, "public-key");

    const errors = await captureOutput(async () => {
      assert.equal(await runCli(["init", "--config", configPath, "--password-env", "X"]), 1);
      assert.equal(await runCli(["decrypt", "--config", configPath, "--mode", "password"]), 1);
      assert.equal(await runCli(["encrypt", "--private-key-env", "X"]), 1);
      assert.equal(
        await runCli(["decrypt", "--private-key-stdin", "--password-stdin", "--config", configPath]),
        1
      );
    });
    assert.match(errors, /does not accept --password-env/);
    assert.match(errors, /Only one secret can be read from stdin/);

    await mkdir(join(directory, "path", "to", "private-app"), { recursive: true });
    assert.equal(await runCli(["encrypt", "--config", configPath, "--dry-run"]), 0);
    await assert.rejects(() => stat(join(directory, "path", "to", "private-app.appsafe")), {
      code: "ENOENT",
    });
  });
});

test("rekey rotates passwords and migrates artifacts to public-key mode", async () => {
  await withTemporaryDirectory(async (directory) => {
    const source = join(directory, "migrate.txt");
    const encrypted = `${source}.appsafe`;
    const configPath = join(directory, "appsafe.config.json");

    await writeFile(source, "migrate me\n");
    await writeFile(
      configPath,
      JSON.stringify({
        version: 1,
        targets: [{ source: "migrate.txt" }],
        encryption: { iterations: 100_000 },
      })
    );
    let loaded = await loadConfig(configPath);
    await encryptConfiguredTargets(loaded.config, loaded.path, "old-password");

    assert.deepEqual(
      await rekeyConfiguredTargets(loaded.config, loaded.path, {
        password: "old-password",
        newPassword: "new-password",
      }),
      [{ encrypted, from: "password", to: "password", verified: true }]
    );
    await assert.rejects(
      () => decryptConfiguredTargets(loaded.config, loaded.path, "old-password", { force: true }),
      /password or encrypted data is invalid/
    );

    const { privateKey } = await writeKeys(directory);
    await writeFile(
      configPath,
      JSON.stringify({
        version: 2,
        encryption: { mode: "public-key", publicKeyFile: "./.appsafe/key.pub" },
        targets: [{ source: "migrate.txt" }],
      })
    );
    loaded = await loadConfig(configPath);

    const preview = await rekeyConfiguredTargets(loaded.config, loaded.path, {}, { dryRun: true });
    assert.deepEqual(preview, [{ encrypted, from: "password", to: "public-key", verified: false }]);

    const beforeFailure = await readFile(encrypted);
    await assert.rejects(
      () => rekeyConfiguredTargets(loaded.config, loaded.path, { password: "wrong-password" }),
      /password or encrypted data is invalid/
    );
    assert.deepEqual(await readFile(encrypted), beforeFailure);

    const migrated = await rekeyConfiguredTargets(loaded.config, loaded.path, {
      password: "new-password",
      privateKey,
    });
    assert.deepEqual(migrated, [{ encrypted, from: "password", to: "public-key", verified: true }]);
    await rm(source);
    await decryptConfiguredTargets(loaded.config, loaded.path, { privateKey });
    assert.equal(await readFile(source, "utf8"), "migrate me\n");
  });
});
