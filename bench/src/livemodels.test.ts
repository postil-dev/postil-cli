import { describe, expect, test } from "bun:test";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase, type BenchmarkCase } from "./harness";
import {
  admissionManifestCandidate,
  assertGitTreeSourceAuthority,
  assertPricingProviderIdentity,
  assertExactQualificationFixtures,
  assertQualificationInputsUnchanged,
  benchmarkProviderIdentityFor,
  canonicalQualificationCostCap,
  endpointAuthFromEnvironment,
  EVALUATOR_CONTRACT_SOURCE_PATHS,
  fetchPricing,
  formatLiveModelsReport,
  hashNamedSources,
  liveEnv,
  liveModelsQualificationExitCode,
  MANAGED_OPENROUTER_PROVIDER_IDENTITY,
  modelPriceBoundsFor,
  normalizeApiBase,
  normalizeQualificationPairs,
  parseQualificationPairs,
  prepareImmutableQualificationBinary,
  prepareAttributionEvaluatorEnvironment,
  pricingFromFile,
  qualificationCandidateDocument,
  qualificationProfileDigest,
  readPinnedQualificationWorktreeFile,
  runLiveModels,
  withImmutableQualificationBinary,
  type LiveModelsReport,
} from "./livemodels";
import type { QualificationPair } from "./livemodels-score";

const pair: QualificationPair = { generatorModel: "test/generator", scorerModel: "test/scorer" };

function git(cwd: string, args: string[]): string {
  const result = Bun.spawnSync(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(new TextDecoder().decode(result.stderr));
  }
  return new TextDecoder().decode(result.stdout).trim();
}

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ origin: string; server: Server }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;
  return { origin: `http://127.0.0.1:${address.port}`, server };
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

describe("pair qualification configuration", () => {
  test("requires and normalizes exact generator/scorer pairs", () => {
    expect(parseQualificationPairs(" a/generator::b/scorer ")).toEqual([
      {
        generatorModel: "a/generator",
        generatorCascade: [],
        consensus: 1,
        scorerModel: "b/scorer",
        scorerCascade: [],
      },
    ]);
    expect(parseQualificationPairs("a/one+b/two+c/three::s/scorer")).toEqual([{
      generatorModel: "a/one",
      generatorCascade: ["b/two", "c/three"],
      consensus: 3,
      scorerModel: "s/scorer",
      scorerCascade: [],
    }]);
    expect(parseQualificationPairs("a/one+b/two::1::s/one+s/two")).toEqual([{
      generatorModel: "a/one",
      generatorCascade: ["b/two"],
      consensus: 1,
      scorerModel: "s/one",
      scorerCascade: ["s/two"],
    }]);
    expect(() => parseQualificationPairs("a/generator")).toThrow(
      "generators::scorer+fallback or generators::consensus::scorer+fallback",
    );
    expect(() => parseQualificationPairs("a/generator::1::s/scorer::ignored")).toThrow(
      "generators::scorer+fallback or generators::consensus::scorer+fallback",
    );
    expect(normalizeQualificationPairs([pair, { ...pair }])).toEqual([{
      ...pair,
      generatorCascade: [],
      consensus: 1,
      scorerCascade: [],
    }]);
    expect(() => normalizeQualificationPairs([])).toThrow("at least one generator+scorer pair");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      scorerModel: "s/one",
      scorerCascade: ["s/two", "s/three"],
    }])).toThrow("exactly one ordered fallback");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      generatorCascade: ["a/generator"],
      scorerModel: "s/scorer",
    }])).toThrow("generator chain must not repeat");

    for (const malformed of [
      "a/generator::s/scorer,",
      ",a/generator::s/scorer",
      "a/generator::s/scorer,,b/generator::s/scorer",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("empty pair component");
    }
    for (const malformed of [
      "+a/generator::s/scorer",
      "a/generator+::s/scorer",
      "a/generator++b/fallback::s/scorer",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("generator chain contains an empty model component");
    }
    for (const malformed of [
      "a/generator::+s/scorer",
      "a/generator::s/scorer+",
      "a/generator::s/scorer++s/fallback",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("scorer chain contains an empty model component");
    }
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      generatorCascade: [" "],
      scorerModel: "s/scorer",
    }])).toThrow("generator chain contains an empty model component");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      scorerModel: "s/scorer",
      scorerCascade: [""],
    }])).toThrow("scorer chain contains an empty model component");
  });

  test("forces the exact pair and no fallback model", () => {
    const env = liveEnv(
      "/tmp/home",
      "/tmp/tmp",
      "http://github.test",
      pair,
      "https://openrouter.ai/api/v1",
    );
    expect(env).toMatchObject({
      REVIEW_MODEL: pair.generatorModel,
      REVIEW_MODEL_CASCADE: pair.generatorModel,
      REVIEW_MODEL_CONSENSUS: "1",
      REVIEW_SCORER_MODEL: pair.scorerModel,
      POSTIL_API_FORMAT: "openai-compatible",
    });
    expect(env.POSTIL_DISABLE_SCORER).toBeUndefined();
  });

  test("binds candidate hosted execution to an exact profile file", () => {
    const pricing = new Map([
      [pair.generatorModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
      [pair.scorerModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
    ]);
    const apiBase = normalizeApiBase("https://openrouter.ai/api/v1");
    expect(qualificationCandidateDocument(pair, pricing, apiBase, "openai-compatible", "PinnedProvider"))
      .toMatchObject({
        benchmarkProviderIdentity: MANAGED_OPENROUTER_PROVIDER_IDENTITY,
        apiBase,
        generatorChain: [pair.generatorModel],
        scorerChain: [pair.scorerModel],
      });
    expect(liveEnv(
      "/tmp/home",
      "/tmp/tmp",
      "http://127.0.0.1:1234",
      pair,
      apiBase,
      "openai-compatible",
      "/tmp/candidate.json",
    ).POSTIL_QUALIFICATION_CANDIDATE_PROFILE).toBe("/tmp/candidate.json");
  });

  test("activates the exact candidate profile for evaluator-bank calls", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-evaluator-profile-"));
    const pricing = new Map([
      [pair.generatorModel, {
        providerIdentity: "PinnedProvider",
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
      [pair.scorerModel, {
        providerIdentity: "PinnedProvider",
        promptUsdPerToken: 0.000003,
        completionUsdPerToken: 0.000004,
        inputMicrosPerMillionTokens: 3_000_000,
        outputMicrosPerMillionTokens: 4_000_000,
      }],
    ]);
    try {
      const env = await prepareAttributionEvaluatorEnvironment(
        root,
        pair,
        pricing,
        normalizeApiBase("https://openrouter.ai/api/v1"),
        "openai-compatible",
        "PinnedProvider",
      );
      const profilePath = env.POSTIL_QUALIFICATION_CANDIDATE_PROFILE;
      expect(profilePath).toBe(resolve(root, "qualification-candidate.json"));
      expect(await Bun.file(profilePath!).json()).toMatchObject({
        upstreamProviderIdentity: "PinnedProvider",
        scorerChain: [pair.scorerModel],
        modelPriceBounds: [
          { model: pair.generatorModel, inputMicrosPerMillionTokens: 1_000_000, outputMicrosPerMillionTokens: 2_000_000 },
          { model: pair.scorerModel, inputMicrosPerMillionTokens: 3_000_000, outputMicrosPerMillionTokens: 4_000_000 },
        ],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("forwards validated endpoint authentication without exposing managed headers", () => {
    const inheritedHeader = process.env.POSTIL_ENDPOINT_AUTH_HEADER;
    const inheritedValue = process.env.POSTIL_ENDPOINT_AUTH_VALUE;
    try {
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Private-Auth";
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "opaque credential";
      expect(endpointAuthFromEnvironment("openai-compatible")).toEqual({
        header: "X-Private-Auth",
        value: "opaque credential",
      });
      expect(liveEnv("/tmp/home", "/tmp/tmp", "http://github.test", pair, "https://models.test/v1"))
        .toMatchObject({
          POSTIL_ENDPOINT_AUTH_HEADER: "X-Private-Auth",
          POSTIL_ENDPOINT_AUTH_VALUE: "opaque credential",
        });
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "Authorization";
      expect(() => endpointAuthFromEnvironment("openai-compatible")).toThrow("provider-managed");
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "Bad Header";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("valid HTTP header name");
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Private-Auth";
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "bad\r\nvalue";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("valid HTTP header value");
      delete process.env.POSTIL_ENDPOINT_AUTH_HEADER;
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "value-only";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("HEADER must be set");
    } finally {
      if (inheritedHeader === undefined) delete process.env.POSTIL_ENDPOINT_AUTH_HEADER;
      else process.env.POSTIL_ENDPOINT_AUTH_HEADER = inheritedHeader;
      if (inheritedValue === undefined) delete process.env.POSTIL_ENDPOINT_AUTH_VALUE;
      else process.env.POSTIL_ENDPOINT_AUTH_VALUE = inheritedValue;
    }
  });

  test("canonicalizes the provider endpoint exactly like the runtime", () => {
    expect(normalizeApiBase("HTTPS://OpenRouter.AI/api/v1/")).toBe(
      "https://openrouter.ai:443/api/v1",
    );
    expect(() => normalizeApiBase("https://example.test/v1?route=x")).toThrow(
      "must not contain a query or fragment",
    );
    expect(benchmarkProviderIdentityFor(
      "https://openrouter.ai:443/api/v1",
      "openai-compatible",
    )).toBe(MANAGED_OPENROUTER_PROVIDER_IDENTITY);
    expect(benchmarkProviderIdentityFor("https://models.example:443/v1", "openai-compatible"))
      .toBeNull();
    expect(benchmarkProviderIdentityFor("https://openrouter.ai:443/api/v1", "anthropic"))
      .toBeNull();
  });

  test("enforces cost and candidate bounds before execution", async () => {
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs: [pair],
      pricing: new Map(),
      costCapUsd: 36,
      upstreamProvider: "PinnedProvider",
    })).rejects.toThrow("cost cap must be greater than zero and at most $35");

    const pairs = Array.from({ length: 7 }, (_, index) => ({
      generatorModel: `generator/${index}`,
      scorerModel: `scorer/${index}`,
    }));
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs,
      pricing: new Map(),
      upstreamProvider: "PinnedProvider",
    })).rejects.toThrow("at most 6 candidates");

  });

  test("validates the raw cost cap as a bounded canonical decimal", () => {
    expect(canonicalQualificationCostCap("34.123456")).toBe("34.123456");
    for (const invalid of ["1junk", "1e0", "-1", "0", "01", "1.0000000", "0.0000001"]) {
      expect(() => canonicalQualificationCostCap(invalid)).toThrow();
    }
  });

  test("requires pricing-file rows to name the exact upstream provider", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-pricing-file-"));
    const pricingPath = resolve(root, "pricing.json");
    try {
      await writeFile(pricingPath, JSON.stringify({
        "provider/model": {
          providerIdentity: "PinnedProvider",
          promptUsdPerToken: "0.000001",
          completionUsdPerToken: "0.000005",
        },
      }));
      expect((await pricingFromFile(pricingPath)).get("provider/model")).toMatchObject({
        providerIdentity: "PinnedProvider",
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 5_000_000,
      });
      const exactPricing = await pricingFromFile(pricingPath);
      expect(() => assertPricingProviderIdentity(exactPricing, ["provider/model"], "PinnedProvider"))
        .not.toThrow();
      expect(() => assertPricingProviderIdentity(exactPricing, ["provider/model"], "OtherProvider"))
        .toThrow("not bound to upstream provider OtherProvider");

      for (const row of [
        { promptUsdPerToken: "0.000001", completionUsdPerToken: "0.000005" },
        { providerIdentity: " ", promptUsdPerToken: "0.000001", completionUsdPerToken: "0.000005" },
        { providerIdentity: "PinnedProvider", promptUsdPerToken: "0.000001", completionUsdPerToken: "0.000005", extra: true },
      ]) {
        await writeFile(pricingPath, JSON.stringify({ "provider/model": row }));
        await expect(pricingFromFile(pricingPath)).rejects.toThrow();
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("qualification Git source authority", () => {
  test("rejects relevant untracked sources missing from the named commit", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-"));
    try {
      git(root, ["init", "--quiet"]);
      await writeFile(resolve(root, "README.md"), "authority fixture\n");
      git(root, ["add", "README.md"]);
      const sourceSha = git(root, ["write-tree"]);

      await mkdir(resolve(root, "src"), { recursive: true });
      await mkdir(resolve(root, "bench", "src"), { recursive: true });
      await writeFile(resolve(root, "src", "attribution.rs"), "pub fn attribute() {}\n");
      await writeFile(resolve(root, "bench", "src", "attribution.ts"), "export const attribute = true;\n");
      await expect(assertGitTreeSourceAuthority(root, sourceSha, [
        "src/attribution.rs",
        "bench/src/attribution.ts",
      ])).rejects.toThrow("does not track regular file");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("allows unrelated untracked files without changing relevant authority", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-unrelated-"));
    try {
      git(root, ["init", "--quiet"]);
      await mkdir(resolve(root, "src"), { recursive: true });
      await writeFile(resolve(root, "src", "required.ts"), "export const required = true;\n");
      git(root, ["add", "src/required.ts"]);
      const sourceSha = git(root, ["write-tree"]);
      await writeFile(resolve(root, "notes.tmp"), "unrelated\n");
      await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
        .resolves.toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a staged index blob that differs from the named source", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-index-"));
    try {
      git(root, ["init", "--quiet"]);
      await mkdir(resolve(root, "src"), { recursive: true });
      const path = resolve(root, "src", "required.ts");
      await writeFile(path, "export const value = 1;\n");
      git(root, ["add", "src/required.ts"]);
      const sourceSha = git(root, ["write-tree"]);
      await writeFile(path, "export const value = 2;\n");
      git(root, ["add", "src/required.ts"]);
      await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
        .rejects.toThrow("index path src/required.ts differs");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects missing and symbolic-link worktree sources", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-type-"));
    try {
      git(root, ["init", "--quiet"]);
      await mkdir(resolve(root, "src"), { recursive: true });
      const path = resolve(root, "src", "required.ts");
      await writeFile(path, "export const required = true;\n");
      git(root, ["add", "src/required.ts"]);
      const sourceSha = git(root, ["write-tree"]);
      await rm(path);
      await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
        .rejects.toThrow("missing or could not be opened safely");
      const target = resolve(root, "target.ts");
      await writeFile(target, "export const required = true;\n");
      await symlink(target, path);
      await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
        .rejects.toThrow("missing or could not be opened safely");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
    test(`rejects worktree changes hidden by ${flag}`, async () => {
      const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-index-flag-"));
      try {
        git(root, ["init", "--quiet"]);
        await mkdir(resolve(root, "src"), { recursive: true });
        await writeFile(resolve(root, "src", "required.ts"), "export const value = 1;\n");
        git(root, ["add", "src/required.ts"]);
        const sourceSha = git(root, ["write-tree"]);
        git(root, ["update-index", flag, "src/required.ts"]);
        await writeFile(resolve(root, "src", "required.ts"), "export const value = 2;\n");
        await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
          .rejects.toThrow("worktree path src/required.ts differs");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }

  test("rejects executable mode changes hidden from content comparison", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-mode-"));
    try {
      git(root, ["init", "--quiet"]);
      await mkdir(resolve(root, "src"), { recursive: true });
      const path = resolve(root, "src", "required.ts");
      await writeFile(path, "export const required = true;\n", { mode: 0o644 });
      git(root, ["add", "src/required.ts"]);
      const sourceSha = git(root, ["write-tree"]);
      git(root, ["update-index", "--assume-unchanged", "src/required.ts"]);
      await chmod(path, 0o755);
      await expect(assertGitTreeSourceAuthority(root, sourceSha, ["src/required.ts"]))
        .rejects.toThrow("executable mode differs");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a hard-linked qualification source", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-hardlink-"));
    try {
      await mkdir(resolve(root, "src"), { recursive: true });
      const path = resolve(root, "src", "required.ts");
      await writeFile(path, "export const required = true;\n");
      await link(path, resolve(root, "alias.ts"));
      await expect(readPinnedQualificationWorktreeFile(root, "src/required.ts"))
        .rejects.toThrow("not a bounded single-link regular file");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a qualification source beyond the descriptor-read bound", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-size-"));
    try {
      await mkdir(resolve(root, "src"), { recursive: true });
      await writeFile(resolve(root, "src", "required.ts"), Buffer.alloc(16 * 1024 * 1024 + 1));
      await expect(readPinnedQualificationWorktreeFile(root, "src/required.ts"))
        .rejects.toThrow("not a bounded single-link regular file");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a symbolic-link parent directory", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-parent-link-"));
    const external = await mkdtemp(resolve(tmpdir(), "postil-source-authority-external-"));
    try {
      await writeFile(resolve(external, "required.ts"), "external replacement\n");
      await symlink(external, resolve(root, "src"), "dir");
      await expect(readPinnedQualificationWorktreeFile(root, "src/required.ts"))
        .rejects.toThrow("directory for src/required.ts could not be opened safely");
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(external, { recursive: true, force: true });
    }
  });

  test("a parent-directory swap reads only the pinned original or fails", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-source-authority-parent-race-"));
    const external = await mkdtemp(resolve(tmpdir(), "postil-source-authority-race-external-"));
    const original = Buffer.from("pinned original\n");
    const sourceDirectory = resolve(root, "src");
    const parkedDirectory = resolve(root, "src-pinned");
    try {
      await mkdir(sourceDirectory);
      await writeFile(resolve(sourceDirectory, "required.ts"), original);
      await writeFile(resolve(external, "required.ts"), "external replacement\n");
      expect((await readPinnedQualificationWorktreeFile(root, "src/required.ts")).bytes)
        .toEqual(original);
      const swapper = (async () => {
        for (let attempt = 0; attempt < 100; attempt += 1) {
          await rename(sourceDirectory, parkedDirectory);
          await symlink(external, sourceDirectory, "dir");
          await rm(sourceDirectory);
          await rename(parkedDirectory, sourceDirectory);
        }
      })();
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const result = await readPinnedQualificationWorktreeFile(root, "src/required.ts")
          .then((value) => value.bytes, () => null);
        if (result !== null) expect(result).toEqual(original);
      }
      await swapper;
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(external, { recursive: true, force: true });
    }
  });
});

describe("immutable qualification binary", () => {
  test("rejects a qualification contract input changed before candidate emission", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-qualification-input-"));
    const config = resolve(root, "config.toml");
    try {
      await writeFile(config, "model = \"one\"");
      const initial = hashNamedSources([["config.toml", await readFile(config)]]);
      await writeFile(config, "model = \"two\"");
      const current = hashNamedSources([["config.toml", await readFile(config)]]);
      expect(() => assertQualificationInputsUnchanged([
        ["model defaults config", initial, current],
      ])).toThrow("model defaults config changed before manifest candidate emission");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("copies one opened regular file into a private executable and isolates later source changes", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-immutable-binary-"));
    const source = resolve(root, "source");
    try {
      await writeFile(source, "first", { mode: 0o700 });
      const copy = await prepareImmutableQualificationBinary(source, root);
      expect(await readFile(copy.path, "utf8")).toBe("first");
      await writeFile(source, "second", { mode: 0o700 });
      expect(await readFile(copy.path, "utf8")).toBe("first");
      const metadata = await lstat(copy.path);
      expect(metadata.isFile()).toBe(true);
      expect(metadata.isSymbolicLink()).toBe(false);
      expect(metadata.nlink).toBe(1);
      expect(metadata.mode & 0o777).toBe(0o500);
      await rm(copy.directory, { recursive: true, force: true });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a symbolic-link source", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-immutable-binary-link-"));
    const source = resolve(root, "source");
    const link = resolve(root, "link");
    try {
      await writeFile(source, "binary", { mode: 0o700 });
      await symlink(source, link);
      await expect(prepareImmutableQualificationBinary(link, root)).rejects.toThrow("not a symbolic link");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("removes the private copy after successful and failed work", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-immutable-binary-cleanup-"));
    const source = resolve(root, "source");
    try {
      await writeFile(source, "binary", { mode: 0o700 });
      let successfulDirectory = "";
      expect(await withImmutableQualificationBinary(source, root, async (copy) => {
        successfulDirectory = copy.directory;
        expect(await readFile(copy.path, "utf8")).toBe("binary");
        return "complete";
      })).toBe("complete");
      await expect(lstat(successfulDirectory)).rejects.toThrow();

      let failedDirectory = "";
      await expect(withImmutableQualificationBinary(source, root, async (copy) => {
        failedDirectory = copy.directory;
        throw new Error("work failed");
      })).rejects.toThrow("work failed");
      await expect(lstat(failedDirectory)).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("pricing transport isolation", () => {
  test("rejects redirects without forwarding provider or endpoint credentials", async () => {
    const keyNames = ["MODEL_API_KEY", "LLM_API_KEY", "OPENROUTER_API_KEY", "POSTIL_API_KEY"] as const;
    const authNames = ["POSTIL_ENDPOINT_AUTH_HEADER", "POSTIL_ENDPOINT_AUTH_VALUE"] as const;
    const inherited = new Map([...keyNames, ...authNames].map((name) => [name, process.env[name]]));
    for (const name of [...keyNames, ...authNames]) delete process.env[name];

    const targetRequests: IncomingMessage[] = [];
    const target = await listen((request, response) => {
      targetRequests.push(request);
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"data":[]}');
    });
    try {
      for (const scenario of [
        { format: "openai-compatible" as const, status: 301, providerHeader: "authorization" },
        { format: "anthropic" as const, status: 302, providerHeader: "x-api-key" },
        { format: "openai-compatible" as const, status: 303, providerHeader: "authorization" },
        { format: "anthropic" as const, status: 307, providerHeader: "x-api-key" },
        { format: "openai-compatible" as const, status: 308, providerHeader: "authorization" },
      ]) {
        process.env.MODEL_API_KEY = "test-provider-credential";
        process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Endpoint-Auth";
        process.env.POSTIL_ENDPOINT_AUTH_VALUE = "test-endpoint-credential";
        let sourceHeaders: IncomingMessage["headers"] | undefined;
        const source = await listen((request, response) => {
          sourceHeaders = request.headers;
          response.writeHead(scenario.status, { location: `${target.origin}/captured` });
          response.end();
        });
        try {
          await expect(fetchPricing(`${source.origin}/v1`, scenario.format, ["provider/model"], "PinnedProvider"))
            .rejects.toThrow("pricing redirects are not allowed");
          expect(sourceHeaders?.[scenario.providerHeader]).toBe(
            scenario.format === "openai-compatible"
              ? "Bearer test-provider-credential"
              : "test-provider-credential",
          );
          expect(sourceHeaders?.["x-endpoint-auth"]).toBe("test-endpoint-credential");
          expect(targetRequests).toHaveLength(0);
        } finally {
          await close(source.server);
        }
      }
    } finally {
      await close(target.server);
      for (const [name, value] of inherited) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});

describe("managed admission workflow", () => {
  test("pins OpenRouter and isolates candidate output from the checkout", async () => {
    const workflow = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "bench-live.yml"),
    ).text();
    expect(workflow).toContain("POSTIL_API_BASE: https://openrouter.ai/api/v1");
    expect(workflow).toContain("POSTIL_API_FORMAT: openai-compatible");
    expect(workflow).toContain("POSTIL_BENCH_REPEATS: \"3\"");
    expect(workflow).toContain("POSTIL_BENCH_PAIRS: ${{ inputs.pairs }}");
    expect(workflow).toContain("upstream_provider:");
    expect(workflow).toContain("POSTIL_BENCH_UPSTREAM_PROVIDER: ${{ inputs.upstream_provider }}");
    expect(workflow).toContain('echo "POSTIL_MANIFEST_OUT=${RUNNER_TEMP}/postil-qualified-models-${suffix}.json"');
    expect(workflow).toContain('>> "$GITHUB_ENV"');
    expect(workflow).toContain('test "$GITHUB_REF" = "refs/heads/main"');
    expect(workflow).toContain('rm -f "$POSTIL_REPORT_OUT" "$POSTIL_MANIFEST_OUT" "$POSTIL_ATTESTATION_BUNDLE_OUT"');
    expect(workflow).toContain('--manifest-out "$POSTIL_MANIFEST_OUT"');
    expect(workflow).toContain("POSTIL_QUALIFICATION_SOURCE_SHA: ${{ github.sha }}");
    expect(workflow).toContain("uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4");
    expect(workflow).toContain("subject-path: ${{ env.POSTIL_MANIFEST_OUT }}");
    expect(workflow).toContain("${{ steps.attest-candidate.outputs.bundle-path }}");
    expect(workflow).toContain("${{ env.POSTIL_ATTESTATION_BUNDLE_OUT }}");
    expect(workflow).toMatch(/name: Upload admission report\n\s+if: always\(\)/u);
    expect(workflow).toMatch(/name: Upload admitted candidate\n\s+if: success\(\)/u);
    expect(workflow).not.toContain("$GITHUB_WORKSPACE/qualified-models.json");
    expect(workflow).not.toContain("inputs.api_base");
    expect(workflow).not.toContain("inputs.api_format");
    expect(workflow).not.toContain("POSTIL_BENCH_MODELS");
    const ci = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "ci.yml"),
    ).text();
    expect(ci).toContain("bun run verify-admission");
    expect(ci).toMatch(/bench:\n[\s\S]*?fetch-depth: 0/u);
    const release = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "release.yml"),
    ).text();
    expect(release).toMatch(/validate-tag:\n[\s\S]*?fetch-depth: 0[\s\S]*?bun-version: 1\.3\.14[\s\S]*?bun install --frozen-lockfile[\s\S]*?bun run verify-admission[\s\S]*?\n  build:\n/u);
    expect(release).toMatch(/build:\n\s+needs: validate-tag/u);
    let checkedReferences = 0;
    const workflowGlob = new Bun.Glob("*.yml");
    for await (const workflowName of workflowGlob.scan(resolve(import.meta.dir, "..", "..", ".github", "workflows"))) {
      const source = await Bun.file(resolve(import.meta.dir, "..", "..", ".github", "workflows", workflowName)).text();
      const actionReferences = [...source.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?$/gmu)];
      checkedReferences += actionReferences.length;
      expect({
        workflowName,
        mutable: actionReferences.filter((match) => !/@[0-9a-f]{40}$/u.test(match[1] ?? "")),
      }).toEqual({ workflowName, mutable: [] });
      expect({
        workflowName,
        unlabelled: actionReferences.filter((match) => (match[2] ?? "").length === 0),
      }).toEqual({ workflowName, unlabelled: [] });
    }
    expect(checkedReferences).toBeGreaterThan(0);
  });
});

describe("qualification report", () => {
  test("binds the exact fixture matrix and evaluator toolchain sources", () => {
    // livemodels validates and snapshots these inputs at module initialization.
    const exact = fixtureInputs as BenchmarkCase[];
    expect(() => assertExactQualificationFixtures(exact)).not.toThrow();
    const changed = exact.map((candidate, index) => index === 0
      ? { ...candidate, name: `${candidate.name} substituted` }
      : candidate);
    expect(() => assertExactQualificationFixtures(changed)).toThrow("exact embedded fixture matrix");
    expect(EVALUATOR_CONTRACT_SOURCE_PATHS).toContain("bench/package.json");
    expect(EVALUATOR_CONTRACT_SOURCE_PATHS).toContain("bench/bun.lock");
  });
  test("matches the runtime named-source framing vector", () => {
    expect(hashNamedSources([
      ["a.txt", Buffer.from("alpha")],
      ["b/β.txt", Buffer.from("line\n")],
    ])).toBe("1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba");
  });

  test("emits the exact cross-language admission manifest vector", async () => {
    const profileMaterial = {
      qualificationSourceSha: "9".repeat(40),
      modelDefaultsSha256: "c".repeat(64),
      reportSha256: "e".repeat(64),
      apiBase: "https://openrouter.ai:443/api/v1",
      apiFormat: "openai-compatible" as const,
      benchmarkProviderIdentity: MANAGED_OPENROUTER_PROVIDER_IDENTITY,
      upstreamProviderIdentity: "test-provider",
      generatorModels: ["provider/one", "provider/two"],
      consensus: 2,
      scorerModels: ["provider/scorer"],
      modelPriceBounds: [
        {
          model: "provider/one",
          inputMicrosPerMillionTokens: 1_000_000,
          outputMicrosPerMillionTokens: 2_000_000,
        },
        {
          model: "provider/scorer",
          inputMicrosPerMillionTokens: 3_000_000,
          outputMicrosPerMillionTokens: 4_000_000,
        },
        {
          model: "provider/two",
          inputMicrosPerMillionTokens: 5_000_000,
          outputMicrosPerMillionTokens: 6_000_000,
        },
      ],
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      evaluatorContractHash: "f".repeat(64),
      evaluatorRuntimeIdentity: "bun@1.3.14",
      evaluatorEvidenceSha256: "e".repeat(64),
      configHash: "c".repeat(64),
      cliBinaryHash: "d".repeat(64),
      repeats: 3,
    };
    const profile = { id: qualificationProfileDigest(profileMaterial), ...profileMaterial };
    expect(profile.id).toBe("24cd24ba19e6125b6c1b152c77c0860efffdc87c2f3db3bc9fb6fb70768e35ce");
    const vector = await Bun.file(
      resolve(import.meta.dir, "..", "admission-manifest-candidate-vector.json"),
    ).json();
    expect(admissionManifestCandidate(
      "9".repeat(40),
      "c".repeat(64),
      [profile],
      1_800_000_000,
    )).toEqual(vector);
    expect(() => admissionManifestCandidate(
      "9".repeat(40),
      "c".repeat(64),
      [{ ...profile, benchmarkProviderIdentity: null }],
      1_800_000_000,
    )).toThrow("canonical managed OpenRouter endpoint and provider identity");
  });

  test("prints attributable metrics, hashes, provider, and bounded costs", () => {
    const cost = 0.123456;
    const report: LiveModelsReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      qualificationSourceSha: "9".repeat(40),
      cliVersion: "postil 0.6.1",
      apiBase: "https://example.test/v1",
      apiFormat: "openai-compatible",
      providerEndpointIdentity: "https://example.test:443/v1",
      upstreamProviderPinned: true,
      upstreamProviderIdentity: "PinnedProvider",
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      evaluatorContractHash: "f".repeat(64),
      evaluatorRuntimeIdentity: "bun@1.3.14",
      attributionContractHash: "1".repeat(64),
      attributionBankHash: "2".repeat(64),
      attributionEvaluators: [],
      configHash: "d".repeat(64),
      cliBinaryHash: "c".repeat(64),
      evidenceHash: "e".repeat(64),
      hostedOperationCostCapMicros: 1_000_000,
      repeats: 3,
      profiles: [],
      manifestCandidate: {
        version: 1,
        qualificationSourceSha: "9".repeat(40),
        modelDefaultsSha256: "d".repeat(64),
        qualificationIssuedAtUnixSeconds: 1_800_000_000,
        qualificationExpiresAtUnixSeconds: 1_802_592_000,
        qualificationMaxAgeDays: 30,
        profiles: [],
      },
      passed: false,
      models: [],
      modelAggregates: [{
        id: "test/generator + test/scorer",
        generatorModel: "test/generator",
        generatorModels: ["test/generator"],
        scorerModel: "test/scorer",
        repeats: 3,
        mustBlockRecall: 1,
        mustBlockFinalBlockingRate: 1,
        advisoryDetectionRate: 0.95,
        advisoryOverblockRate: 0,
        cleanFalseBlocks: 0,
        cleanFindingFalsePositiveRate: 0,
        unrelatedFindings: 0,
        casesRun: 183,
        meanCostUsdPerReview: cost,
        meanDurationMs: 1200,
        p95DurationMs: 1200,
        maxDurationMs: 1200,
        totalCostUsd: cost,
        mustBlockCases: 102,
        mustBlockDetected: 102,
        mustBlockFinalBlocking: 102,
        advisoryCases: 45,
        advisoryDetected: 43,
        advisoryOverblocked: 0,
        cleanCases: 36,
        errors: 0,
        pricingKnown: true,
        fidelityFailures: 0,
        structuredOutputFailures: 0,
        usageFailures: 0,
        providerExactCases: 183,
        catalogEstimateCases: 0,
        admissionFailures: ["mean cost exceeds admission limit"],
        passed: false,
      }],
      totalRunCostUsd: cost,
      totalRunCostUsdDecimal: "0.123456",
      exactSuccessfulCostUsdDecimal: "0.123456",
      failedOrUnknownExposureUsdDecimal: "0",
      costAccountingComplete: true,
      reservedQualificationExposureUsdDecimal: "0.123456",
      attributionRunCostUsdDecimal: "0",
      attributionFailedExposureUsdDecimal: "0",
      attributionRunCostUsd: 0.001,
      attributionProviderCalls: 2,
      cases: [],
    };

    const output = formatLiveModelsReport(report);
    expect(output).toContain("block");
    expect(output).toContain("adv");
    expect(output).toContain("Fixture aaaa");
    expect(output).toContain("Provider endpoint https://example.test:443/v1; upstream PinnedProvider pinned for every qualification call; 3 complete repeats");
    expect(output).toContain("$0.1235");
    expect(output).toContain("exact successful $0.123456");
    expect(output).toContain("FAIL: mean cost exceeds admission limit");
    expect(liveModelsQualificationExitCode(report)).toBe(1);
  });

  test("derives exact sorted price bounds for the generator and scorer union", () => {
    const shared = { generatorModel: "provider/shared", scorerModel: "provider/shared" };
    expect(modelPriceBoundsFor(shared, new Map([["provider/shared", {
      promptUsdPerToken: 0.000001,
      completionUsdPerToken: 0.000002,
      inputMicrosPerMillionTokens: 1_000_000,
      outputMicrosPerMillionTokens: 2_000_000,
    }]]))).toEqual([{
      model: "provider/shared",
      inputMicrosPerMillionTokens: 1_000_000,
      outputMicrosPerMillionTokens: 2_000_000,
    }]);

    expect(() => modelPriceBoundsFor(pair, new Map())).toThrow(
      "qualification price bound missing for test/generator",
    );
    expect(() => modelPriceBoundsFor(pair, new Map([
      [pair.generatorModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 0,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
      [pair.scorerModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
    ]))).toThrow("must be a positive safe integer");
  });
});
