import { afterEach, describe, expect, test } from "bun:test";
import { link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { privateEvidenceSha256, type LiveModelsPrivateEvidenceBundle, type LiveModelsReport } from "./livemodels";
import { atomicWriteOutput, invalidateExplicitOutputs, prepareExplicitOutputs, writePrivateEvidenceBundle } from "./run";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "postil-bench-output-"));
  temporaryDirectories.push(path);
  return path;
}

function emptyReport(privateEvidenceDigest: string): LiveModelsReport {
  return {
    schemaVersion: 2,
    generatedAt: "2026-07-16T00:00:00.000Z",
    qualificationSourceSha: "9".repeat(40),
    cliVersion: "postil 0.6.4",
    apiBase: "https://openrouter.ai:443/api/v1",
    apiFormat: "openai-compatible",
    providerEndpointIdentity: "openrouter:managed-routing",
    upstreamProviderPinned: true,
    upstreamProviderIdentity: "PinnedProvider",
    fixtureHash: "a".repeat(64),
    reviewContractHash: "b".repeat(64),
    evaluatorContractHash: "c".repeat(64),
    evaluatorRuntimeIdentity: "bun@1.3.14",
    configHash: "d".repeat(64),
    cliBinaryHash: "e".repeat(64),
    evidenceHash: "f".repeat(64),
    privateEvidenceSha256: privateEvidenceDigest,
    attributionContractHash: "1".repeat(64),
    attributionBankHash: "2".repeat(64),
    attributionEvaluators: [],
    hostedOperationCostCapMicros: 1_000_000,
    repeats: 3,
    profiles: [],
    passed: false,
    models: [],
    modelAggregates: [],
    totalRunCostUsd: 0,
    totalRunCostUsdDecimal: "0",
    exactSuccessfulCostUsdDecimal: "0",
    failedOrUnknownExposureUsdDecimal: "0",
    costAccountingComplete: true,
    reservedQualificationExposureUsdDecimal: "0",
    attributionRunCostUsd: 0,
    attributionRunCostUsdDecimal: "0",
    attributionFailedExposureUsdDecimal: "0",
    attributionProviderCalls: 0,
    cases: [],
  };
}

describe("benchmark output lifecycle", () => {
  test("cleans and rejects one path used for both evidence and a candidate", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "report.json");
    await writeFile(path, "stale");
    await expect(prepareExplicitOutputs(path, path)).rejects.toThrow(
      "--json-out and --manifest-out must use different paths",
    );
    expect(await Bun.file(path).exists()).toBe(false);
  });

  test("rejects output paths whose parents are filesystem aliases", async () => {
    const directory = await temporaryDirectory();
    const realDirectory = join(directory, "real");
    const aliasDirectory = join(directory, "alias");
    await mkdir(realDirectory);
    await symlink(realDirectory, aliasDirectory, "dir");
    await expect(
      prepareExplicitOutputs(join(realDirectory, "artifact.json"), join(aliasDirectory, "artifact.json")),
    ).rejects.toThrow("--json-out and --manifest-out must use different paths");
  });

  test("accepts distinct prospective outputs below a missing parent", async () => {
    const directory = await temporaryDirectory();
    const missing = join(directory, "missing", "nested");
    await expect(prepareExplicitOutputs(
      join(missing, "report.json"),
      join(missing, "candidate.json"),
      join(missing, "private.json"),
    )).resolves.toBeUndefined();
  });

  test("rejects prospective outputs below aliased missing parents", async () => {
    const directory = await temporaryDirectory();
    const realDirectory = join(directory, "real");
    const aliasDirectory = join(directory, "alias");
    await mkdir(realDirectory);
    await symlink(realDirectory, aliasDirectory, "dir");
    await expect(prepareExplicitOutputs(
      join(realDirectory, "missing", "artifact.json"),
      join(aliasDirectory, "missing", "artifact.json"),
    )).rejects.toThrow("--json-out and --manifest-out must use different paths");
  });

  test("cleans and rejects existing hardlinked output aliases", async () => {
    const directory = await temporaryDirectory();
    const report = join(directory, "report.json");
    const candidate = join(directory, "candidate.json");
    await writeFile(report, "stale");
    await link(report, candidate);
    await expect(prepareExplicitOutputs(report, candidate)).rejects.toThrow(
      "--json-out and --manifest-out must use different paths",
    );
    expect(await Bun.file(report).exists()).toBe(false);
    expect(await Bun.file(candidate).exists()).toBe(false);
  });

  test("rejects a private evidence path aliased to a public output", async () => {
    const directory = await temporaryDirectory();
    const report = join(directory, "report.json");
    const manifest = join(directory, "manifest.json");
    await expect(prepareExplicitOutputs(report, manifest, report)).rejects.toThrow(
      "report, manifest, and private evidence outputs must use different paths",
    );
  });

  test("atomically replaces and explicitly invalidates output files", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "report.json");
    await writeFile(path, "stale");
    await atomicWriteOutput(path, "current\n");
    expect(await readFile(path, "utf8")).toBe("current\n");
    expect((await readdir(directory)).filter((entry) => entry.endsWith(".tmp"))).toEqual([]);
    await invalidateExplicitOutputs([path]);
    expect(await Bun.file(path).exists()).toBe(false);
  });

  test("persists private replay evidence as mode 0600 and verifies it after readback", async () => {
    const directory = await temporaryDirectory();
    const path = join(directory, "private.json");
    const bundle: LiveModelsPrivateEvidenceBundle = {
      schemaVersion: 1,
      qualificationSourceSha: "9".repeat(40),
      cliBinaryHash: "e".repeat(64),
      attributionEvaluators: [],
      cases: [],
    };
    const report = emptyReport(privateEvidenceSha256(bundle));

    await writePrivateEvidenceBundle(path, bundle, report);

    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect(await readFile(path, "utf8")).toContain('"schemaVersion": 1');
  });

  test("removes stale explicit outputs before a live preflight failure", async () => {
    const directory = await temporaryDirectory();
    const report = join(directory, "report.json");
    const candidate = join(directory, "candidate.json");
    await Promise.all([writeFile(report, "stale report"), writeFile(candidate, "stale candidate")]);
    const child = Bun.spawn({
      cmd: [
        process.execPath,
        "run",
        resolve(import.meta.dir, "run.ts"),
        "--json-out",
        report,
        "--manifest-out",
        candidate,
      ],
      cwd: resolve(import.meta.dir, ".."),
      env: { ...process.env, POSTIL_BENCH_MODE: "live", POSTIL_BENCH_PAIRS: "" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("qualification pair list contains an empty");
    expect(await Bun.file(report).exists()).toBe(false);
    expect(await Bun.file(candidate).exists()).toBe(false);
  });

  test("rejects manifest output in mock mode and removes a stale candidate", async () => {
    const directory = await temporaryDirectory();
    const candidate = join(directory, "candidate.json");
    await writeFile(candidate, "stale candidate");
    const child = Bun.spawn({
      cmd: [process.execPath, "run", resolve(import.meta.dir, "run.ts"), "--manifest-out", candidate],
      cwd: resolve(import.meta.dir, ".."),
      env: { ...process.env, POSTIL_BENCH_MODE: "mock" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("only in live-models admission mode");
    expect(await Bun.file(candidate).exists()).toBe(false);
  });

  test("removes the supplied artifact when the other output flag lacks a path", async () => {
    const directory = await temporaryDirectory();
    const report = join(directory, "report.json");
    await writeFile(report, "stale report");
    const child = Bun.spawn({
      cmd: [
        process.execPath,
        "run",
        resolve(import.meta.dir, "run.ts"),
        "--json-out",
        report,
        "--manifest-out",
      ],
      cwd: resolve(import.meta.dir, ".."),
      env: { ...process.env, POSTIL_BENCH_MODE: "live" },
      stdout: "pipe",
      stderr: "pipe",
    });
    expect(await child.exited).toBe(1);
    expect(await new Response(child.stderr).text()).toContain("--manifest-out requires a path");
    expect(await Bun.file(report).exists()).toBe(false);
  });
});
