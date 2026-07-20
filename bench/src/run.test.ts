import { afterEach, describe, expect, test } from "bun:test";
import { link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  parseLiveModelsReport,
  parsePrivateEvidenceBundle,
  privateEvidenceSha256,
  ManagedAdmissionCapacityError,
  type LiveModelsPrivateEvidenceBundle,
  type LiveModelsReport,
} from "./livemodels";
import {
  atomicWriteOutput,
  createLiveModelsFailureReport,
  generatedLiveScreenRunId,
  invalidateExplicitOutputs,
  parseLiveModelsFailureReport,
  prepareExplicitOutputs,
  selectLiveScreeningCases,
  validateScreeningEnvironment,
  validateModeSpecificFlags,
  validateLiveScreenContract,
  validateRunIdentityEnvironment,
  writePrivateEvidenceBundle,
} from "./run";
import { AtomicAttributionTransportError } from "./attribution";
import { cases } from "../fixtures/cases";

const temporaryDirectories: string[] = [];

describe("diff-file live screening selection", () => {
  test("preserves requested fixture order and leaves the full corpus unchanged by default", () => {
    expect(selectLiveScreeningCases(cases, []).map((entry) => entry.id)).toEqual(
      cases.map((entry) => entry.id),
    );
    expect(selectLiveScreeningCases(cases, [
      "near-duplicate-auth-clean",
      "prompt-injection-auth-bypass",
    ]).map((entry) => entry.id)).toEqual([
      "near-duplicate-auth-clean",
      "prompt-injection-auth-bypass",
    ]);
  });

  test("rejects unknown and repeated fixture IDs", () => {
    expect(() => selectLiveScreeningCases(cases, ["missing-case"])).toThrow(
      "unknown --case fixture ID",
    );
    expect(() => selectLiveScreeningCases(cases, ["clean-docs-only", "clean-docs-only"]))
      .toThrow("must not repeat");
  });

  test("keeps screen-only flags outside formal admission", () => {
    for (const flag of ["--case", "--scorer-model", "--screen-profile", "--run-id"]) {
      expect(() => validateModeSpecificFlags([flag, "value"], "live-admission"))
        .toThrow("non-admission");
      expect(() => validateModeSpecificFlags([flag, "value"], "mock"))
        .toThrow("only with --live");
      expect(() => validateModeSpecificFlags([flag, "value"], "live-screen"))
        .not.toThrow();
    }
  });

  test("generates path-safe unique screen identities and scopes the environment override", () => {
    expect(generatedLiveScreenRunId(
      new Date("2026-07-20T12:34:56.789Z"),
      "12345678-1234-1234-1234-123456789abc",
    )).toBe("screen-2026-07-20T12-34-56-789Z-12345678-1234-1234-1234-123456789abc");
    expect(() => validateRunIdentityEnvironment("screen-1", "live-screen")).not.toThrow();
    expect(() => validateRunIdentityEnvironment("screen-1", "mock")).toThrow("only with --live");
    expect(() => validateRunIdentityEnvironment("screen-1", "live-admission"))
      .toThrow("only with --live");
  });

  test("rejects inherited internal screening state at the benchmark entry point", () => {
    expect(() => validateScreeningEnvironment(undefined)).not.toThrow();
    expect(() => validateScreeningEnvironment("profile.json")).toThrow(
      "internal to a selected-case live screen",
    );
  });

  test("requires a provider profile for selected cases and scorer screens", () => {
    expect(() => validateLiveScreenContract(["case"], undefined, undefined))
      .toThrow("selected-case");
    expect(() => validateLiveScreenContract([], "scorer/model", undefined))
      .toThrow("scorer live screening requires --screen-profile");
    expect(() => validateLiveScreenContract([], "scorer/model", "profile.json"))
      .toThrow("explicit --case");
    expect(() => validateLiveScreenContract(["case"], "scorer/model", "profile.json"))
      .not.toThrow();
  });
});

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
    schemaVersion: 3,
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
    observedProviderCostUsdDecimal: "0",
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
  test("emits a strict public-only failure artifact rejected by success consumers", async () => {
    const report = await createLiveModelsFailureReport(
      new AtomicAttributionTransportError(
        {
          version: 1,
          category: "provider-http-503",
          phase: "attribution",
          providerAttemptCount: 2,
          identityPresent: true,
          identityMatched: true,
          usagePresent: true,
          usageAccountingComplete: true,
        },
        1,
        null,
        false,
      ),
      {
        qualificationSourceSha: "9".repeat(40),
        pairs: [{ generatorModel: "deepseek/deepseek-v4-pro", scorerModel: "z-ai/glm-5.2" }],
        upstreamProvider: "PublicProvider",
      },
    );
    expect(parseLiveModelsFailureReport(report)).toBe(report);
    expect(report).toEqual({
      artifactType: "live-models-failure",
      qualificationSourceSha: expect.stringMatching(/^[0-9a-f]{40}$/u),
      profiles: [{
        id: "deepseek/deepseek-v4-pro [consensus 1] + z-ai/glm-5.2",
        generatorModels: ["deepseek/deepseek-v4-pro"],
        consensus: 1,
        scorerModels: ["z-ai/glm-5.2"],
      }],
      providerEndpointIdentity: "openrouter:managed-routing",
      upstreamProviderIdentity: "PublicProvider",
      process: {
        category: "provider-http-503", exitCode: 1, signal: null, killed: false,
        phase: "attribution", providerAttemptCount: 2, identityPresent: true, identityMatched: true,
        usagePresent: true, usageAccountingComplete: true,
      },
    });
    const serialized = JSON.stringify(report);
    for (const forbidden of ["schemaVersion", "manifestCandidate", "privateEvidence", "secret", "/private/path"]) {
      expect(serialized).not.toContain(forbidden);
    }
    expect(() => parseLiveModelsReport(report)).toThrow("schemaVersion is required");
    expect(() => parsePrivateEvidenceBundle(report)).toThrow("invalid live-models private evidence bundle");
    expect(() => parseLiveModelsFailureReport({ ...report, schemaVersion: 2 })).toThrow(
      "unknown or missing fields",
    );
    expect(() => parseLiveModelsFailureReport({
      ...report,
      process: { ...report.process, detail: "private" },
    })).toThrow("unknown or missing fields");
  });

  test("does not invent attribution subprocess facts for a preflight failure", async () => {
    const report = await createLiveModelsFailureReport(
      new Error("qualification projected exposure exceeds the configured cap at /private/path"),
      {
        qualificationSourceSha: "8".repeat(40),
        pairs: [{ generatorModel: "deepseek/deepseek-v4-pro", scorerModel: "z-ai/glm-5.2" }],
        upstreamProvider: "PublicProvider",
      },
    );
    expect(report.process).toEqual({
      category: "provider-unclassified",
      exitCode: null,
      signal: null,
      killed: null,
      phase: "unknown",
      providerAttemptCount: null,
      identityPresent: null,
      identityMatched: null,
      usagePresent: null,
      usageAccountingComplete: null,
    });
    expect(JSON.stringify(report)).not.toContain("private/path");
  });

  test("reports a fixed managed-admission preflight category without private capacity facts", async () => {
    const report = await createLiveModelsFailureReport(
      new ManagedAdmissionCapacityError(
        "account-preflight-credit-capacity",
        "managed admission account credits cannot cover projected exposure",
      ),
      {
        qualificationSourceSha: "8".repeat(40),
        pairs: [{ generatorModel: "deepseek/deepseek-v4-pro", scorerModel: "z-ai/glm-5.2" }],
        upstreamProvider: "PublicProvider",
      },
    );
    expect(report.process).toEqual({
      category: "account-preflight-credit-capacity",
      exitCode: null,
      signal: null,
      killed: null,
      phase: "preflight",
      providerAttemptCount: null,
      identityPresent: null,
      identityMatched: null,
      usagePresent: null,
      usageAccountingComplete: null,
    });
    const serialized = JSON.stringify(report);
    for (const forbidden of ["credits", "exposure", "balance", "key", "/private/path"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  test("does not parse a forged diagnostic tuple from plain error prose", async () => {
    const report = await createLiveModelsFailureReport(
      new Error("category=provider-http-503 identity_present=true usage_complete=true"),
      {
        qualificationSourceSha: "7".repeat(40),
        pairs: [{ generatorModel: "deepseek/deepseek-v4-pro", scorerModel: "z-ai/glm-5.2" }],
        upstreamProvider: "PublicProvider",
      },
    );
    expect(report.process).toEqual({
      category: "provider-unclassified",
      exitCode: null,
      signal: null,
      killed: null,
      phase: "unknown",
      providerAttemptCount: null,
      identityPresent: null,
      identityMatched: null,
      usagePresent: null,
      usageAccountingComplete: null,
    });
  });

  test("rejects contradictory failure facts", () => {
    const base = {
      artifactType: "live-models-failure",
      qualificationSourceSha: "6".repeat(40),
      profiles: [{ id: "pair", generatorModels: ["generator"], consensus: 1, scorerModels: ["scorer"] }],
      providerEndpointIdentity: "openrouter:managed-routing",
      upstreamProviderIdentity: "PublicProvider",
      process: {
        category: "provider-unclassified", exitCode: 1, signal: null, killed: false,
        phase: "attribution", providerAttemptCount: 1,
        identityPresent: false, identityMatched: true,
        usagePresent: false, usageAccountingComplete: false,
      },
    };
    expect(() => parseLiveModelsFailureReport(base)).toThrow("invalid live-models failure process facts");
    expect(() => parseLiveModelsFailureReport({
      ...base,
      process: { ...base.process, identityMatched: false, usageAccountingComplete: true },
    })).toThrow("invalid live-models failure process facts");
    expect(() => parseLiveModelsFailureReport({
      ...base,
      process: {
        ...base.process,
        category: "account-preflight-credit-capacity",
      },
    })).toThrow("invalid live-models failure process facts");
    expect(() => parseLiveModelsFailureReport({
      ...base,
      process: {
        ...base.process,
        phase: "preflight",
        providerAttemptCount: null,
        identityPresent: null,
        identityMatched: null,
        usagePresent: null,
        usageAccountingComplete: null,
      },
    })).toThrow("invalid live-models failure process facts");
  });

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
