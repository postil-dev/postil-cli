import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase, envelopeV1, type BenchmarkCase } from "./harness";
import type { AttributionCallEvidence } from "./attribution";
import {
  admissionManifestCandidate,
  assertPromptInjectionCleanAdmissionRegression,
  assertManagedAdmissionCapacityPreflight,
  assertGitTreeSourceAuthority,
  assertPricingProviderIdentity,
  assertExactQualificationFixtures,
  assertQualificationInputsUnchanged,
  assertQualificationSourceAuthorityUnchanged,
  assertRuntimeShapedQualificationPreflight,
  benchmarkProviderIdentityFor,
  canonicalQualificationCostCap,
  endpointAuthFromEnvironment,
  EVALUATOR_CONTRACT_SOURCE_PATHS,
  fetchPricing,
  formatLiveModelsReport,
  hashNamedSources,
  liveEnv,
  liveModelsQualificationExitCode,
  liveModelsCostAccountingComplete,
  MANAGED_OPENROUTER_PROVIDER_IDENTITY,
  modelPriceBoundsFor,
  modelExecutionIntegrityFailures,
  normalizeApiBase,
  normalizeQualificationPairs,
  parseLiveModelsReport,
  parseQualificationPairs,
  planQualificationJobs,
  prepareImmutableQualificationBinary,
  PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
  PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS,
  prepareAttributionEvaluatorEnvironment,
  pricingFromFile,
  privateEvidenceSha256,
  qualificationCandidateDocument,
  qualificationCaseRepeats,
  qualificationRequiredParameters,
  qualificationProfileDigest,
  qualificationProfileDigestMaterial,
  readPinnedQualificationWorktreeFile,
  runLiveModels,
  runQualificationCanariesSequentially,
  BINARY_SOURCE_PATHS,
  REVIEW_CONTRACT_SOURCE_PATHS,
  summarizeAttributionEvaluator,
  verifyPrivateEvidenceBundle,
  withImmutableQualificationBinary,
  type LiveModelsReport,
} from "./livemodels";
import {
  compareCanonicalDecimals,
  MAX_GENERATOR_COST_CAP_USD,
  parseCanonicalDecimal,
  qualificationPairId,
  type LiveModelCaseResult,
  type QualificationPair,
} from "./livemodels-score";
import { evaluatorSourceSha256 } from "./live";

const pair: QualificationPair = { generatorModel: "test/generator", scorerModel: "test/scorer" };

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function cleanPromptInjectionCanary(repeat: number): LiveModelCaseResult {
  return {
    id: PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
    name: "Prompt injection hidden in a harmless comment",
    pairId: qualificationPairId(pair),
    generatorModel: "test/generator",
    generatorModels: ["test/generator"],
    scorerModel: "test/scorer",
    repeat,
    classification: "clean",
    scored: true,
    detected: null,
    unrelatedFindings: 0,
    attributedFinalBlocker: false,
    unrelatedFinalBlockers: 0,
    finalBlocking: false,
    gateFailingActual: false,
    findingEvidence: [],
    promptTokens: 100,
    completionTokens: 10,
    usageAccountingComplete: true,
    usageValid: true,
    costProvenance: "providerExact",
    costProviderDecimal: "0.001",
    usageCostEvidence: [{
      model: "test/generator",
      role: "reviewGenerator",
      phase: "initial",
      callOrdinal: 1,
      attempt: 1,
      promptTokens: 100,
      completionTokens: 10,
      accountingComplete: true,
      costProvenance: "providerExact",
      costProviderDecimal: "0.001",
      costCatalogEstimateDecimal: null,
    }],
    costUsd: 0.001,
    durationMs: 100,
    exitCode: 0,
    fidelityDiagnostics: { count: 0, sha256: null },
    structuredOutputDiagnostics: { count: 0, sha256: null },
    attributionEvidence: [],
  };
}

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
  test("always dispatches three clean canaries before broader work", () => {
    const allCases = fixtureInputs.map((input) => benchmarkCase.parse(input));
    const canary = allCases.find((candidate) =>
      candidate.id === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID
    )!;
    const ordinary = allCases.find((candidate) =>
      candidate.id !== PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID
    )!;
    for (const repeats of [1, 2, 3, 4]) {
      expect(qualificationCaseRepeats(PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID, repeats))
        .toBe(Math.max(repeats, 3));
      expect(qualificationCaseRepeats(ordinary.id, repeats)).toBe(repeats);
      const { jobs, canaryIndices } = planQualificationJobs([pair], [ordinary, canary], repeats);
      expect(canaryIndices.map((index) => jobs[index]!.repeat)).toEqual([1, 2, 3]);
      expect(canaryIndices.map((index) => jobs[index]!.case.id)).toEqual([
        PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
        PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
        PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID,
      ]);
      expect(jobs.filter((job) => job.case.id === ordinary.id).map((job) => job.repeat))
        .toEqual(Array.from({ length: repeats }, (_, index) => index + 1));
      expect(jobs.filter((job) =>
        job.case.id === PROMPT_INJECTION_CLEAN_ADMISSION_CASE_ID && job.repeat > 3
      ).map((job) => job.repeat)).toEqual(repeats > 3 ? [4] : []);
    }
  });

  test("aborts the ordered canary sequence at the first failed repeat", async () => {
    const calls: number[] = [];
    await expect(runQualificationCanariesSequentially([4, 8, 12], async (index) => {
      calls.push(index);
      if (index === 8) throw new Error("canary repeat failed");
    })).rejects.toThrow("canary repeat failed");
    expect(calls).toEqual([4, 8]);
  });

  test("requires three silent prompt-injection clean canary repeats", () => {
    const results = Array.from(
      { length: PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS },
      (_, index) => cleanPromptInjectionCanary(index + 1),
    );
    expect(() => assertPromptInjectionCleanAdmissionRegression(
      results,
      [pair],
      PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS,
    )).not.toThrow();
    expect(() => assertPromptInjectionCleanAdmissionRegression(
      results.slice(0, 2),
      [pair],
      PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS,
    )).toThrow("repeat 3 produced 0 result(s)");
  });

  test("rejects generator, scorer, repair, and publication canary failures", () => {
    const finding = {
      atomicAttribution: "unrelated" as const,
      disposition: "final" as const,
      path: "src/lib/readme.ts",
      line: 12,
      severity: "warn",
      kind: "risk",
      confidence: 0.9,
    };
    const failures: Array<[string, LiveModelCaseResult]> = [
      ["final finding(s)", { ...cleanPromptInjectionCanary(1), findingEvidence: [finding] }],
      ["suppressed finding(s)", {
        ...cleanPromptInjectionCanary(1),
        findingEvidence: [{ ...finding, disposition: "suppressed" }],
      }],
      ["generator, repair, or scorer structure", {
        ...cleanPromptInjectionCanary(1),
        structuredOutputDiagnostics: { count: 1, sha256: "a".repeat(64) },
      }],
      ["final publication fidelity", {
        ...cleanPromptInjectionCanary(1),
        fidelityDiagnostics: { count: 1, sha256: "b".repeat(64) },
      }],
      ["exact provider cost", {
        ...cleanPromptInjectionCanary(1),
        costProvenance: "catalogEstimate",
        costProviderDecimal: null,
      }],
      ["model, role, or phase identity", {
        ...cleanPromptInjectionCanary(1),
        usageCostEvidence: [{
          ...cleanPromptInjectionCanary(1).usageCostEvidence[0]!,
          phase: "schemaRepair",
        }],
      }],
    ];
    for (const [message, failed] of failures) {
      const results = [
        failed,
        cleanPromptInjectionCanary(2),
        cleanPromptInjectionCanary(3),
      ];
      expect(() => assertPromptInjectionCleanAdmissionRegression(
        results,
        [pair],
        PROMPT_INJECTION_CLEAN_ADMISSION_REPEATS,
      )).toThrow(message);
    }
  });

  test("rejects recovered incidents, repairs, and fallbacks", () => {
    const base = {
      version: 1 as const,
      summary: "",
      silent: true,
      findings: [],
      suppressedFindings: [],
      resolved: [],
      counts: { info: 0, warn: 0, error: 0, suppressed: 0, ungrounded: 0 },
      confidenceBuckets: [0, 0, 0, 0, 0],
      gate: { failOn: "error", failing: false, blockOnKinds: [] },
      modelUsed: "test/generator",
      usage: { promptTokens: 1, completionTokens: 1 },
      durationMs: 1,
      baseSha: null,
      headSha: null,
      sinceSha: null,
    };
    const repair = envelopeV1.parse({
      ...base,
      modelUsage: [{
        model: "test/generator",
        role: "reviewGenerator",
        phase: "schemaRepair",
        promptTokens: 1,
        completionTokens: 1,
        accountingComplete: true,
      }],
      modelIncidents: [{
        phase: "review",
        category: "invalidOutput",
        recovered: true,
        recovery: "repair",
      }],
    });
    expect(modelExecutionIntegrityFailures(repair)).toEqual([
      "model incident review/invalidOutput/repair",
      "model usage entered schemaRepair",
    ]);
    const fallback = envelopeV1.parse({
      ...base,
      modelIncidents: [{
        phase: "review",
        category: "providerError",
        recovered: true,
        recovery: "fallback",
      }],
    });
    expect(modelExecutionIntegrityFailures(fallback)).toEqual([
      "model incident review/providerError/fallback",
    ]);
  });

  test("keeps provider cost completeness independent from scoring outcome", () => {
    expect(liveModelsCostAccountingComplete([{
      usageAccountingComplete: true,
      costProvenance: "providerExact",
    }], "0")).toBe(true);
    expect(liveModelsCostAccountingComplete([{
      usageAccountingComplete: false,
      costProvenance: "providerExact",
    }], "0")).toBe(false);
    expect(liveModelsCostAccountingComplete([{
      usageAccountingComplete: true,
      costProvenance: "providerExact",
    }], "0.01")).toBe(false);
  });

  test("derives role-specific provider parameters for every model in a profile", () => {
    const pair = {
      generatorModel: "provider/shared",
      generatorCascade: ["provider/generator-fallback"],
      consensus: 2,
      scorerModel: "provider/shared",
      scorerCascade: ["provider/scorer-fallback"],
    };
    expect(qualificationRequiredParameters([pair], "Azure")).toEqual(new Map([
      ["provider/shared", [
        "max_completion_tokens",
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "response_format",
        "structured_outputs",
        "temperature",
      ]],
      ["provider/generator-fallback", [
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "temperature",
      ]],
      ["provider/scorer-fallback", [
        "max_completion_tokens",
        "reasoning",
        "reasoning_effort",
        "response_format",
        "structured_outputs",
      ]],
    ]));
    expect(qualificationRequiredParameters([pair], "OpenAI")).toEqual(new Map([
      ["provider/shared", [
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "response_format",
        "structured_outputs",
        "temperature",
      ]],
      ["provider/generator-fallback", [
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "temperature",
      ]],
      ["provider/scorer-fallback", [
        "max_tokens",
        "reasoning",
        "reasoning_effort",
        "response_format",
        "structured_outputs",
      ]],
    ]));
  });

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
      "http://127.0.0.1:4321",
    )).toMatchObject({
      POSTIL_QUALIFICATION_CANDIDATE_PROFILE: "/tmp/candidate.json",
      POSTIL_QUALIFICATION_CAPTURE_API_BASE: "http://127.0.0.1:4321",
    });
    expect(() => liveEnv(
      "/tmp/home",
      "/tmp/tmp",
      "http://127.0.0.1:1234",
      pair,
      apiBase,
      "openai-compatible",
      undefined,
      "http://127.0.0.1:4321",
    )).toThrow("requires a qualification candidate profile");
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
        "pinned/route",
        "http://127.0.0.1:4321",
      );
      const profilePath = env.POSTIL_QUALIFICATION_CANDIDATE_PROFILE;
      expect(profilePath).toBe(resolve(root, "qualification-candidate.json"));
      expect(env.POSTIL_QUALIFICATION_CAPTURE_API_BASE).toBe("http://127.0.0.1:4321");
      expect(await Bun.file(profilePath!).json()).toMatchObject({
        upstreamProviderIdentity: "PinnedProvider",
        upstreamProviderRoute: "pinned/route",
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
      costCapUsd: 71,
      upstreamProvider: "PinnedProvider",
    })).rejects.toThrow("cost cap must be greater than zero and at most $70");

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

  test("isolates runtime-shaped preflight and routes any provider escape to loopback", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-runtime-preflight-"));
    const binary = resolve(root, "fixture-postil");
    const cases = fixtureInputs.slice(0, 2).map((input) => benchmarkCase.parse(input));
    const runtimePair = normalizeQualificationPairs([pair])[0]!;
    const pricing = new Map([
      [runtimePair.generatorModel, {
        providerIdentity: "PinnedProvider",
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
      [runtimePair.scorerModel, {
        providerIdentity: "PinnedProvider",
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
    ]);
    await writeFile(binary, `#!/usr/bin/env node
const fail = (message) => { console.error(message); process.exit(97); };
if (process.env.POSTIL_QUALIFICATION_PLAN_ONLY !== "1") fail("plan-only mode was not set");
if (process.env.POSTIL_QUALIFICATION_CAPTURE_API_BASE !== "http://127.0.0.1:9") {
  fail("plan-only preflight escaped loopback capture");
}
if (process.env.POSTIL_API_KEY !== "postil-plan-only-fixture") {
  fail("the explicit fixture credential was not forwarded");
}
for (const name of ["MODEL_API_KEY", "LLM_API_KEY", "OPENROUTER_API_KEY", "POSTIL_ENDPOINT_AUTH_VALUE"]) {
  if (process.env[name] !== undefined) fail("ambient credential reached plan-only preflight: " + name);
}
console.log(JSON.stringify({
  version: 1, summary: "", silent: true, findings: [], resolved: [],
  counts: { info: 0, warn: 0, error: 0, suppressed: 0, ungrounded: 0 },
  confidenceBuckets: [0, 0, 0, 0, 0],
  gate: { failOn: "error", failing: false, blockOnKinds: [] },
  modelUsed: "none (qualification plan)", usage: { promptTokens: 0, completionTokens: 0 },
  reviewCoverage: { mode: "exhaustive", selectedBatches: 1, totalBatches: 1 },
  reviewAdmission: { providerAttempts: 6, serializedInputBytes: 5000, outputTokens: 180, projectedCostMicros: 1000000 },
  durationMs: 0, baseSha: null, headSha: null, sinceSha: null
}));
`);
    await chmod(binary, 0o700);
    try {
      await expect(assertRuntimeShapedQualificationPreflight({
        binary,
        rootDir: root,
        cases,
        pairs: [runtimePair],
        repeats: 3,
        pricing,
        apiBase: normalizeApiBase("https://openrouter.ai/api/v1"),
        apiFormat: "openai-compatible",
        costCapUsdDecimal: "1",
        upstreamProvider: "PinnedProvider",
        upstreamProviderRoute: "pinned/route",
        credentialEnvironment: { POSTIL_API_KEY: "postil-plan-only-fixture" },
      })).rejects.toThrow("runtime-shaped qualification spend");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  test("settles every started preflight worker before cleaning a failed workspace", async () => {
    const root = await mkdtemp(resolve(tmpdir(), "postil-runtime-preflight-failure-"));
    const binary = resolve(root, "fixture-postil");
    const startsPath = resolve(root, "starts.log");
    await writeFile(binary, `#!/usr/bin/env node
import { appendFileSync, closeSync, openSync } from "node:fs";
import { resolve } from "node:path";
const root = resolve(process.cwd(), "../../..");
const identity = process.cwd();
appendFileSync(resolve(root, "starts.log"), identity + "\\n");
try {
  closeSync(openSync(resolve(root, "fail-once"), "wx"));
  console.error("deliberate preflight failure");
  process.exit(17);
} catch {}
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 250);
appendFileSync(resolve(root, "finishes.log"), identity + "\\n");
console.log(JSON.stringify({
  version: 1, summary: "", silent: true, findings: [], resolved: [],
  counts: { info: 0, warn: 0, error: 0, suppressed: 0, ungrounded: 0 },
  confidenceBuckets: [0, 0, 0, 0, 0],
  gate: { failOn: "error", failing: false, blockOnKinds: [] },
  modelUsed: "test/generator", usage: { promptTokens: 0, completionTokens: 0 },
  reviewCoverage: { mode: "exhaustive", selectedBatches: 1, totalBatches: 1 },
  reviewAdmission: { providerAttempts: 6, serializedInputBytes: 5000, outputTokens: 180, projectedCostMicros: 1 },
  durationMs: 0, baseSha: null, headSha: null, sinceSha: null
}));
process.exit(0);
`);
    await chmod(binary, 0o700);
    try {
      const cases = fixtureInputs.slice(0, 8).map((input) => benchmarkCase.parse(input));
      const pricing = new Map([
        [pair.generatorModel, {
          providerIdentity: "PinnedProvider",
          promptUsdPerToken: 0.0009478,
          completionUsdPerToken: 0.0029788,
          inputMicrosPerMillionTokens: 947_800,
          outputMicrosPerMillionTokens: 2_978_800,
        }],
        [pair.scorerModel, {
          providerIdentity: "PinnedProvider",
          promptUsdPerToken: 0.0009478,
          completionUsdPerToken: 0.0029788,
          inputMicrosPerMillionTokens: 947_800,
          outputMicrosPerMillionTokens: 2_978_800,
        }],
      ]);
      await expect(assertRuntimeShapedQualificationPreflight({
        binary,
        rootDir: root,
        cases,
        pairs: normalizeQualificationPairs([pair]),
        repeats: 3,
        pricing,
        apiBase: normalizeApiBase("https://openrouter.ai/api/v1"),
        apiFormat: "openai-compatible",
        costCapUsdDecimal: "55",
        upstreamProvider: "PinnedProvider",
        upstreamProviderRoute: "pinned/route",
        credentialEnvironment: { POSTIL_API_KEY: "postil-plan-only-fixture" },
      })).rejects.toThrow("deliberate preflight failure");
      const starts = (await readFile(startsPath, "utf8")).trim().split("\n");
      const finishes = (await readFile(resolve(root, "finishes.log"), "utf8"))
        .trim()
        .split("\n");
      expect(starts.length).toBeGreaterThan(0);
      expect(starts.length).toBeLessThanOrEqual(4);
      expect(finishes).toHaveLength(starts.length - 1);
      expect(new Set(finishes).size).toBe(finishes.length);
      expect(finishes.every((identity) => starts.includes(identity))).toBe(true);
      await expect(lstat(resolve(root, "preflight"))).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 20_000);

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
  test("review contract hashes every regular source file with the required manifests", async () => {
    const repositoryRoot = resolve(import.meta.dir, "../..");
    async function collectReviewSources(directory: string): Promise<string[]> {
      const entries = await readdir(directory, { withFileTypes: true });
      const paths = await Promise.all(entries.sort((left, right) =>
        left.name < right.name ? -1 : left.name > right.name ? 1 : 0)
        .map(async (entry) => entry.isDirectory()
          ? collectReviewSources(resolve(directory, entry.name))
          : entry.isFile()
          ? [resolve(directory, entry.name).slice(repositoryRoot.length + 1).replaceAll("\\", "/")]
          : []));
      return paths.flat();
    }

    const expected = ["Cargo.lock", "Cargo.toml", "build.rs", ...await collectReviewSources(resolve(repositoryRoot, "src"))]
      .sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
    expect(REVIEW_CONTRACT_SOURCE_PATHS).toEqual(expected);
    expect(BINARY_SOURCE_PATHS).toEqual(expected);

    const sources = await Promise.all(REVIEW_CONTRACT_SOURCE_PATHS.map(async (path) =>
      [path, await readFile(resolve(repositoryRoot, path))] as const));
    expect(hashNamedSources(sources)).toMatch(/^[0-9a-f]{64}$/);
  });

  test("rejects source authority drift before broader qualification spend", () => {
    const expected = {
      sourceSha: "a".repeat(40),
      fixtureHash: "b".repeat(64),
      reviewContractHash: "c".repeat(64),
      evaluatorContractHash: "d".repeat(64),
      configHash: "e".repeat(64),
    };
    expect(() => assertQualificationSourceAuthorityUnchanged(expected, expected)).not.toThrow();
    expect(() => assertQualificationSourceAuthorityUnchanged(expected, {
      ...expected,
      configHash: "f".repeat(64),
    })).toThrow("model defaults config changed before broader qualification spend");
  });

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

describe("managed admission capacity preflight", () => {
  const completionApiKey = "completion-secret";
  const managementApiKey = "management-secret";
  const expectedCompletionKeySha256 = sha256(completionApiKey);

  test("requires both the completion-key limit and account credits to cover exposure", async () => {
    const requests: Array<{ url: string; authorization: string | null }> = [];
    const fetchImpl = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      requests.push({
        url,
        authorization: new Headers(init?.headers).get("authorization"),
      });
      const data = url.endsWith("/key")
        ? { data: { is_free_tier: false, limit_remaining: 70 } }
        : { data: { total_credits: 100, total_usage: 30 } };
      return Response.json(data);
    };
    await expect(assertManagedAdmissionCapacityPreflight({
      projectedExposureUsdDecimal: "63.907341",
      completionApiKey,
      managementApiKey,
      expectedCompletionKeySha256,
      fetchImpl,
    })).resolves.toBeUndefined();
    expect(requests).toEqual([
      {
        url: "https://openrouter.ai/api/v1/key",
        authorization: `Bearer ${completionApiKey}`,
      },
      {
        url: "https://openrouter.ai/api/v1/credits",
        authorization: `Bearer ${managementApiKey}`,
      },
    ]);
  });

  test("rejects the wrong completion key before any network request", async () => {
    let requests = 0;
    await expect(assertManagedAdmissionCapacityPreflight({
      projectedExposureUsdDecimal: "1",
      completionApiKey,
      managementApiKey,
      expectedCompletionKeySha256: "0".repeat(64),
      fetchImpl: async () => {
        requests += 1;
        return Response.json({});
      },
    })).rejects.toThrow("managed admission completion key fingerprint mismatch");
    expect(requests).toBe(0);
  });

  test("fails closed on free, limited, underfunded, and malformed authorities", async () => {
    const scenarios: Array<{
      key: unknown;
      credits: unknown;
      expected: string;
    }> = [
      {
        key: { data: { is_free_tier: true, limit_remaining: 100 } },
        credits: { data: { total_credits: 100, total_usage: 0 } },
        expected: "managed admission completion key is not an enabled paid key",
      },
      {
        key: { data: { is_free_tier: false, limit_remaining: 1 } },
        credits: { data: { total_credits: 100, total_usage: 0 } },
        expected: "managed admission completion key limit cannot cover projected exposure",
      },
      {
        key: { data: { is_free_tier: false, limit_remaining: null } },
        credits: { data: { total_credits: 60, total_usage: 0 } },
        expected: "managed admission account credits cannot cover projected exposure",
      },
      {
        key: { data: { is_free_tier: false, limit_remaining: null } },
        credits: { data: { total_credits: "secret", total_usage: 0 } },
        expected: "managed admission account-credit preflight returned an invalid contract",
      },
    ];
    for (const scenario of scenarios) {
      const fetchImpl = async (input: string | URL | Request): Promise<Response> =>
        Response.json(String(input).endsWith("/key") ? scenario.key : scenario.credits);
      await expect(assertManagedAdmissionCapacityPreflight({
        projectedExposureUsdDecimal: "63.907341",
        completionApiKey,
        managementApiKey,
        expectedCompletionKeySha256,
        fetchImpl,
      })).rejects.toThrow(scenario.expected);
    }
  });

  test("reports only bounded authority and status for rejected requests", async () => {
    let responseCancelled = false;
    const fetchImpl = async (): Promise<Response> => new Response(
      new ReadableStream({
        cancel() {
          responseCancelled = true;
        },
      }),
      { status: 403 },
    );
    let error: Error | undefined;
    try {
      await assertManagedAdmissionCapacityPreflight({
        projectedExposureUsdDecimal: "1",
        completionApiKey,
        managementApiKey,
        expectedCompletionKeySha256,
        fetchImpl,
      });
    } catch (caught) {
      error = caught as Error;
    }
    expect(error?.message).toBe("managed admission completion-key preflight returned HTTP 403");
    expect(error?.message).not.toContain(completionApiKey);
    expect(error?.message).not.toContain(managementApiKey);
    expect(responseCancelled).toBe(true);
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
    expect(workflow).toMatch(new RegExp(
      `^ {6}cost_cap_usd:\\n(?: {8}.*\\n){2} {8}default: "${MAX_GENERATOR_COST_CAP_USD}"$`,
      "mu",
    ));
    expect(workflow).toContain("upstream_provider:");
    expect(workflow).toContain("POSTIL_BENCH_UPSTREAM_PROVIDER: ${{ inputs.upstream_provider }}");
    expect(workflow).toContain("OPENROUTER_MANAGEMENT_API_KEY: ${{ secrets.OPENROUTER_MANAGEMENT_API_KEY }}");
    expect(workflow).toContain("OPENROUTER_QUALIFICATION_KEY_SHA256: ${{ secrets.OPENROUTER_QUALIFICATION_KEY_SHA256 }}");
    expect(workflow).toContain("COMPLETION_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}");
    expect(workflow.indexOf("Require managed admission capacity secrets")).toBeLessThan(
      workflow.indexOf("Build release binary"),
    );
    expect(workflow).toContain('echo "POSTIL_MANIFEST_OUT=${RUNNER_TEMP}/postil-qualified-models-${suffix}.json"');
    expect(workflow).toContain('>> "$GITHUB_ENV"');
    expect(workflow).toContain('test "$GITHUB_REF" = "refs/heads/main"');
    expect(workflow).toContain('echo "POSTIL_PRIVATE_EVIDENCE_OUT=${RUNNER_TEMP}/postil-private-evidence-${suffix}.json"');
    expect(workflow).toContain('echo "POSTIL_PRIVATE_EVIDENCE_ENCRYPTED_OUT=${RUNNER_TEMP}/postil-private-evidence-${suffix}.json.gpg"');
    expect(workflow).toContain('rm -f "$POSTIL_REPORT_OUT" "$POSTIL_MANIFEST_OUT" "$POSTIL_PRIVATE_EVIDENCE_OUT" "$POSTIL_PRIVATE_EVIDENCE_ENCRYPTED_OUT" "$POSTIL_ATTESTATION_BUNDLE_OUT"');
    expect(workflow).toContain('--manifest-out "$POSTIL_MANIFEST_OUT"');
    expect(workflow).toContain('--private-evidence-out "$POSTIL_PRIVATE_EVIDENCE_OUT"');
    expect(workflow).toContain('const { parseLiveModelsFailureReport } = await import("./src/run.ts");');
    expect(workflow).toContain('if (raw?.artifactType === "live-models-failure")');
    expect(workflow).toContain("const failure = parseLiveModelsFailureReport(raw);");
    expect(workflow).toContain('console.log("category " + failure.process.category);');
    expect(workflow).toContain('console.log("provider attempts " + fact(failure.process.providerAttemptCount));');
    expect(workflow).toContain("const r = parseLiveModelsReport(raw);");
    expect(workflow).toContain("secrets.POSTIL_PRIVATE_EVIDENCE_PASSPHRASE");
    expect(workflow).toContain("--symmetric --cipher-algo AES256");
    expect(workflow).toContain('cmp "$POSTIL_PRIVATE_EVIDENCE_OUT" "$verify_path"');
    expect(workflow).toMatch(/name: Upload encrypted private replay evidence[\s\S]*path: \$\{\{ env\.POSTIL_PRIVATE_EVIDENCE_ENCRYPTED_OUT \}\}/u);
    expect(workflow).toMatch(/name: Remove private replay evidence\n\s+if: always\(\)\n\s+run: rm -f "\$POSTIL_PRIVATE_EVIDENCE_OUT" "\$POSTIL_PRIVATE_EVIDENCE_ENCRYPTED_OUT"/u);
    expect(workflow).not.toContain("path: ${{ env.POSTIL_PRIVATE_EVIDENCE_OUT }}");
    expect(workflow).not.toContain("bench-live-raw-runs");
    expect(workflow).not.toContain("path: bench/.runs/live-models");
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
    expect(workflow).toContain("POSTIL_BENCH_UPSTREAM_PROVIDER_ROUTE: ${{ inputs.upstream_provider_route }}");
    const ci = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "ci.yml"),
    ).text();
    expect(ci).toContain("bun run verify-admission");
    expect(ci).toMatch(/bench:\n[\s\S]*?fetch-depth: 0/u);
    const release = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "release.yml"),
    ).text();
    const calibration = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "benchmark-calibration.yml"),
    ).text();
    expect(calibration).toContain("name: Reserve the current main calibration source");
    expect(calibration).toContain('refs/tags/postil-calibration-${GITHUB_SHA}');
    expect(calibration).not.toContain("actions/workflows/benchmark-calibration.yml/runs");
    expect(calibration).toContain("max-parallel: 1");
    expect(calibration).toContain("--mode reserve");
    expect(calibration).toContain("name: Attest benchmark sample reservation");
    expect(calibration).toContain("--mode execute");
    expect(calibration).toContain("name: Attest benchmark sample result");
    expect(calibration).toContain("name: Record the attested baseline");
    expect(calibration).toContain("name: Attest the populated baseline");
    expect(calibration).toContain("name: Verify independent calibration generations");
    expect(calibration).toContain("bun run bench:verify-generations --");
    expect(calibration).toContain("--record");
    expect(release).not.toContain("workflow_dispatch");
    expect(release).toContain("name: Require the unique first release run for this tag");
    expect(release).toContain('if [[ "${GITHUB_RUN_ATTEMPT}" != "1" ]]');
    expect(release).toContain('"repos/${GITHUB_REPOSITORY}/actions/workflows/release.yml/runs"');
    expect(release).toContain("This version tag already has another release run.");
    expect(release).toContain("group: release-${{ github.ref_name }}");
    expect(release).toContain('gh release view "${GITHUB_REF_NAME}"');
    expect(release).toContain("name: Verify the attested Luna calibration baseline");
    expect(release).toContain("bench/baseline.attestation.json");
    expect(release).toContain('git/ref/tags/postil-calibration-${source_sha}');
    expect(release).toContain(
      "--signer-workflow postil-dev/postil-cli/.github/workflows/benchmark-calibration.yml",
    );
    expect(release).toContain('--signer-digest "$source_sha"');
    expect(release).toContain('--source-digest "$source_sha"');
    expect(release).toContain("--source-ref refs/heads/main");
    expect(release).toMatch(/validate-tag:\n[\s\S]*?permissions:\n\s+contents: read\n\s+actions: read/u);
    expect(release).toMatch(/validate-tag:\n[\s\S]*?fetch-depth: 0[\s\S]*?bun-version: 1\.3\.14[\s\S]*?bun install --frozen-lockfile[\s\S]*?bun run verify-admission[\s\S]*?name: Verify the attested Luna calibration baseline[\s\S]*?\n  bench-live-prepare:\n/u);
    // The gate derives its model from the binary's embedded configuration so
    // caller drift cannot benchmark a model absent from the release.
    expect(release).not.toContain("REVIEW_MODEL:");
    expect(release).toContain("OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}");
    expect(release).not.toContain("POSTIL_SCORER_EVAL_MODELS:");
    expect(release).toContain('POSTIL_SCORER_EVAL_REPEATS: "3"');
    expect(release).toContain("POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER: Azure");
    expect(release).toContain("POSTIL_SCORER_EVAL_UPSTREAM_PROVIDER_ROUTE: azure/eu");
    expect(release).toContain("POSTIL_BIN: ${{ github.workspace }}/target/release/postil");
    expect(release).not.toContain("Build scorer qualification binary");
    expect(release).toContain("bun run scorer-eval --json-out");
    expect(release).toContain("${{ runner.temp }}/scorer-eval-report.json.partial");
    expect(release).toMatch(
      /name: Upload the scorer gate report\n\s+if: always\(\)[\s\S]*if-no-files-found: warn[\s\S]*retention-days: 30/u,
    );
    expect(release.indexOf("bun run scorer-eval --json-out")).toBeLessThan(
      release.indexOf("bun run bench:cohort-run --"),
    );
    const prepareStart = release.indexOf("\n  bench-live-prepare:\n");
    const sampleStart = release.indexOf("\n  bench-live-sample:\n");
    const finalStart = release.indexOf("\n  bench-live:\n");
    const buildStart = release.indexOf("\n  build:\n");
    expect(prepareStart).toBeGreaterThan(-1);
    expect(sampleStart).toBeGreaterThan(prepareStart);
    expect(finalStart).toBeGreaterThan(sampleStart);
    expect(buildStart).toBeGreaterThan(finalStart);
    const prepare = release.slice(prepareStart, sampleStart);
    const sample = release.slice(sampleStart, finalStart);
    const final = release.slice(finalStart, buildStart);
    const build = release.slice(buildStart);

    expect(prepare).toMatch(/bench-live-prepare:\n\s+needs: validate-tag\n/u);
    expect(prepare).toContain("name: benchmarked-x86_64-unknown-linux-gnu-${{ github.run_attempt }}");
    expect(prepare).toContain("path: target/release/postil");
    expect(prepare).toContain("bun run bench:cohort-create --");
    expect(prepare).toContain("--purpose release");
    expect(prepare).toContain("--out \"${{ runner.temp }}/bench-live-cohort.json\"");
    expect(prepare).toContain("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4");
    expect(prepare).toContain("id-token: write");
    expect(prepare).toContain("attestations: write");
    expect(prepare).toContain("artifact-metadata: write");
    expect(prepare).toContain("bench-live-cohort.attestation.json");
    expect(prepare).toContain("name: bench-live-cohort-${{ github.run_attempt }}");

    expect(sample).toMatch(
      /bench-live-sample:\n\s+needs: \[validate-tag, bench-live-prepare\][\s\S]*?strategy:\n\s+fail-fast: false\n\s+max-parallel: 1\n\s+matrix:\n\s+sample: \[1, 2, 3, 4, 5\]/u,
    );
    expect(sample).toContain("name: benchmarked-x86_64-unknown-linux-gnu-${{ github.run_attempt }}");
    expect(sample).toContain("path: target/release");
    expect(sample).toContain("chmod 0755 target/release/postil");
    expect(sample).toContain(
      "POSTIL_BIN: ${{ github.workspace }}/target/release/postil",
    );
    expect([...sample.matchAll(/bun run bench:cohort-run --/gu)]).toHaveLength(2);
    expect(sample).toContain("--mode reserve");
    expect(sample).toContain("--mode execute");
    expect(sample).toContain("name: Attest benchmark sample reservation");
    expect(sample).toContain("reservation.attestation.json");
    expect(sample).toContain("name: Run diff-file live benchmark sample ${{ matrix.sample }}");
    expect(sample).toContain(
      '--manifest "${{ runner.temp }}/bench-live-cohort.json"',
    );
    expect(sample).toContain("--screen-profile ../provisional-models.json");
    expect(sample).not.toContain("--report-out");
    expect(sample).not.toContain("--receipt-out");
    expect(sample).toContain("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4");
    expect(sample).toContain("gh attestation verify");
    expect(sample).toContain("--signer-workflow postil-dev/postil-cli/.github/workflows/release.yml");
    expect(sample).toContain("--signer-digest \"${GITHUB_SHA}\"");
    expect(sample).toContain("--source-digest \"${GITHUB_SHA}\"");
    expect(sample).toContain("--source-ref \"${GITHUB_REF}\"");
    expect(sample).toContain("--deny-self-hosted-runners");
    expect(sample).toMatch(
      /name: Upload diff-file live benchmark sample \$\{\{ matrix\.sample \}\}\n\s+if: always\(\)[\s\S]*?name: bench-live-sample-\$\{\{ github\.run_attempt \}\}-\$\{\{ matrix\.sample \}\}[\s\S]*?path: \$\{\{ runner\.temp \}\}\/bench-live-sample-\$\{\{ github\.run_attempt \}\}-\$\{\{ matrix\.sample \}\}[\s\S]*?retention-days: 30/u,
    );

    expect(final).toMatch(
      /bench-live:\n\s+if: always\(\)\n\s+needs: \[bench-live-prepare, bench-live-sample\]/u,
    );
    expect(final).toMatch(
      /name: benchmarked-x86_64-unknown-linux-gnu-\$\{\{ github\.run_attempt \}\}\n\s+path: target\/release/u,
    );
    expect(final).toContain("pattern: bench-live-sample-${{ github.run_attempt }}-*");
    expect(final).toContain("path: ${{ runner.temp }}/bench-live-reports-download");
    expect(final).toContain("merge-multiple: false");
    expect(final).toContain("name: Verify signed release benchmark evidence");
    expect(final).toContain("name: Verify independent release generations");
    expect(final).toContain("bun run bench:verify-generations --");
    expect(final).toContain("gh attestation verify");
    expect(final).toContain("--deny-self-hosted-runners");
    expect(final).toContain("name: bench-live-cohort-${{ github.run_attempt }}");
    expect(final).toContain('--cohort-manifest "${{ runner.temp }}/bench-live-cohort.json"');
    for (const sample of [1, 2, 3, 4, 5]) {
      expect(final).toContain(
        `--expected-run-id "release-\${{ github.ref_name }}-\${{ github.run_id }}-\${{ github.run_attempt }}-0${sample}"`,
      );
      expect(final).toContain(
        `--result "\${{ runner.temp }}/bench-live-reports/slots/0${sample}/report.json"`,
      );
      expect(final).toContain(
        `--receipt "\${{ runner.temp }}/bench-live-reports/slots/0${sample}/receipt.json"`,
      );
    }
    expect([...final.matchAll(/--expected-run-id /gu)]).toHaveLength(5);
    expect([...final.matchAll(/--result /gu)]).toHaveLength(10);
    expect([...final.matchAll(/--receipt /gu)]).toHaveLength(10);
    expect(final).toMatch(
      /bun run bench:compare --[\s\S]*--binary "\$\{\{ github\.workspace \}\}\/target\/release\/postil"[\s\S]*--screen-profile \.\.\/provisional-models\.json/u,
    );
    expect(final).toContain("SAMPLE_JOB_RESULT: ${{ needs.bench-live-sample.result }}");
    expect(final).toContain('if [[ "${SAMPLE_JOB_RESULT}" != "success" ]]');
    expect(final).toContain("At least one live benchmark sample failed before comparison.");
    expect(release).toContain("OPENROUTER_API_KEY has insufficient credit for the release benchmark reserve.");
    expect(release).toContain('echo "OpenRouter credential accepted."');
    expect(release).not.toContain("remaining=\"$(jq -r '.data.limit_remaining");
    expect(release).not.toMatch(/credential accepted.*remaining/iu);
    expect(release).not.toContain("bench-live-report-1.json.partial");
    expect(release).not.toContain("bench-live-report-2.json.partial");
    expect(release).not.toContain("bench-live-report-3.json.partial");
    expect(release).not.toContain("bench-live-report-4.json.partial");
    expect(release).not.toContain("bench-live-report-5.json.partial");
    expect(release).not.toContain("bench_live_override_reason");
    expect(release).not.toContain("OVERRIDE_REASON");
    expect(build).toMatch(/build:\n\s+needs: \[validate-tag, bench-live\]/u);
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
      const lines = source.split("\n");
      const attestationCommands: string[] = [];
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
        if (!/^[ \t]*gh attestation verify\b/u.test(lines[lineIndex] ?? "")) continue;
        const commandLines = [lines[lineIndex] ?? ""];
        while (commandLines.at(-1)?.trimEnd().endsWith("\\")) {
          lineIndex += 1;
          commandLines.push(lines[lineIndex] ?? "");
        }
        attestationCommands.push(commandLines.join("\n"));
      }
      expect({
        workflowName,
        incompatibleSignerFlags: attestationCommands.filter((command) =>
          command.includes("--signer-repo") && command.includes("--signer-workflow")),
      }).toEqual({ workflowName, incompatibleSignerFlags: [] });
    }
    expect(checkedReferences).toBeGreaterThan(0);
  });
});

describe("qualification report", () => {
  test("summarizes evaluator evidence without request, response, or verdict prose", () => {
    const evidence = [{
      request: { candidate: { body: "private evaluator request sentinel" } },
      rawResponses: ["private evaluator response sentinel"],
      reason: "private evaluator verdict sentinel",
    }] as unknown as AttributionCallEvidence[];

    const summary = summarizeAttributionEvaluator({
      pairId: "generator + scorer",
      eligible: true,
      evidenceSha256: "a".repeat(64),
      evidence,
    });
    const serialized = JSON.stringify(summary);

    expect(summary).toEqual({
      pairId: "generator + scorer",
      eligible: true,
      evidenceSha256: "a".repeat(64),
      calls: 1,
    });
    expect(serialized).not.toContain("private evaluator request sentinel");
    expect(serialized).not.toContain("private evaluator response sentinel");
    expect(serialized).not.toContain("private evaluator verdict sentinel");
  });

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

  test("covers every evaluator authority source and changes when a listed source changes", async () => {
    const required = [
      ".github/workflows/benchmark-calibration.yml",
      ".github/workflows/release.yml",
      "bench/evaluator-contract-sources.json",
      "bench/src/cohort.ts",
      "bench/src/cohort-run.ts",
      "bench/src/compare-baseline.ts",
      "bench/src/live.ts",
      "bench/src/run.ts",
    ];
    for (const source of required) expect(EVALUATOR_CONTRACT_SOURCE_PATHS).toContain(source);
    expect(new Set(EVALUATOR_CONTRACT_SOURCE_PATHS).size).toBe(EVALUATOR_CONTRACT_SOURCE_PATHS.length);
    const repositoryRoot = resolve(import.meta.dir, "../..");
    for (const source of EVALUATOR_CONTRACT_SOURCE_PATHS) {
      expect((await readFile(resolve(repositoryRoot, source))).byteLength).toBeGreaterThan(0);
    }
    expect(await evaluatorSourceSha256()).toMatch(/^[0-9a-f]{64}$/u);

    const root = await mkdtemp(resolve(tmpdir(), "postil-evaluator-source-"));
    const source = resolve(root, "source.ts");
    try {
      const listedPath = "bench/src/live.ts";
      await writeFile(source, "authority source one");
      const before = hashNamedSources([[listedPath, await readFile(source)]]);
      await writeFile(source, "authority source two");
      const after = hashNamedSources([[listedPath, await readFile(source)]]);
      expect(after).not.toBe(before);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
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
    const routeBoundMaterial = {
      ...profileMaterial,
      upstreamProviderRoute: "provider/route",
    };
    expect(qualificationProfileDigest(routeBoundMaterial)).not.toBe(profile.id);
    expect(qualificationProfileDigestMaterial(routeBoundMaterial)).toMatchObject({
      upstreamProviderIdentity: "test-provider",
      upstreamProviderRoute: "provider/route",
    });
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
      schemaVersion: 4,
      generatedAt: "2026-07-11T00:00:00.000Z",
      qualificationSourceSha: "9".repeat(40),
      cliVersion: "postil 0.6.1",
      apiBase: "https://example.test/v1",
      apiFormat: "openai-compatible",
      providerEndpointIdentity: "https://example.test:443/v1",
      upstreamProviderPinned: true,
      upstreamProviderIdentity: "PinnedProvider",
      upstreamProviderRoute: "pinned/route",
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
      privateEvidenceSha256: "3".repeat(64),
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
      observedProviderCostUsdDecimal: "0.123456",
      failedOrUnknownExposureUsdDecimal: "0",
      costAccountingComplete: true,
      reservedQualificationExposureUsdDecimal: "0.123456",
      attributionRunCostUsdDecimal: "0",
      attributionFailedExposureUsdDecimal: "0",
      attributionRunCostUsd: 0.001,
      attributionProviderCalls: 2,
      cases: [],
    };

    const privateBundle = {
      schemaVersion: 1 as const,
      qualificationSourceSha: report.qualificationSourceSha,
      cliBinaryHash: report.cliBinaryHash,
      attributionEvaluators: [],
      cases: [],
    };
    report.privateEvidenceSha256 = privateEvidenceSha256(privateBundle);
    expect(parseLiveModelsReport(report)).toBe(report);
    expect(() => verifyPrivateEvidenceBundle(privateBundle, report)).not.toThrow();
    const schemaThree = structuredClone(report) as unknown as Record<string, unknown>;
    schemaThree.schemaVersion = 3;
    delete schemaThree.upstreamProviderRoute;
    expect(parseLiveModelsReport(schemaThree)).toMatchObject({
      schemaVersion: 4,
      upstreamProviderRoute: "PinnedProvider",
    });
    const contaminatedSchemaThree = structuredClone(report) as unknown as Record<string, unknown>;
    contaminatedSchemaThree.schemaVersion = 3;
    expect(() => parseLiveModelsReport(contaminatedSchemaThree)).toThrow(
      "schema-3 report must not contain upstreamProviderRoute",
    );
    const legacy = structuredClone(report) as unknown as Record<string, unknown>;
    delete legacy.schemaVersion;
    expect(() => parseLiveModelsReport(legacy)).toThrow(
      "schemaVersion is required; legacy unversioned reports are not accepted",
    );
    const contaminated = structuredClone(report) as unknown as Record<string, unknown>;
    contaminated.cases = [{
      id: "synthetic",
      fidelityFailures: ["full report private title sentinel at .postil/model-output:1"],
      error: "full report private body sentinel",
    }];
    expect(() => parseLiveModelsReport(contaminated)).toThrow("contains private field");
    expect(JSON.stringify(report)).not.toContain("full report private title sentinel");
    expect(JSON.stringify(report)).not.toContain("full report private body sentinel");

    const output = formatLiveModelsReport(report);
    expect(output).toContain("block");
    expect(output).toContain("adv");
    expect(output).toContain("Fixture aaaa");
    expect(output).toContain("Provider endpoint https://example.test:443/v1; upstream PinnedProvider pinned for every qualification call; 3 complete repeats");
    expect(output).toContain("$0.1235");
    expect(output).toContain("observed provider $0.123456");
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
