import { describe, expect, test } from "bun:test";
import { cases as fixtureInputs } from "../fixtures/cases";
import {
  admissionManifestCandidate,
  formatLiveModelsReport,
  hashNamedSources,
  liveEnv,
  liveModelsQualificationExitCode,
  normalizeApiBase,
  normalizeQualificationPairs,
  parseQualificationPairs,
  runLiveModels,
  type LiveModelsReport,
} from "./livemodels";
import type { QualificationPair } from "./livemodels-score";

const pair: QualificationPair = { generatorModel: "test/generator", scorerModel: "test/scorer" };

describe("pair qualification configuration", () => {
  test("requires and normalizes exact generator/scorer pairs", () => {
    expect(parseQualificationPairs(" a/generator::b/scorer ")).toEqual([
      { generatorModel: "a/generator", generatorCascade: [], consensus: 1, scorerModel: "b/scorer" },
    ]);
    expect(parseQualificationPairs("a/one+b/two+c/three::s/scorer")).toEqual([{
      generatorModel: "a/one",
      generatorCascade: ["b/two", "c/three"],
      consensus: 3,
      scorerModel: "s/scorer",
    }]);
    expect(() => parseQualificationPairs("a/generator")).toThrow("generator/model::scorer/model");
    expect(normalizeQualificationPairs([pair, { ...pair }])).toEqual([{
      ...pair,
      generatorCascade: [],
      consensus: 1,
    }]);
    expect(() => normalizeQualificationPairs([])).toThrow("at least one generator+scorer pair");
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

  test("canonicalizes the provider endpoint exactly like the runtime", () => {
    expect(normalizeApiBase("HTTPS://OpenRouter.AI/api/v1/")).toBe(
      "https://openrouter.ai:443/api/v1",
    );
    expect(() => normalizeApiBase("https://example.test/v1?route=x")).toThrow(
      "must not contain a query or fragment",
    );
  });

  test("enforces cost and candidate bounds before execution", async () => {
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs: [pair],
      pricing: new Map(),
      costCapUsd: 26,
    })).rejects.toThrow("cost cap must be greater than zero and at most $25");

    const pairs = Array.from({ length: 7 }, (_, index) => ({
      generatorModel: `generator/${index}`,
      scorerModel: `scorer/${index}`,
    }));
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs,
      pricing: new Map(),
    })).rejects.toThrow("at most 6 candidates");

    const inheritedKey = process.env.POSTIL_API_KEY;
    process.env.POSTIL_API_KEY = "test-only-key";
    try {
      await expect(runLiveModels([fixtureInputs[0]!], {
        binary: "/missing/postil",
        pairs: [{ generatorModel: "costly/model", scorerModel: "cheap/scorer" }],
        pricing: new Map([
          ["costly/model", { promptUsdPerToken: 0.001, completionUsdPerToken: 0.001 }],
          ["cheap/scorer", { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000001 }],
        ]),
        costCapUsd: 1,
      })).rejects.toThrow("projected pair qualification spend");
    } finally {
      if (inheritedKey === undefined) delete process.env.POSTIL_API_KEY;
      else process.env.POSTIL_API_KEY = inheritedKey;
    }
  });
});

describe("qualification report", () => {
  test("matches the runtime named-source framing vector", () => {
    expect(hashNamedSources([
      ["a.txt", Buffer.from("alpha")],
      ["b/β.txt", Buffer.from("line\n")],
    ])).toBe("1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba");
  });

  test("emits the exact runtime admission manifest profile", () => {
    const profile = {
      id: "profile-id",
      apiBase: "https://openrouter.ai:443/api/v1",
      apiFormat: "openai-compatible" as const,
      generatorModels: ["provider/one", "provider/two"],
      consensus: 2,
      scorerModels: ["provider/scorer"],
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      configHash: "c".repeat(64),
      cliBinaryHash: "d".repeat(64),
      repeats: 3,
    };
    expect(admissionManifestCandidate("c".repeat(64), "e".repeat(64), [profile])).toEqual({
      version: 1,
      modelDefaultsSha256: "c".repeat(64),
      profiles: [{
        id: "profile-id",
        apiBase: "https://openrouter.ai:443/api/v1",
        generatorChain: ["provider/one", "provider/two"],
        consensus: 2,
        scorerChain: ["provider/scorer"],
        apiFormat: "openai-compatible",
        reviewContractSha256: "b".repeat(64),
        fixtureSetSha256: "a".repeat(64),
        reportSha256: "e".repeat(64),
        repeatedRuns: 3,
      }],
    });
  });

  test("prints attributable metrics, hashes, provider, and bounded costs", () => {
    const cost = 0.123456;
    const report: LiveModelsReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      cliVersion: "postil 0.6.1",
      apiBase: "https://example.test/v1",
      apiFormat: "openai-compatible",
      providerEndpointIdentity: "https://example.test:443/v1",
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      configHash: "d".repeat(64),
      cliBinaryHash: "c".repeat(64),
      evidenceHash: "e".repeat(64),
      repeats: 3,
      profiles: [],
      manifestCandidate: { version: 1, modelDefaultsSha256: "d".repeat(64), profiles: [] },
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
      cases: [],
    };

    const output = formatLiveModelsReport(report);
    expect(output).toContain("block");
    expect(output).toContain("adv");
    expect(output).toContain("Fixture aaaa");
    expect(output).toContain("Provider endpoint https://example.test:443/v1; 3 complete repeats");
    expect(output).toContain("$0.1235");
    expect(output).not.toContain("$0.123456");
    expect(output).toContain("FAIL: mean cost exceeds admission limit");
    expect(liveModelsQualificationExitCode(report)).toBe(1);
  });
});
