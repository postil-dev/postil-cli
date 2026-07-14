import { describe, expect, test } from "bun:test";
import { benchmarkCase, type BenchmarkCase, type Envelope } from "./harness";
import {
  aggregateModel,
  assertPairQualificationPreflight,
  calculateTotalRunCostUsd,
  findingHitsSeededRegion,
  groundTruthOf,
  pricingFromCatalog,
  projectTotalCostUsd,
  qualificationPairId,
  scoreLiveCase,
  toSiteModelAggregate,
  type LiveModelCaseResult,
  type ModelPricing,
  type QualificationPair,
} from "./livemodels-score";

const pair: QualificationPair = { generatorModel: "provider/generator", scorerModel: "provider/scorer" };
const prices = new Map<string, ModelPricing>([
  [pair.generatorModel, { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000002 }],
  [pair.scorerModel, { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000002 }],
]);

function fixture(
  classification: "mustBlock" | "advisory" | "clean",
  id = `case-${classification}`,
): BenchmarkCase {
  const severity = classification === "mustBlock" ? "error" : classification === "advisory" ? "warn" : null;
  return benchmarkCase.parse({
    id,
    name: id,
    repo: "benchmark/example",
    pullNumber: 1,
    headSha: "a".repeat(40),
    diff: "diff --git a/src/x.ts b/src/x.ts\n+ bad();\n",
    admission: { classification, contractRule: "test-contract" },
    groundTruth: {
      findings: severity === null ? [] : [{
        path: "src/x.ts",
        line: 20,
        severity,
        semantics: {
          positive: [{ all: [["generated detail"]] }],
          negative: [{ all: [["no generated detail"]] }],
        },
      }],
    },
    modelOutput: { summary: "", findings: [] },
    expectations: { minFindings: 0 },
  });
}

function finding(severity: "info" | "warn" | "error", path = "src/x.ts", line = 20) {
  return {
    path,
    line,
    severity,
    kind: "risk",
    confidence: 0.9,
    title: "generated prose must not persist",
    body: "generated detail must not persist",
  } as const;
}

function usage(model: string, role: "reviewGenerator" | "findingScorer", exact = true) {
  return {
    model,
    role,
    phase: "initial" as const,
    callOrdinal: role === "reviewGenerator" ? 1 : 2,
    attempt: 1,
    promptTokens: 100,
    completionTokens: 20,
    ...(exact ? {
      costMicros: 100,
      costProviderDecimal: "0.0001",
      costSource: "providerReported" as const,
    } : {}),
    accountingComplete: true,
  };
}

function envelope(args: {
  findings?: Envelope["findings"];
  suppressed?: Envelope["suppressedFindings"];
  gateFailing?: boolean;
  exactCost?: boolean;
  scorerError?: string;
  durationMs?: number;
} = {}): Envelope {
  const findings = args.findings ?? [];
  const suppressedFindings = args.suppressed ?? [];
  const needsScorer = findings.length + suppressedFindings.length > 0;
  const modelUsage = [
    usage(pair.generatorModel, "reviewGenerator", args.exactCost ?? true),
    ...(needsScorer ? [usage(pair.scorerModel, "findingScorer", args.exactCost ?? true)] : []),
  ];
  return {
    version: 1,
    summary: "",
    silent: findings.length === 0,
    findings,
    suppressedFindings,
    resolved: [],
    counts: { info: 0, warn: 0, error: 0, suppressed: suppressedFindings.length, ungrounded: 0 },
    confidenceBuckets: [0, 0, 0, 0, 0],
    gate: { failOn: "error", failing: args.gateFailing ?? false, blockOnKinds: [] },
    modelUsed: pair.generatorModel,
    ...(needsScorer ? { scorerModel: pair.scorerModel } : {}),
    ...(args.scorerError === undefined ? {} : { scorerError: args.scorerError }),
    usage: {
      promptTokens: modelUsage.reduce((sum, entry) => sum + entry.promptTokens, 0),
      completionTokens: modelUsage.reduce((sum, entry) => sum + entry.completionTokens, 0),
    },
    modelUsage,
    usageAccountingComplete: true,
    durationMs: args.durationMs ?? 1000,
    baseSha: null,
    headSha: null,
    sinceSha: null,
  };
}

function score(
  classification: "mustBlock" | "advisory" | "clean",
  repeat: number,
  env: Envelope,
  id?: string,
): LiveModelCaseResult {
  return scoreLiveCase({
    case: fixture(classification, id),
    pair,
    repeat,
    envelope: env,
    pricing: prices,
    exitCode: env.gate.failing ? 1 : 0,
    fidelityFailures: [],
  });
}

function passingMatrix(repeats = 3): LiveModelCaseResult[] {
  const results: LiveModelCaseResult[] = [];
  for (let repeat = 1; repeat <= repeats; repeat += 1) {
    for (let i = 0; i < 34; i += 1) {
      results.push(score("mustBlock", repeat, envelope({ findings: [finding("error")], gateFailing: true }), `m-${i}`));
    }
    for (let i = 0; i < 15; i += 1) {
      results.push(score("advisory", repeat, envelope({ findings: [finding("warn")] }), `a-${i}`));
    }
    for (let i = 0; i < 12; i += 1) {
      results.push(score("clean", repeat, envelope(), `c-${i}`));
    }
  }
  return results;
}

describe("fixture contract", () => {
  test("distinguishes must-block, advisory, and clean ground truth", () => {
    expect(groundTruthOf(fixture("mustBlock"))).toMatchObject({ classification: "mustBlock", severity: "error" });
    expect(groundTruthOf(fixture("advisory"))).toMatchObject({ classification: "advisory", severity: "warn" });
    expect(groundTruthOf(fixture("clean"))).toMatchObject({ classification: "clean", path: null });
  });

  test("attributes only overlapping findings to the seeded defect", () => {
    expect(findingHitsSeededRegion({ path: "src/x.ts", line: 17 }, 20)).toBe(true);
    expect(findingHitsSeededRegion({ path: "src/x.ts", line: 16 }, 20)).toBe(false);
  });
});

describe("pair scoring", () => {
  test("records final and suppressed detector evidence without generated prose", () => {
    const result = score("advisory", 1, envelope({
      suppressed: [{ finding: finding("warn"), reason: "confidence" }],
    }));
    expect(result.detected).toBe(true);
    expect(result.findingEvidence).toEqual([{
      detectorAttribution: "seeded",
      disposition: "suppressed",
      path: "src/x.ts",
      line: 20,
      severity: "warn",
      kind: "risk",
      confidence: 0.9,
      semanticMatch: true,
    }]);
    expect(JSON.stringify(result.findingEvidence)).not.toContain("generated prose");
    expect(JSON.stringify(result.findingEvidence)).not.toContain("generated detail");
  });

  test("requires the seeded detector itself to block and rejects unrelated substitute blockers", () => {
    const result = score("mustBlock", 1, envelope({
      findings: [finding("warn"), finding("error", "src/other.ts", 8)],
      gateFailing: true,
    }));
    expect(result.detected).toBe(true);
    expect(result.seededFinalBlocker).toBe(false);
    expect(result.unrelatedFinalBlockers).toBe(1);
    expect(result.finalBlocking).toBe(false);
  });

  test("requires useful defect semantics in addition to a nearby coordinate", () => {
    const unrelated = { ...finding("error"), body: "This nearby line only changes formatting." };
    const result = score("mustBlock", 1, envelope({ findings: [unrelated], gateFailing: true }));
    expect(result.detected).toBe(false);
    expect(result.findingEvidence[0]?.semanticMatch).toBe(false);
  });

  test("preserves provider-exact and catalog fallback cost provenance", () => {
    const exact = score("advisory", 1, envelope({ findings: [finding("warn")] }));
    expect(exact.costProvenance).toBe("providerExact");
    expect(exact.costUsd).toBeCloseTo(0.0002, 8);
    expect(exact.costProviderDecimal).toBe("0.0002");
    expect(exact.usageCostEvidence).toHaveLength(2);

    const catalog = score("advisory", 1, envelope({ findings: [finding("warn")], exactCost: false }));
    expect(catalog.costProvenance).toBe("catalogEstimate");
    expect(catalog.costUsd).toBeCloseTo(0.00028, 8);
  });
});

describe("pair admission", () => {
  test("passes only a repeated complete exact-pair matrix", () => {
    const aggregate = aggregateModel(pair, passingMatrix(), 3);
    expect(aggregate).toMatchObject({
      id: qualificationPairId(pair),
      casesRun: 183,
      mustBlockRecall: 1,
      mustBlockFinalBlockingRate: 1,
      advisoryDetectionRate: 1,
      advisoryOverblockRate: 0,
      cleanFalseBlocks: 0,
      cleanFindingFalsePositiveRate: 0,
      errors: 0,
      fidelityFailures: 0,
      structuredOutputFailures: 0,
      usageFailures: 0,
      passed: true,
      admissionFailures: [],
    });
  });

  test("rejects a latency outlier that the mean could hide", () => {
    const matrix = passingMatrix();
    matrix[0]!.durationMs = 187_000;
    const aggregate = aggregateModel(pair, matrix, 3);
    expect(aggregate.passed).toBe(false);
    expect(aggregate.admissionFailures.some((failure) => failure.includes("max latency"))).toBe(true);
  });

  test("fails every attributable quality boundary independently", () => {
    const missedBlock = passingMatrix();
    missedBlock[0] = score("mustBlock", 1, envelope(), "m-0");
    expect(aggregateModel(pair, missedBlock, 3).admissionFailures.join("\n")).toContain("must-block recall");

    const substituteBlock = passingMatrix();
    substituteBlock[0] = score("mustBlock", 1, envelope({
      findings: [finding("warn"), finding("error", "src/other.ts", 1)], gateFailing: true,
    }), "m-0");
    expect(aggregateModel(pair, substituteBlock, 3).admissionFailures.join("\n")).toContain("final seeded blocking");

    const advisoryMisses = passingMatrix();
    advisoryMisses[34] = score("advisory", 1, envelope(), "a-0");
    advisoryMisses[35] = score("advisory", 1, envelope(), "a-1");
    expect(aggregateModel(pair, advisoryMisses, 3).admissionFailures.join("\n")).toContain("advisory detection");

    const advisoryBlocks = passingMatrix();
    advisoryBlocks[34] = score("advisory", 1, envelope({ findings: [finding("error")], gateFailing: true }), "a-0");
    advisoryBlocks[35] = score("advisory", 1, envelope({ findings: [finding("error")], gateFailing: true }), "a-1");
    expect(aggregateModel(pair, advisoryBlocks, 3).admissionFailures.join("\n")).toContain("advisory overblocking");

    const cleanNoise = passingMatrix();
    cleanNoise[49] = score("clean", 1, envelope({ findings: [finding("warn", "src/other.ts", 1)] }), "c-0");
    expect(aggregateModel(pair, cleanNoise, 3).admissionFailures.join("\n")).toContain("clean finding false-positive");

    const cleanBlock = passingMatrix();
    cleanBlock[49] = score("clean", 1, envelope({ findings: [finding("error", "src/other.ts", 1)], gateFailing: true }), "c-0");
    expect(aggregateModel(pair, cleanBlock, 3).admissionFailures.join("\n")).toContain("clean false block");
  });

  test("fails incomplete, single-run, fidelity, structured-output, and accounting results", () => {
    expect(aggregateModel(pair, passingMatrix(1), 1).admissionFailures.join("\n")).toContain("at least 3");

    const incomplete = passingMatrix();
    incomplete.pop();
    expect(aggregateModel(pair, incomplete, 3).admissionFailures.join("\n")).toContain("matrix is");

    const fidelity = passingMatrix();
    fidelity[0]!.fidelityFailures.push("statusline mismatch");
    expect(aggregateModel(pair, fidelity, 3).admissionFailures.join("\n")).toContain("pipeline fidelity");

    const structured = passingMatrix();
    structured[0]!.structuredOutputFailures.push("scorer mismatch");
    expect(aggregateModel(pair, structured, 3).admissionFailures.join("\n")).toContain("structured-output");

    const usageFailure = passingMatrix();
    usageFailure[0]!.usageValid = false;
    expect(aggregateModel(pair, usageFailure, 3).admissionFailures.join("\n")).toContain("usage accounting");
  });
});

describe("report and pricing utilities", () => {
  test("site aggregate identifies the exact pair and attributable metrics", () => {
    const site = toSiteModelAggregate(aggregateModel(pair, passingMatrix(), 3));
    expect(site).toEqual({
      id: qualificationPairId(pair),
      generatorModel: pair.generatorModel,
      generatorModels: [pair.generatorModel],
      scorerModel: pair.scorerModel,
      mustBlockRecall: 1,
      advisoryDetectionRate: 1,
      cleanFindingFalsePositiveRate: 0,
      casesRun: 183,
      meanCostUsdPerReview: 0.0001803278688524587,
      meanDurationMs: 1000,
      p95DurationMs: 1000,
      maxDurationMs: 1000,
    });
  });

  test("sums case costs and matches canonical catalog ids", () => {
    const results = passingMatrix();
    expect(calculateTotalRunCostUsd(results)).toBeCloseTo(0.033, 8);
    const catalog = pricingFromCatalog({ data: [{
      id: "alias",
      canonical_slug: pair.generatorModel,
      pricing: { prompt: "0.000001", completion: "0.000002" },
    }] }, [pair.generatorModel]);
    expect(catalog.get(pair.generatorModel)).toEqual(prices.get(pair.generatorModel));
  });

  test("rejects duplicate requested catalog ids and canonical aliases before pricing", () => {
    const price = { prompt: "0.000001", completion: "0.000002" };
    expect(() => pricingFromCatalog({ data: [
      { id: pair.generatorModel, pricing: price },
      { id: "provider/alias", canonical_slug: pair.generatorModel, pricing: price },
    ] }, [pair.generatorModel])).toThrow("duplicate rows 0 and 1");

    const aliases = pricingFromCatalog({ data: [{
      id: "provider/alias",
      canonical_slug: pair.generatorModel,
      pricing: price,
    }] }, ["provider/alias", pair.generatorModel]);
    expect(aliases.get("provider/alias")).toEqual(prices.get(pair.generatorModel));
    expect(aliases.get(pair.generatorModel)).toEqual(prices.get(pair.generatorModel));
  });

  test("rejects negative, malformed, noncanonical, and nonfinite catalog prices", () => {
    for (const invalid of ["-1", "1junk", "NaN", "Infinity", "0.0000010"]) {
      const catalog = pricingFromCatalog({ data: [{
        id: pair.generatorModel,
        pricing: { prompt: invalid, completion: "0.000002" },
      }] }, [pair.generatorModel]);
      expect(catalog.has(pair.generatorModel)).toBe(false);
    }
  });

  test("projects separate generator and scorer calls when one model fills both roles", () => {
    const sameRolePair = { generatorModel: "provider/shared", scorerModel: "provider/shared" };
    const pricing = new Map([["provider/shared", {
      promptUsdPerToken: 0.000001,
      completionUsdPerToken: 0.000002,
    }]]);
    const oneRole = projectTotalCostUsd({ diffs: ["+ change"], models: ["provider/shared"], pricing });
    const bothRoles = assertPairQualificationPreflight({
      diffs: ["+ change"],
      pairs: [sameRolePair],
      pricing,
      costCapUsd: 25,
    });
    expect(bothRoles).toBeCloseTo(oneRole * 2, 12);
  });
});
