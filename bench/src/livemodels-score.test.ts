import { describe, expect, test } from "bun:test";
import { benchmarkCase, type BenchmarkCase, type Envelope } from "./harness";
import {
  aggregateModel,
  calculateTotalRunCostUsd,
  erroredLiveCase,
  estimateCasePromptTokens,
  findingHitsSeededRegion,
  GUARDRAIL_COMPLETION_TOKENS,
  GUARDRAIL_SYSTEM_PROMPT_TOKENS,
  groundTruthOf,
  LINE_TOLERANCE,
  pricingFromCatalog,
  projectTotalCostUsd,
  scoreLiveCase,
  toSiteModelAggregate,
  type ModelPricing,
} from "./livemodels-score";

// ---------------------------------------------------------------------------
// Fixtures builders

function defectCase(overrides?: {
  path?: string;
  line?: number;
  severity?: "info" | "warn" | "error";
}): BenchmarkCase {
  return benchmarkCase.parse({
    id: "defect-1",
    name: "seeded defect",
    repo: "benchmark/example",
    pullNumber: 1,
    headSha: "a".repeat(40),
    diff: "diff --git a/src/x.ts b/src/x.ts\n+ bad();\n",
    groundTruth: {
      findings: [
        {
          path: overrides?.path ?? "src/x.ts",
          line: overrides?.line ?? 20,
          severity: overrides?.severity ?? "error",
        },
      ],
    },
    modelOutput: { summary: "", findings: [] },
    expectations: { minFindings: 0 },
  } satisfies Parameters<typeof benchmarkCase.parse>[0]);
}

function cleanCase(): BenchmarkCase {
  return benchmarkCase.parse({
    id: "clean-1",
    name: "clean pr",
    repo: "benchmark/example",
    pullNumber: 2,
    headSha: "b".repeat(40),
    diff: "diff --git a/src/y.ts b/src/y.ts\n+ ok();\n",
    groundTruth: { findings: [] },
    modelOutput: { summary: "", findings: [] },
    expectations: { minFindings: 0 },
  } satisfies Parameters<typeof benchmarkCase.parse>[0]);
}

function envelope(overrides: Partial<Envelope> = {}): Envelope {
  return {
    version: 1,
    summary: "",
    silent: false,
    findings: [],
    resolved: [],
    counts: { info: 0, warn: 0, error: 0, suppressed: 0, ungrounded: 0 },
    confidenceBuckets: [0, 0, 0, 0, 0],
    gate: { failOn: "error", failing: false },
    modelUsed: "m",
    usage: { promptTokens: 1000, completionTokens: 200 },
    durationMs: 1234,
    baseSha: null,
    headSha: null,
    sinceSha: null,
    ...overrides,
  };
}

function mkFinding(
  path: string,
  line: number,
  severity: "info" | "warn" | "error",
  endLine?: number,
): Envelope["findings"][number] {
  return { path, line, endLine, severity, kind: "risk", confidence: 0.9, title: "t", body: "b" };
}

const pricing: ModelPricing = { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000002 };

// ---------------------------------------------------------------------------
// groundTruthOf

describe("groundTruthOf", () => {
  test("defect fixture with an error finding demands a failing gate", () => {
    const gt = groundTruthOf(defectCase({ severity: "error" }));
    expect(gt).toMatchObject({ clean: false, path: "src/x.ts", line: 20, severity: "error", gateShouldFail: true });
  });

  test("defect fixture with a warn finding does not demand a failing gate", () => {
    const gt = groundTruthOf(defectCase({ severity: "warn" }));
    expect(gt.gateShouldFail).toBe(false);
  });

  test("clean fixture is clean with a passing gate", () => {
    const gt = groundTruthOf(cleanCase());
    expect(gt).toMatchObject({ clean: true, path: null, line: null, gateShouldFail: false });
  });
});

// ---------------------------------------------------------------------------
// findingHitsSeededRegion

describe("findingHitsSeededRegion", () => {
  test("exact line hit", () => {
    expect(findingHitsSeededRegion({ path: "x", line: 20 }, 20)).toBe(true);
  });

  test("within tolerance below and above", () => {
    expect(findingHitsSeededRegion({ path: "x", line: 20 - LINE_TOLERANCE }, 20)).toBe(true);
    expect(findingHitsSeededRegion({ path: "x", line: 20 + LINE_TOLERANCE }, 20)).toBe(true);
  });

  test("just outside tolerance misses", () => {
    expect(findingHitsSeededRegion({ path: "x", line: 20 + LINE_TOLERANCE + 1 }, 20)).toBe(false);
  });

  test("endLine range overlapping the seeded line hits", () => {
    // finding spans lines 40..60; seeded line 20 is far below, no overlap even
    // with tolerance.
    expect(findingHitsSeededRegion({ path: "x", line: 40, endLine: 60 }, 20)).toBe(false);
    // finding spans 10..25; seeded line 20 falls inside the range.
    expect(findingHitsSeededRegion({ path: "x", line: 10, endLine: 25 }, 20)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// scoreLiveCase — detection

describe("scoreLiveCase detection", () => {
  test("a finding on the seeded file within the region is a detection, no FP", () => {
    const c = defectCase({ line: 20 });
    const env = envelope({ findings: [mkFinding("src/x.ts", 21, "error")] });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 1, fidelityFailures: [] });
    expect(r.detected).toBe(true);
    expect(r.falsePositives).toBe(0);
  });

  test("a finding on the wrong file is a miss and a false positive", () => {
    const c = defectCase({ line: 20, path: "src/x.ts" });
    const env = envelope({ findings: [mkFinding("src/other.ts", 20, "error")] });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.detected).toBe(false);
    expect(r.falsePositives).toBe(1);
  });

  test("a finding on the right file outside the region is a miss and a false positive", () => {
    const c = defectCase({ line: 20 });
    const env = envelope({ findings: [mkFinding("src/x.ts", 200, "error")] });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.detected).toBe(false);
    expect(r.falsePositives).toBe(1);
  });

  test("one detector plus one stray finding: detected with one FP", () => {
    const c = defectCase({ line: 20 });
    const env = envelope({
      findings: [mkFinding("src/x.ts", 20, "error"), mkFinding("src/x.ts", 300, "warn")],
    });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 1, fidelityFailures: [] });
    expect(r.detected).toBe(true);
    expect(r.falsePositives).toBe(1);
  });

  test("carried/resolved findings never count as detections (only env.findings scored)", () => {
    const c = defectCase({ line: 20 });
    // The detector is only present in `resolved`, not in the active findings.
    const env = envelope({ findings: [], resolved: [mkFinding("src/x.ts", 20, "error")] });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.detected).toBe(false);
    expect(r.falsePositives).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// scoreLiveCase — clean fixtures and gate

describe("scoreLiveCase clean and gate", () => {
  test("clean fixture with no findings: no FP, detection undefined", () => {
    const env = envelope({ findings: [], silent: true });
    const r = scoreLiveCase({ case: cleanCase(), model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.detected).toBeNull();
    expect(r.falsePositives).toBe(0);
    expect(r.type).toBe("clean");
  });

  test("clean fixture with any finding: every finding is a false positive", () => {
    const env = envelope({ findings: [mkFinding("src/y.ts", 3, "warn")] });
    const r = scoreLiveCase({ case: cleanCase(), model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.falsePositives).toBe(1);
  });

  test("gate correctness: error defect wants a failing gate", () => {
    const c = defectCase({ severity: "error" });
    const env = envelope({ findings: [mkFinding("src/x.ts", 20, "error")], gate: { failOn: "error", failing: true } });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 1, fidelityFailures: [] });
    expect(r.gateFailingExpected).toBe(true);
    expect(r.gateFailingActual).toBe(true);
    expect(r.gateCorrect).toBe(true);
  });

  test("gate correctness: model that fails to fail the gate on an error defect is scored incorrect", () => {
    const c = defectCase({ severity: "error" });
    const env = envelope({ findings: [mkFinding("src/x.ts", 20, "warn")], gate: { failOn: "error", failing: false } });
    const r = scoreLiveCase({ case: c, model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.gateCorrect).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cost

describe("cost", () => {
  test("cost is prompt*promptPrice + completion*completionPrice", () => {
    const env = envelope({ usage: { promptTokens: 1000, completionTokens: 200 }, findings: [] });
    const r = scoreLiveCase({ case: cleanCase(), model: "m", envelope: env, pricing, exitCode: 0, fidelityFailures: [] });
    expect(r.costUsd).toBeCloseTo(1000 * 0.000001 + 200 * 0.000002, 12);
  });

  test("cost is null when pricing is unknown", () => {
    const env = envelope({ findings: [] });
    const r = scoreLiveCase({ case: cleanCase(), model: "m", envelope: env, pricing: null, exitCode: 0, fidelityFailures: [] });
    expect(r.costUsd).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// aggregateModel

describe("aggregateModel", () => {
  test("detection rate, FP sum, mean cost/duration, gate tally, total cost", () => {
    const c = defectCase({ line: 20 });
    const hit = scoreLiveCase({
      case: c,
      model: "m",
      envelope: envelope({ findings: [mkFinding("src/x.ts", 20, "error")], usage: { promptTokens: 1000, completionTokens: 100 }, durationMs: 1000, gate: { failOn: "error", failing: true } }),
      pricing,
      exitCode: 1,
      fidelityFailures: [],
    });
    const miss = scoreLiveCase({
      case: c,
      model: "m",
      envelope: envelope({ findings: [mkFinding("src/x.ts", 999, "warn")], usage: { promptTokens: 2000, completionTokens: 300 }, durationMs: 3000, gate: { failOn: "error", failing: false } }),
      pricing,
      exitCode: 0,
      fidelityFailures: [],
    });
    const agg = aggregateModel("m", [hit, miss]);
    expect(agg.detectionRate).toBeCloseTo(0.5, 10);
    expect(agg.defectCases).toBe(2);
    expect(agg.casesRun).toBe(2);
    expect(agg.falsePositives).toBe(1); // the miss's stray finding
    const costHit = 1000 * 0.000001 + 100 * 0.000002;
    const costMiss = 2000 * 0.000001 + 300 * 0.000002;
    expect(agg.totalCostUsd).toBeCloseTo(costHit + costMiss, 12);
    expect(agg.meanCostUsdPerReview).toBeCloseTo((costHit + costMiss) / 2, 12);
    expect(agg.meanDurationMs).toBeCloseTo(2000, 6);
    expect(agg.gateScored).toBe(2);
    // The miss's envelope reports a passing gate on an error-severity defect, so
    // its gate verdict is scored incorrect; only the hit's gate is correct.
    expect(agg.gateCorrect).toBe(1);
  });

  test("errored cases are excluded from scoring but counted as errors", () => {
    const c = defectCase();
    const err = erroredLiveCase({ case: c, model: "m", exitCode: 2, error: "no valid v1 envelope (exit 2)" });
    const agg = aggregateModel("m", [err]);
    expect(agg.casesRun).toBe(0);
    expect(agg.errors).toBe(1);
    expect(agg.detectionRate).toBe(0);
  });

  test("empty results produce zeroed aggregate", () => {
    const agg = aggregateModel("m", []);
    expect(agg).toMatchObject({ detectionRate: 0, casesRun: 0, meanCostUsdPerReview: 0, meanDurationMs: 0, totalCostUsd: 0 });
  });
});

// ---------------------------------------------------------------------------
// Run cost total

describe("calculateTotalRunCostUsd", () => {
  test("sums included per-case costs and matches per-model totals", () => {
    const c = defectCase({ line: 20 });
    const modelA = [
      scoreLiveCase({
        case: c,
        model: "a/model",
        envelope: envelope({ usage: { promptTokens: 1000, completionTokens: 100 } }),
        pricing,
        exitCode: 0,
        fidelityFailures: [],
      }),
      scoreLiveCase({
        case: cleanCase(),
        model: "a/model",
        envelope: envelope({ usage: { promptTokens: 500, completionTokens: 50 } }),
        pricing,
        exitCode: 0,
        fidelityFailures: [],
      }),
    ];
    const modelB = [
      scoreLiveCase({
        case: c,
        model: "b/model",
        envelope: envelope({ usage: { promptTokens: 200, completionTokens: 20 } }),
        pricing,
        exitCode: 0,
        fidelityFailures: [],
      }),
      scoreLiveCase({
        case: cleanCase(),
        model: "b/model",
        envelope: envelope({ usage: { promptTokens: 999, completionTokens: 999 } }),
        pricing: null,
        exitCode: 0,
        fidelityFailures: [],
      }),
      erroredLiveCase({ case: c, model: "b/model", exitCode: 2, error: "no valid v1 envelope (exit 2)" }),
    ];

    const results = [...modelA, ...modelB];
    const perCaseTotal = results.reduce((sum, r) => sum + (r.costUsd ?? 0), 0);
    const perModelTotal =
      aggregateModel("a/model", modelA).totalCostUsd + aggregateModel("b/model", modelB).totalCostUsd;

    expect(calculateTotalRunCostUsd(results)).toBeCloseTo(perCaseTotal, 12);
    expect(calculateTotalRunCostUsd(results)).toBeCloseTo(perModelTotal, 12);
  });
});

// ---------------------------------------------------------------------------
// Site schema shape

describe("toSiteModelAggregate", () => {
  test("emits exactly the six site fields", () => {
    const agg = aggregateModel("m", [
      scoreLiveCase({ case: defectCase({ line: 20 }), model: "m", envelope: envelope({ findings: [mkFinding("src/x.ts", 20, "error")] }), pricing, exitCode: 1, fidelityFailures: [] }),
    ]);
    const site = toSiteModelAggregate(agg);
    expect(Object.keys(site).sort()).toEqual(
      ["casesRun", "detectionRate", "falsePositives", "id", "meanCostUsdPerReview", "meanDurationMs"].sort(),
    );
  });
});

// ---------------------------------------------------------------------------
// Pricing catalog

describe("pricingFromCatalog", () => {
  const catalog = {
    data: [
      { id: "a/model", pricing: { prompt: "0.000001", completion: "0.000002" } },
      { id: "b/model", pricing: { prompt: "0", completion: "0" } },
      { id: "c/model", pricing: { prompt: "", completion: "x" } },
      { id: "d/unwanted", pricing: { prompt: "0.5", completion: "0.5" } },
    ],
  };

  test("keeps only wanted models with parseable prices", () => {
    const p = pricingFromCatalog(catalog, ["a/model", "b/model", "c/model"]);
    expect(p.get("a/model")).toEqual({ promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000002 });
    expect(p.get("b/model")).toEqual({ promptUsdPerToken: 0, completionUsdPerToken: 0 });
    expect(p.has("c/model")).toBe(false); // unparseable
    expect(p.has("d/unwanted")).toBe(false); // not requested
  });
});

// ---------------------------------------------------------------------------
// Cost guardrail projection

describe("projectTotalCostUsd", () => {
  test("estimate is a fixed overhead plus diff length over the divisor", () => {
    expect(estimateCasePromptTokens("")).toBe(GUARDRAIL_SYSTEM_PROMPT_TOKENS);
    expect(estimateCasePromptTokens("a".repeat(30))).toBe(GUARDRAIL_SYSTEM_PROMPT_TOKENS + 10);
  });

  test("projects prompt+completion cost across every case-model pair", () => {
    const diffs = ["a".repeat(30), "b".repeat(60)];
    const models = ["a/model", "b/model"];
    const p = new Map<string, ModelPricing>([
      ["a/model", { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000002 }],
      ["b/model", { promptUsdPerToken: 0.000003, completionUsdPerToken: 0.000004 }],
    ]);
    const total = projectTotalCostUsd({ diffs, models, pricing: p });
    let expected = 0;
    for (const model of models) {
      const price = p.get(model)!;
      for (const diff of diffs) {
        expected +=
          estimateCasePromptTokens(diff) * price.promptUsdPerToken +
          GUARDRAIL_COMPLETION_TOKENS * price.completionUsdPerToken;
      }
    }
    expect(total).toBeCloseTo(expected, 12);
  });

  test("models with unknown pricing contribute zero to the projection", () => {
    const total = projectTotalCostUsd({
      diffs: ["x".repeat(100)],
      models: ["priced", "unpriced"],
      pricing: new Map([["priced", { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000001 }]]),
    });
    const only = projectTotalCostUsd({
      diffs: ["x".repeat(100)],
      models: ["priced"],
      pricing: new Map([["priced", { promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000001 }]]),
    });
    expect(total).toBeCloseTo(only, 12);
  });
});
