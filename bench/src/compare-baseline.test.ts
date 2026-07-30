import { describe, expect, test } from "bun:test";
import {
  DETECTION_RATE_MAX_DROP_PP,
  FALSE_FINDINGS_MAX_INCREASE,
  GATE_VERDICT_MAX_DROP_PP,
  LATENCY_P95_MAX_INCREASE_RATIO,
  MEAN_COST_MAX_INCREASE_RATIO,
  compareMetrics,
  extractObservedMetrics,
  formatComparisonTable,
  percentile,
  type BaselineProfile,
  type LiveReportForComparison,
} from "./compare-baseline";

function fakeReport(overrides: {
  falsePositives?: number;
  observedProviderCostUsdDecimal?: string;
  results?: LiveReportForComparison["results"];
  detected?: number;
} = {}): LiveReportForComparison {
  const results: LiveReportForComparison["results"] = overrides.results ?? [
    { id: "must-block-1", type: "defect", scored: true, truthSeverity: "error", durationMs: 1000, exitCode: 1 },
    { id: "must-block-2", type: "defect", scored: true, truthSeverity: "error", durationMs: 2000, exitCode: 1 },
    { id: "advisory-1", type: "defect", scored: true, truthSeverity: "warn", durationMs: 1500, exitCode: 0 },
    { id: "clean-1", type: "clean", scored: true, truthSeverity: null, durationMs: 500, exitCode: 0 },
  ];
  const defectCases = results.filter((r) => r.type === "defect").length;
  return {
    summary: {
      model: "z-ai/glm-5.2",
      reviewMode: "exhaustive",
      fixtureCorpusSha256: "corpus-sha",
      evaluatorSha256: "evaluator-sha",
      totalCases: results.length,
      scoredCases: results.filter((r) => r.scored).length,
      defectCases,
      detected: overrides.detected ?? defectCases,
      falsePositives: overrides.falsePositives ?? 0,
      observedProviderCostUsdDecimal: overrides.observedProviderCostUsdDecimal ?? "0.004",
      ranAt: "2026-01-01T00:00:00.000Z",
    },
    results,
  };
}

const populatedBaseline: Extract<BaselineProfile, { populated: true }> = {
  populated: true,
  generatedAt: "2026-01-01T00:00:00.000Z",
  reviewMode: "exhaustive",
  sourceRunAt: "2026-01-01T00:00:00.000Z",
  totalCases: 70,
  scoredCases: 70,
  detectionRate: 0.95,
  falsePositives: 2,
  gateVerdictCorrectness: 0.97,
  meanCostUsdPerCase: 0.003,
  latencyMs: { p50: 4000, p95: 9000 },
};

describe("percentile", () => {
  test("nearest-rank over a sorted sample", () => {
    const sorted = [10, 20, 30, 40, 50];
    expect(percentile(sorted, 50)).toBe(30);
    expect(percentile(sorted, 95)).toBe(50);
    expect(percentile(sorted, 1)).toBe(10);
  });

  test("single-element sample returns that element at any percentile", () => {
    expect(percentile([42], 50)).toBe(42);
    expect(percentile([42], 95)).toBe(42);
  });

  test("rejects an empty sample", () => {
    expect(() => percentile([], 50)).toThrow("empty sample");
  });
});

describe("extractObservedMetrics", () => {
  test("derives detection rate, gate-verdict correctness, cost, and latency from a live report", () => {
    const metrics = extractObservedMetrics(fakeReport());
    // 2 defects, 2 detected.
    expect(metrics.detectionRate).toBeCloseTo(1, 5);
    // All four scored cases: two must-block exit 1 (correct), one advisory
    // exit 0 (correct), one clean exit 0 (correct) => 4/4 correct.
    expect(metrics.gateVerdictCorrectness).toBeCloseTo(1, 5);
    expect(metrics.meanCostUsdPerCase).toBeCloseTo(0.004 / 4, 6);
    expect(metrics.latencyMs.p50).toBeGreaterThan(0);
    expect(metrics.latencyMs.p95).toBe(2000);
  });

  test("scores a wrongly-blocked advisory case as an incorrect gate verdict", () => {
    const report = fakeReport({
      results: [
        { id: "must-block-1", type: "defect", scored: true, truthSeverity: "error", durationMs: 1000, exitCode: 1 },
        // An advisory (warn) case that the model over-blocked: exit 1 when it
        // should have exited 0.
        { id: "advisory-1", type: "defect", scored: true, truthSeverity: "warn", durationMs: 1500, exitCode: 1 },
      ],
    });
    const metrics = extractObservedMetrics(report);
    expect(metrics.gateVerdictCorrectness).toBeCloseTo(0.5, 5);
  });

  test("excludes unscored (errored) cases from gate-verdict and latency scoring", () => {
    const report = fakeReport({
      results: [
        { id: "must-block-1", type: "defect", scored: true, truthSeverity: "error", durationMs: 1000, exitCode: 1 },
        { id: "errored-1", type: "defect", scored: false, truthSeverity: "error", durationMs: null, exitCode: undefined },
      ],
    });
    const metrics = extractObservedMetrics(report);
    expect(metrics.gateVerdictCorrectness).toBeCloseTo(1, 5);
    expect(metrics.latencyMs.p50).toBe(1000);
  });

  test("names an all-unscored run an operational failure, not a regression", () => {
    // A release blocked because the model got worse and one blocked because the
    // run never reached the model need different responses from whoever reads
    // the log, so the message has to say which happened.
    const report = fakeReport({
      results: [
        { id: "errored-1", type: "defect", scored: false, truthSeverity: "error", durationMs: null, exitCode: undefined },
        { id: "errored-2", type: "defect", scored: false, truthSeverity: "error", durationMs: null, exitCode: undefined },
      ],
    });
    expect(() => extractObservedMetrics(report)).toThrow(
      "scored none of its 2 cases",
    );
    expect(() => extractObservedMetrics(report)).toThrow(
      "operational failure rather than a quality regression",
    );
  });
});

describe("compareMetrics", () => {
  test("passes when observed metrics match baseline exactly", () => {
    const baseline = { ...populatedBaseline, detectionRate: 1, gateVerdictCorrectness: 1 };
    const observed = extractObservedMetrics(fakeReport({
      falsePositives: baseline.falsePositives,
      observedProviderCostUsdDecimal: String(baseline.meanCostUsdPerCase * 4),
    }));
    const comparison = compareMetrics(baseline, observed);
    expect(comparison.ok).toBe(true);
    expect(comparison.rows.every((row) => row.verdict === "PASS")).toBe(true);
  });

  test("fails when detection rate drops more than the tolerance", () => {
    const baseline = { ...populatedBaseline, detectionRate: 0.98 };
    const observed = extractObservedMetrics(fakeReport({
      detected: 1,
      results: [
        { id: "must-block-1", type: "defect", scored: true, truthSeverity: "error", durationMs: 1000, exitCode: 1 },
        { id: "must-block-2", type: "defect", scored: true, truthSeverity: "error", durationMs: 1000, exitCode: 0 },
      ],
    }));
    expect(observed.detectionRate).toBeCloseTo(0.5, 5);
    expect(0.98 - observed.detectionRate).toBeGreaterThan(DETECTION_RATE_MAX_DROP_PP / 100);
    const comparison = compareMetrics(baseline, observed);
    expect(comparison.ok).toBe(false);
    expect(comparison.rows.find((row) => row.metric === "detection rate")?.verdict).toBe("FAIL");
  });

  test("tolerates a detection-rate drop within the percentage-point budget", () => {
    // Baseline 69/70, observed 68/70: a ~1.4pp drop, inside the 2pp budget.
    const baseline = { ...populatedBaseline, detectionRate: 69 / 70 };
    const observed = extractObservedMetrics(fakeReport()); // detectionRate 1.0 here; force via override below
    const nearlyEqual = { ...observed, detectionRate: 68 / 70 };
    const comparison = compareMetrics(baseline, nearlyEqual);
    expect(comparison.rows.find((row) => row.metric === "detection rate")?.verdict).toBe("PASS");
  });

  test("reports false/unrelated findings past the budget without blocking", () => {
    // Six runs of one unchanged binary spanned 4 to 7 false findings against a
    // budget of baseline + 2, so this threshold marks a run worth reading, not
    // a release worth stopping.
    const observed = extractObservedMetrics(fakeReport({
      falsePositives: populatedBaseline.falsePositives + FALSE_FINDINGS_MAX_INCREASE + 1,
    }));
    const comparison = compareMetrics(populatedBaseline, observed);
    const row = comparison.rows.find((r) => r.metric === "false/unrelated findings");
    expect(row?.verdict).toBe("FAIL");
    expect(row?.informational).toBe(true);
    expect(comparison.ok).toBe(true);
  });

  test("says so in the table when a reported metric leaves its usual range", () => {
    const observed = extractObservedMetrics(fakeReport({
      falsePositives: populatedBaseline.falsePositives + FALSE_FINDINGS_MAX_INCREASE + 1,
    }));
    const table = formatComparisonTable(compareMetrics(populatedBaseline, observed).rows);
    expect(table).toContain("Outside its usual range, but not blocking");
    expect(table).toContain("false/unrelated findings");
  });

  test("a detection-rate drop still blocks the release", () => {
    // The one metric whose spread across those runs (3.5pp) stayed inside a
    // threshold that can still catch a real regression.
    const observed = {
      ...extractObservedMetrics(fakeReport()),
      detectionRate: populatedBaseline.detectionRate - (DETECTION_RATE_MAX_DROP_PP / 100) - 0.01,
    };
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((r) => r.metric === "detection rate")?.verdict).toBe("FAIL");
    expect(comparison.ok).toBe(false);
  });

  test("reports a gate-verdict drop past the tolerance without blocking", () => {
    const baseline = { ...populatedBaseline, gateVerdictCorrectness: 1 };
    const observed = { ...extractObservedMetrics(fakeReport()), gateVerdictCorrectness: 1 - (GATE_VERDICT_MAX_DROP_PP / 100) - 0.01 };
    const comparison = compareMetrics(baseline, observed);
    const row = comparison.rows.find((r) => r.metric === "gate verdict correctness");
    expect(row?.verdict).toBe("FAIL");
    expect(row?.informational).toBe(true);
    expect(comparison.ok).toBe(true);
  });

  test("fails when mean cost rises past the ratio budget", () => {
    const observed = { ...extractObservedMetrics(fakeReport()), meanCostUsdPerCase: populatedBaseline.meanCostUsdPerCase * (1 + MEAN_COST_MAX_INCREASE_RATIO) + 0.001 };
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric === "mean cost per case")?.verdict).toBe("FAIL");
  });

  test("fails when p95 latency rises past the ratio budget", () => {
    const observed = {
      ...extractObservedMetrics(fakeReport()),
      latencyMs: { p50: 1000, p95: populatedBaseline.latencyMs.p95 * (1 + LATENCY_P95_MAX_INCREASE_RATIO) + 1 },
    };
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric === "p95 latency (ms)")?.verdict).toBe("FAIL");
  });
});
