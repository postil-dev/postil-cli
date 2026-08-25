import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import {
  DETECTION_RATE_MAX_DROP_PP,
  aggregateObservedMetrics,
  assertDistinctRunIdentities,
  assertDistinctRawReportDigests,
  assertExpectedRunIdentities,
  assertReportsBoundToInputs,
  assertValidReleaseReport,
  compareMetrics,
  exactMeanCostWithinTolerance,
  extractObservedMetrics,
  formatComparisonTable,
  formatRebaselineGuidance,
  median,
  parseCliArguments,
  percentile,
  type BaselineProfile,
  type LiveReportForComparison,
} from "./compare-baseline";
import { benchmarkCase } from "./harness";
import {
  ADMISSION_API_BASE,
  evaluatorSourceSha256,
  screeningProfileMetadata,
} from "./live";
import {
  formatCanonicalDecimal,
  parseCanonicalDecimal,
  providerContractSha256,
  sumCanonicalDecimals,
  type ProviderContractEvidence,
} from "./livemodels-score";

test("committed baseline authority matches the current benchmark sources", async () => {
  const baseline = JSON.parse(
    await readFile(resolve(import.meta.dir, "..", "baseline.json"), "utf8"),
  ) as {
    corpus: { fixtureCorpusSha256: string; evaluatorSha256: string };
  };
  const fixtureCorpusSha256 = createHash("sha256")
    .update(JSON.stringify(cases.map((input) => benchmarkCase.parse(input))))
    .digest("hex");

  expect(baseline.corpus.fixtureCorpusSha256).toBe(fixtureCorpusSha256);
  expect(baseline.corpus.evaluatorSha256).toBe(await evaluatorSourceSha256());
});

const PROVIDER_CONTRACT: ProviderContractEvidence = {
  version: 1,
  benchmarkProviderIdentity: "openrouter:managed-routing",
  upstreamProviderIdentity: "Azure",
  upstreamProviderRoute: "azure/eu",
  dataCollection: "deny",
  zeroDataRetention: true,
  allowFallbacks: false,
  generatorRequireParameters: false,
  scorerRequireParameters: true,
  maxPricePinned: true,
  maxPriceUnits: "USD per million tokens",
  modelPriceBounds: [{
    model: "openai/gpt-5.6-luna",
    roles: ["generator", "scorer"],
    inputMicrosPerMillionTokens: 400_000,
    outputMicrosPerMillionTokens: 1_600_000,
  }],
};

const HASHES = {
  binary: "1".repeat(64),
  corpus: "2".repeat(64),
  evaluator: "3".repeat(64),
  profile: "4".repeat(64),
  contract: providerContractSha256(PROVIDER_CONTRACT),
} as const;

interface FakeReportOptions {
  detected?: number;
  falsePositives?: number;
  costPerCase?: string;
  durationMultiplier?: number;
  ranAt?: string;
  runId?: string;
}

let fakeRunSequence = 0;

function fakeReport(options: FakeReportOptions = {}): LiveReportForComparison {
  fakeRunSequence += 1;
  const detected = options.detected ?? 54;
  const falsePositives = options.falsePositives ?? 0;
  const costPerCase = options.costPerCase ?? "0.001";
  const durationMultiplier = options.durationMultiplier ?? 100;
  const results: LiveReportForComparison["results"] = Array.from({ length: 70 }, (_, index) => {
    const defect = index < 57;
    const truthSeverity = defect ? (index < 47 ? "error" : "warn") : null;
    const caseDetected = defect ? index < detected : null;
    return {
      id: `${defect ? "defect" : "clean"}-${String(index + 1).padStart(2, "0")}`,
      type: defect ? "defect" : "clean",
      scored: true,
      detected: caseDetected,
      truthSeverity,
      falsePositives: index === 0 ? falsePositives : 0,
      durationMs: (index + 1) * durationMultiplier,
      observedProviderCostUsdDecimal: costPerCase,
      costAccountingComplete: true,
      exitCode: truthSeverity === "error" && caseDetected === true ? 1 : 0,
    };
  });
  const observedProviderCostUsdDecimal = formatCanonicalDecimal(sumCanonicalDecimals(
    results.map(() => parseCanonicalDecimal(costPerCase)),
  ));

  return {
    summary: {
      runId: options.runId ?? `fixture-run-${fakeRunSequence}`,
      model: "openai/gpt-5.6-luna",
      binarySha256: HASHES.binary,
      providerIdentity: "openrouter:managed-routing",
      apiBase: ADMISSION_API_BASE,
      apiFormat: "openai-compatible",
      scorerMode: "disabled",
      scorerModel: null,
      reviewMode: "exhaustive",
      evidenceScope: "full-corpus",
      selectedCaseIds: [],
      providerContractEnforced: true,
      screeningProfileSha256: HASHES.profile,
      upstreamProviderIdentity: "Azure",
      upstreamProviderRoute: "azure/eu",
      providerContractSha256: HASHES.contract,
      providerContract: structuredClone(PROVIDER_CONTRACT),
      fixtureCorpusSha256: HASHES.corpus,
      evaluatorSha256: HASHES.evaluator,
      timeoutOverrides: {
        requestSeconds: null,
        totalSeconds: null,
        caseProcessMilliseconds: 180_000,
      },
      totalCases: 70,
      scoredCases: 70,
      defectCases: 57,
      cleanCases: 13,
      detected,
      falsePositives,
      detectionRate: `${detected}/57`,
      observedProviderCostUsdDecimal,
      costAccountingComplete: true,
      errors: 0,
      ranAt: options.ranAt ?? new Date(Date.UTC(2026, 7, 25, 0, 0, fakeRunSequence)).toISOString(),
    },
    results,
  };
}

function cloneReport(report: LiveReportForComparison): LiveReportForComparison {
  return structuredClone(report);
}

async function inputBoundReport(): Promise<LiveReportForComparison> {
  const report = fakeReport();
  const parsedCases = cases.map((input) => benchmarkCase.parse(input));
  let detected = 0;
  report.results = parsedCases.map((fixture, index) => {
    const finding = fixture.groundTruth.findings[0];
    const defect = finding !== undefined;
    const caseDetected = defect && detected < 54;
    if (caseDetected) detected += 1;
    return {
      id: fixture.id,
      type: defect ? "defect" : "clean",
      scored: true,
      detected: defect ? caseDetected : null,
      truthSeverity: finding?.severity ?? null,
      falsePositives: 0,
      durationMs: (index + 1) * 100,
      observedProviderCostUsdDecimal: "0.001",
      costAccountingComplete: true,
      exitCode: caseDetected && finding?.severity === "error" ? 1 : 0,
    };
  });
  const screeningProfilePath = resolve(import.meta.dir, "..", "..", "provisional-models.json");
  const [binary, evaluatorSha256, profile] = await Promise.all([
    readFile(process.execPath),
    evaluatorSourceSha256(),
    screeningProfileMetadata(screeningProfilePath),
  ]);
  Object.assign(report.summary, {
    binarySha256: createHash("sha256").update(binary).digest("hex"),
    fixtureCorpusSha256: createHash("sha256")
      .update(JSON.stringify(parsedCases))
      .digest("hex"),
    evaluatorSha256,
    screeningProfileSha256: profile.sha256,
    upstreamProviderIdentity: profile.upstreamProviderIdentity,
    upstreamProviderRoute: profile.upstreamProviderRoute,
    providerContractSha256: profile.providerContractSha256,
    providerContract: profile.providerContract,
    totalCases: parsedCases.length,
    scoredCases: parsedCases.length,
    defectCases: parsedCases.filter((fixture) => fixture.groundTruth.findings.length > 0).length,
    cleanCases: parsedCases.filter((fixture) => fixture.groundTruth.findings.length === 0).length,
    detected,
    falsePositives: 0,
    detectionRate: `${detected}/${parsedCases.filter((fixture) => fixture.groundTruth.findings.length > 0).length}`,
    observedProviderCostUsdDecimal: formatCanonicalDecimal(sumCanonicalDecimals(
      parsedCases.map(() => parseCanonicalDecimal("0.001")),
    )),
    errors: 0,
  });
  return report;
}

const populatedBaseline: Extract<BaselineProfile, { populated: true }> = {
  populated: true,
  generatedAt: "2026-08-25T00:00:00.000Z",
  reviewMode: "exhaustive",
  sourceRunAt: "2026-08-25T00:00:00.000Z",
  providerContractEnforced: true,
  screeningProfileSha256: HASHES.profile,
  upstreamProviderIdentity: "Azure",
  totalCases: 70,
  scoredCases: 70,
  detectionRate: 54 / 57,
  falsePositives: 0,
  gateVerdictCorrectness: 1,
  meanCostUsdPerCase: 0.001,
  maximumRunCostUsdDecimal: "0.07",
  costCaseCount: 70,
  latencyMs: { p50: 3500, p95: 6700 },
};

describe("sample math", () => {
  test("uses nearest-rank percentiles", () => {
    expect(percentile([10, 20, 30, 40, 50], 50)).toBe(30);
    expect(percentile([10, 20, 30, 40, 50], 95)).toBe(50);
    expect(percentile([42], 95)).toBe(42);
    expect(() => percentile([], 50)).toThrow("empty sample");
  });

  test("computes a median without depending on input order", () => {
    expect(median([52, 54, 53])).toBe(53);
    expect(median([54, 52, 53])).toBe(53);
    expect(() => median([])).toThrow("empty sample");
  });

  test("uses the median per-run nearest-rank p95 and maximum per-run mean cost", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ durationMultiplier: 1, costPerCase: "0.001" }),
      fakeReport({ durationMultiplier: 100, costPerCase: "0.003" }),
      fakeReport({ durationMultiplier: 10, costPerCase: "0.002" }),
    ]);

    expect(observed.latencyMs.p95).toBe(670);
    expect(observed.ranges.p95LatencyMs).toEqual({ min: 67, max: 6700 });
    expect(observed.meanCostUsdPerCase).toBeCloseTo(0.003, 10);
    expect(observed.ranges.meanCostUsdPerCase.min).toBeCloseTo(0.001, 10);
    expect(observed.ranges.meanCostUsdPerCase.max).toBeCloseTo(0.003, 10);
    expect(
      compareMetrics(populatedBaseline, observed).rows.find(
        (row) => row.metric === "maximum mean cost per case",
      )?.verdict,
    ).toBe("FAIL");
  });
});

describe("release report validation", () => {
  test("accepts one complete full-corpus report", () => {
    expect(() => assertValidReleaseReport(fakeReport())).not.toThrow();
    expect(extractObservedMetrics(fakeReport()).reportCount).toBe(1);
  });

  test("rejects 69 of 70 scored cases", () => {
    const report = cloneReport(fakeReport());
    report.summary.scoredCases = 69;
    report.results[69]!.scored = false;
    report.results[69]!.durationMs = null;
    expect(() => assertValidReleaseReport(report)).toThrow("scoredCases must equal totalCases");
  });

  test("rejects any operational error", () => {
    const report = cloneReport(fakeReport());
    report.summary.errors = 1;
    expect(() => assertValidReleaseReport(report)).toThrow("errors must be 0");
  });

  test("rejects a missing scored-case exit code", () => {
    const report = cloneReport(fakeReport());
    (report.results[12] as { exitCode?: number }).exitCode = undefined;
    expect(() => assertValidReleaseReport(report)).toThrow(
      "every scored result must have CLI exit code 0 or 1",
    );
  });

  test("rejects incomplete summary or per-result cost accounting", () => {
    const incompleteSummary = cloneReport(fakeReport());
    incompleteSummary.summary.costAccountingComplete = false;
    expect(() => assertValidReleaseReport(incompleteSummary)).toThrow(
      "summary cost accounting must be complete",
    );

    const incompleteResult = cloneReport(fakeReport());
    incompleteResult.results[12]!.costAccountingComplete = false;
    expect(() => assertValidReleaseReport(incompleteResult)).toThrow(
      "every result must have complete cost accounting",
    );

    const missingResultCost = cloneReport(fakeReport());
    missingResultCost.results[12]!.observedProviderCostUsdDecimal = null;
    expect(() => assertValidReleaseReport(missingResultCost)).toThrow(
      "every result must have canonical observed provider cost",
    );
  });

  test("rejects noncanonical costs and a summary that does not equal the result total", () => {
    const noncanonical = cloneReport(fakeReport());
    noncanonical.results[0]!.observedProviderCostUsdDecimal = "0.0010";
    expect(() => assertValidReleaseReport(noncanonical)).toThrow("canonical nonnegative decimal");

    const inconsistent = cloneReport(fakeReport());
    inconsistent.summary.observedProviderCostUsdDecimal = "0.071";
    expect(() => assertValidReleaseReport(inconsistent)).toThrow("does not match result total");
  });

  test("rejects non-release scope, provider contract, hash, and identity fields", () => {
    const invalidReports: Array<[string, (report: LiveReportForComparison) => void]> = [
      ["reviewMode must be exhaustive", (report) => { report.summary.reviewMode = "bounded"; }],
      ["evidenceScope must be full-corpus", (report) => { report.summary.evidenceScope = "selected-cases"; }],
      ["selectedCaseIds must be empty", (report) => { report.summary.selectedCaseIds = ["defect-01"]; }],
      ["providerContractEnforced must be true", (report) => { report.summary.providerContractEnforced = false; }],
      ["binarySha256 must be exactly 64", (report) => { report.summary.binarySha256 = "A".repeat(64); }],
      ["fixtureCorpusSha256 must be exactly 64", (report) => { report.summary.fixtureCorpusSha256 = "short"; }],
      ["evaluatorSha256 must be exactly 64", (report) => { report.summary.evaluatorSha256 = "short"; }],
      ["screeningProfileSha256 must be exactly 64", (report) => { report.summary.screeningProfileSha256 = "short"; }],
      ["providerContractSha256 must be exactly 64", (report) => { report.summary.providerContractSha256 = "short"; }],
      ["providerIdentity must be nonempty", (report) => {
        (report.summary as { providerIdentity: string }).providerIdentity = "";
      }],
      ["upstreamProviderIdentity must be nonempty", (report) => { report.summary.upstreamProviderIdentity = ""; }],
      ["upstreamProviderRoute must be nonempty", (report) => { report.summary.upstreamProviderRoute = " "; }],
      ["apiBase must be nonempty", (report) => {
        (report.summary as { apiBase: string }).apiBase = "";
      }],
      ["apiFormat must be nonempty", (report) => {
        (report.summary as { apiFormat: string }).apiFormat = "";
      }],
    ];

    for (const [message, mutate] of invalidReports) {
      const report = cloneReport(fakeReport());
      mutate(report);
      expect(() => assertValidReleaseReport(report)).toThrow(message);
    }
  });

  test("binds provider identity, route, models, and digest to the exact contract", () => {
    const identityMismatch = cloneReport(fakeReport());
    (identityMismatch.summary as { providerIdentity: string }).providerIdentity = "custom";
    expect(() => assertValidReleaseReport(identityMismatch)).toThrow(
      "providerIdentity must match the enforced provider contract",
    );

    const routeMismatch = cloneReport(fakeReport());
    routeMismatch.summary.upstreamProviderRoute = "azure/us";
    expect(() => assertValidReleaseReport(routeMismatch)).toThrow(
      "upstreamProviderRoute must match the enforced provider contract",
    );

    const contractMismatch = cloneReport(fakeReport());
    contractMismatch.summary.providerContract.modelPriceBounds[0]!.outputMicrosPerMillionTokens += 1;
    expect(() => assertValidReleaseReport(contractMismatch)).toThrow(
      "providerContractSha256 must match the enforced provider contract",
    );

    const modelMismatch = cloneReport(fakeReport());
    modelMismatch.summary.model = "openai/other";
    expect(() => assertValidReleaseReport(modelMismatch)).toThrow(
      "review model must have a generator price bound",
    );
  });

  test("binds reports to the supplied binary, corpus, evaluator, and screening profile", async () => {
    const report = await inputBoundReport();
    const screeningProfilePath = resolve(import.meta.dir, "..", "..", "provisional-models.json");
    await expect(
      assertReportsBoundToInputs([report], process.execPath, screeningProfilePath),
    ).resolves.toBeUndefined();

    report.summary.binarySha256 = "f".repeat(64);
    await expect(
      assertReportsBoundToInputs([report], process.execPath, screeningProfilePath),
    ).rejects.toThrow("binarySha256 is not bound to the supplied release input");
  });

  test("rejects a non-release API even when its fields are nonempty", () => {
    const report = cloneReport(fakeReport());
    (report.summary as { apiBase: string }).apiBase = "https://not-openrouter.invalid/v1";
    (report.summary as { apiFormat: string }).apiFormat = "arbitrary";
    expect(() => assertValidReleaseReport(report)).toThrow(
      "provider API must be the managed OpenRouter release endpoint",
    );
  });
});

describe("three-report aggregation", () => {
  test("52/54/53 passes the detection floor", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 54 }),
      fakeReport({ detected: 53 }),
    ]);
    expect(observed.detectionRate).toBe(53 / 57);
    expect(populatedBaseline.detectionRate - observed.detectionRate).toBeLessThan(
      DETECTION_RATE_MAX_DROP_PP / 100,
    );
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric === "median detection rate")?.verdict).toBe("PASS");
    expect(comparison.ok).toBe(true);
  });

  test("52/54/52 fails the detection floor", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 54 }),
      fakeReport({ detected: 52 }),
    ]);
    expect(observed.detectionRate).toBe(52 / 57);
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric === "median detection rate")?.verdict).toBe("FAIL");
    expect(comparison.ok).toBe(false);
  });

  test("is independent of report order", () => {
    const reports = [
      fakeReport({ detected: 52, falsePositives: 3, ranAt: "2026-08-25T00:00:01.000Z" }),
      fakeReport({ detected: 54, falsePositives: 1, ranAt: "2026-08-25T00:00:03.000Z" }),
      fakeReport({ detected: 53, falsePositives: 2, ranAt: "2026-08-25T00:00:02.000Z" }),
    ] as const;
    expect(aggregateObservedMetrics(reports)).toEqual(
      aggregateObservedMetrics([reports[2], reports[0], reports[1]]),
    );
  });

  test("rejects a cohort mismatch", () => {
    const mismatched = cloneReport(fakeReport());
    mismatched.summary.binarySha256 = "6".repeat(64);
    expect(() => aggregateObservedMetrics([fakeReport(), mismatched, fakeReport()])).toThrow(
      "cohort mismatch for summary.binarySha256",
    );
  });

  test("rejects repeated logical run identities even when raw files differ", () => {
    const first = fakeReport();
    const reformatted = cloneReport(first);
    const rewritten = cloneReport(first);
    expect(() => assertDistinctRunIdentities([first, reformatted, rewritten])).toThrow(
      "distinct benchmark run IDs",
    );
    expect(() => assertExpectedRunIdentities([first], ["different-run"])).toThrow(
      "does not match its expected run identity",
    );
    expect(() => aggregateObservedMetrics([first, reformatted, rewritten])).toThrow(
      "distinct benchmark run IDs",
    );
  });

  test("keeps false findings and gate correctness informational with the observed range", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ falsePositives: 3 }),
      fakeReport({ falsePositives: 5 }),
      fakeReport({ falsePositives: 4 }),
    ]);
    const comparison = compareMetrics(populatedBaseline, observed);
    const falseFindingRow = comparison.rows.find(
      (row) => row.metric === "median false/unrelated findings",
    );
    const gateRow = comparison.rows.find(
      (row) => row.metric === "median gate verdict correctness",
    );
    expect(falseFindingRow?.verdict).toBe("FAIL");
    expect(falseFindingRow?.informational).toBe(true);
    expect(falseFindingRow?.detail).toContain("range 3-5");
    expect(gateRow?.informational).toBe(true);
    expect(gateRow?.detail).toContain("range");
    expect(comparison.ok).toBe(true);
    expect(formatComparisonTable(comparison.rows)).toContain(
      "Outside its usual range, but not blocking",
    );
  });

  test("cost remains blocking when the provider profile differs", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ costPerCase: "1" }),
      fakeReport({ costPerCase: "1" }),
      fakeReport({ costPerCase: "1" }),
    ]);
    observed.screeningProfileSha256 = "f".repeat(64);
    const comparison = compareMetrics(populatedBaseline, observed);
    const cost = comparison.rows.find((row) => row.metric === "maximum mean cost per case");
    expect(cost?.verdict).toBe("FAIL");
    expect(cost?.informational).not.toBe(true);
    expect(comparison.ok).toBe(false);
  });

  test("compares the blocking cost ceiling without IEEE-754 rounding", () => {
    expect(exactMeanCostWithinTolerance("8.75", 70, "7", 70)).toBe(true);
    expect(exactMeanCostWithinTolerance("8.750000000000000007", 70, "7", 70)).toBe(false);
  });
});

describe("CLI report selection", () => {
  const releaseInputs = [
    "--binary", "target/release/postil",
    "--screen-profile", "provisional-models.json",
  ];

  test("accepts exactly one or three distinct --result paths", () => {
    expect(parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--result", "one.json",
    ]).resultPaths).toEqual(["one.json"]);
    expect(parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--expected-run-id", "two",
      "--expected-run-id", "three",
      "--result", "one.json",
      "--result", "two.json",
      "--result", "three.json",
    ]).resultPaths).toEqual(["one.json", "two.json", "three.json"]);
  });

  test("rejects every other report count", () => {
    expect(() => parseCliArguments([])).toThrow("exactly 1 or 3");
    expect(() => parseCliArguments(["--result", "one", "--result", "two"])).toThrow(
      "exactly 1 or 3",
    );
    expect(() => parseCliArguments([
      "--result", "one",
      "--result", "two",
      "--result", "three",
      "--result", "four",
    ])).toThrow("exactly 1 or 3");
  });

  test("rejects duplicate paths and duplicate raw reports", () => {
    expect(() => parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--expected-run-id", "two",
      "--expected-run-id", "three",
      "--result", "one.json",
      "--result", "./one.json",
      "--result", "three.json",
    ])).toThrow("path must be distinct");
    expect(() => assertDistinctRawReportDigests([
      "a".repeat(64),
      "b".repeat(64),
      "a".repeat(64),
    ])).toThrow("distinct raw SHA-256 digests");
  });

  test("requires the same three-sample estimator for rebaselining", () => {
    expect(() => parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--result", "one.json",
      "--record",
    ])).toThrow("--record requires exactly three --result reports");
    expect(parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--expected-run-id", "two",
      "--expected-run-id", "three",
      "--result", "one.json",
      "--result", "two.json",
      "--result", "three.json",
      "--record",
    ]).record).toBe(true);
  });

  test("requires explicit release binary and screening profile inputs", () => {
    expect(() => parseCliArguments([
      "--expected-run-id", "one",
      "--result", "one.json",
    ])).toThrow(
      "requires --binary",
    );
    expect(() => parseCliArguments([
      "--binary", "postil",
      "--expected-run-id", "one",
      "--result", "one.json",
    ])).toThrow("requires --screen-profile");
    expect(() => parseCliArguments([
      ...releaseInputs,
      "--result", "one.json",
    ])).toThrow("one --expected-run-id per --result report");
  });

  test("prints an executable three-report rebaseline command only for a complete cohort", () => {
    expect(formatRebaselineGuidance({
      binaryPath: "target/release/postil",
      screeningProfilePath: "provisional models.json",
      expectedRunIds: ["one", "two", "three"],
      resultPaths: ["one.json", "two report.json", "three.json"],
    })).toBe([
      "  bun run bench:compare -- \\",
      "    --binary 'target/release/postil' \\",
      "    --screen-profile 'provisional models.json' \\",
      "    --expected-run-id 'one' \\",
      "    --expected-run-id 'two' \\",
      "    --expected-run-id 'three' \\",
      "    --result 'one.json' \\",
      "    --result 'two report.json' \\",
      "    --result 'three.json' \\",
      "    --record",
    ].join("\n"));

    expect(formatRebaselineGuidance({
      binaryPath: "target/release/postil",
      screeningProfilePath: "provisional-models.json",
      expectedRunIds: ["one"],
      resultPaths: ["one.json"],
    })).toContain("collect three independent complete reports");
  });
});
