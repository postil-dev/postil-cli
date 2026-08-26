import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import {
  aggregateObservedMetrics,
  assertCompleteCohortEvidence,
  assertDistinctRunIdentities,
  assertDistinctRawReportDigests,
  assertExpectedRunIdentities,
  assertBaselineCalibrationIntegrity,
  assertReportsBoundToInputs,
  assertValidReleaseReport,
  compareMetrics,
  comparisonCohortSha256,
  buildCalibrationEvidence,
  exactMeanCostWithinTolerance,
  extractObservedMetrics,
  formatComparisonTable,
  formatRebaselineGuidance,
  isCalibratedBaselineProfile,
  meanDetectionCountWithinMargin,
  median,
  parseBaselineFile,
  parseCliArguments,
  percentile,
  type BaselineProfile,
  type LiveReportForComparison,
} from "./compare-baseline";
import {
  sha256,
  type CohortManifest,
  type CohortReceipt,
} from "./cohort";
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
  const baseline = parseBaselineFile(JSON.parse(
    await readFile(resolve(import.meta.dir, "..", "baseline.json"), "utf8"),
  ));
  const fixtureCorpusSha256 = createHash("sha256")
    .update(JSON.stringify(cases.map((input) => benchmarkCase.parse(input))))
    .digest("hex");

  expect(baseline.corpus.fixtureCorpusSha256).toBe(fixtureCorpusSha256);
  expect(baseline.corpus.evaluatorSha256).toBe(await evaluatorSourceSha256());
});

test("committed Luna baseline is either fail-closed or has a valid ten-report calibration", async () => {
  const baseline = parseBaselineFile(JSON.parse(
    await readFile(resolve(import.meta.dir, "..", "baseline.json"), "utf8"),
  ));
  const profile = baseline.profiles["openai/gpt-5.6-luna"];

  expect(baseline.schemaVersion).toBe(2);
  if (profile === undefined) throw new Error("committed Luna baseline profile must exist");
  if (!profile.populated) {
    expect(profile.instructions).toContain("predeclared ten-slot calibration cohort");
    return;
  }
  expect(isCalibratedBaselineProfile(profile)).toBe(true);
  if (!isCalibratedBaselineProfile(profile)) {
    throw new Error("committed Luna baseline must contain calibration evidence");
  }
  expect(profile.calibration.reportCount).toBe(10);
  expect(() => assertBaselineCalibrationIntegrity(profile)).not.toThrow();
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
      providerGenerationIds: [`gen-fixture-${fakeRunSequence}`],
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
  sourceRunAt: "2026-08-25T00:00:06.000Z",
  providerContractEnforced: true,
  screeningProfileSha256: HASHES.profile,
  upstreamProviderIdentity: "Azure",
  totalCases: 70,
  scoredCases: 70,
  defectCases: 57,
  detectionRate: 54 / 57,
  falsePositives: 0,
  gateVerdictCorrectness: 1,
  meanCostUsdPerCase: 0.001,
  maximumRunCostUsdDecimal: "0.07",
  costCaseCount: 70,
  latencyMs: { p50: 3500, p95: 6700 },
  calibration: {
    reportCount: 10,
    cohortId: "00000000-0000-4000-8000-000000000001",
    manifestSha256: "9".repeat(64),
    sourceSha: "a".repeat(40),
    workflowRunId: "456",
    binarySha256: HASHES.binary,
    providerContractSha256: HASHES.contract,
    comparisonCohortSha256: comparisonCohortSha256(fakeReport().summary),
    reports: Array.from({ length: 10 }, (_, index) => ({
      slot: index + 1,
      nonce: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      runId: `calibration-${index + 1}`,
      ranAt: `2026-08-25T00:00:${String(index + 1).padStart(2, "0")}.000Z`,
      rawSha256: String(index + 1).padStart(64, "0"),
      semanticSha256: String(index + 11).padStart(64, "0"),
      receiptRawSha256: String(index + 21).padStart(64, "0"),
      binarySha256: HASHES.binary,
      detected: 54,
      falsePositives: 0,
      gateVerdictCorrect: 70,
      totalCostUsdDecimal: "0.07",
      p50LatencyMs: 3500,
      p95LatencyMs: 6700,
    })),
  },
};

test("calibration baseline is internally consistent and uses exact count arithmetic", () => {
  expect(() => assertBaselineCalibrationIntegrity(populatedBaseline)).not.toThrow();
  expect(meanDetectionCountWithinMargin(540, 10, 260, 5)).toBe(true);
  expect(meanDetectionCountWithinMargin(540, 10, 259, 5)).toBe(false);

  const tamperedDetection = structuredClone(populatedBaseline);
  tamperedDetection.detectionRate = 53 / 57;
  expect(() => assertBaselineCalibrationIntegrity(tamperedDetection)).toThrow(
    "detection rate does not match",
  );

  const tamperedLatency = structuredClone(populatedBaseline);
  tamperedLatency.latencyMs.p95 += 1;
  expect(() => assertBaselineCalibrationIntegrity(tamperedLatency)).toThrow(
    "latency does not match",
  );

  const tamperedFalseFindings = structuredClone(populatedBaseline);
  tamperedFalseFindings.falsePositives = 1;
  expect(() => assertBaselineCalibrationIntegrity(tamperedFalseFindings)).toThrow(
    "false finding count does not match",
  );

  const tamperedGateCorrectness = structuredClone(populatedBaseline);
  tamperedGateCorrectness.gateVerdictCorrectness = 0.9;
  expect(() => assertBaselineCalibrationIntegrity(tamperedGateCorrectness)).toThrow(
    "gate verdict correctness does not match",
  );

  const tamperedMaximumCost = structuredClone(populatedBaseline);
  tamperedMaximumCost.maximumRunCostUsdDecimal = "0.071";
  expect(() => assertBaselineCalibrationIntegrity(tamperedMaximumCost)).toThrow(
    "maximum run cost does not match",
  );

  const tamperedCostCases = structuredClone(populatedBaseline);
  tamperedCostCases.costCaseCount = 69;
  expect(() => assertBaselineCalibrationIntegrity(tamperedCostCases)).toThrow(
    "cost case count does not match",
  );

  const tamperedMeanCost = structuredClone(populatedBaseline);
  tamperedMeanCost.meanCostUsdPerCase = 0.002;
  expect(() => assertBaselineCalibrationIntegrity(tamperedMeanCost)).toThrow(
    "mean cost does not match",
  );

  const tamperedSourceTimestamp = structuredClone(populatedBaseline);
  tamperedSourceTimestamp.sourceRunAt = "2026-08-25T00:00:01.000Z";
  expect(() => assertBaselineCalibrationIntegrity(tamperedSourceTimestamp)).toThrow(
    "source timestamp does not match",
  );

  const tamperedDetectionBounds = structuredClone(populatedBaseline);
  tamperedDetectionBounds.calibration.reports[0]!.detected = 58;
  tamperedDetectionBounds.calibration.reports[1]!.detected = 50;
  expect(() => assertBaselineCalibrationIntegrity(tamperedDetectionBounds)).toThrow(
    "exceeds the defect count",
  );

  const tamperedGateBounds = structuredClone(populatedBaseline);
  tamperedGateBounds.calibration.reports[0]!.gateVerdictCorrect = 71;
  tamperedGateBounds.calibration.reports[1]!.gateVerdictCorrect = 69;
  expect(() => assertBaselineCalibrationIntegrity(tamperedGateBounds)).toThrow(
    "exceeds the total case count",
  );

  const tamperedBinaryDigest = structuredClone(populatedBaseline);
  tamperedBinaryDigest.calibration.binarySha256 = "a".repeat(64);
  expect(() => assertBaselineCalibrationIntegrity(tamperedBinaryDigest)).toThrow(
    "different binary digest",
  );

  const fractionalFalseFindingMedian = structuredClone(populatedBaseline);
  fractionalFalseFindingMedian.calibration.reports.forEach((report, index) => {
    report.falsePositives = index < 5 ? 0 : 1;
  });
  fractionalFalseFindingMedian.falsePositives = 0.5;
  expect(() => assertBaselineCalibrationIntegrity(fractionalFalseFindingMedian)).not.toThrow();
  const parsed = parseBaselineFile({
    schemaVersion: 2,
    corpus: {
      fixtureCorpusSha256: HASHES.corpus,
      evaluatorSha256: HASHES.evaluator,
    },
    profiles: { "openai/gpt-5.6-luna": fractionalFalseFindingMedian },
  });
  expect(parsed.profiles["openai/gpt-5.6-luna"]?.falsePositives).toBe(0.5);
});

test("buildCalibrationEvidence preserves ten-run provenance and rejects incomplete identity", () => {
  const observed = aggregateObservedMetrics(
    Array.from({ length: 10 }, () => fakeReport({ detected: 54 })),
  );
  const rawReports = observed.perRun.map((run, index) => ({
    slot: index + 1,
    nonce: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    runId: run.runId,
    startedAt: `2026-08-25T00:01:${String(index + 1).padStart(2, "0")}.000Z`,
    rawSha256: String(index + 1).padStart(64, "0"),
    semanticSha256: String(index + 11).padStart(64, "0"),
    receiptRawSha256: String(index + 21).padStart(64, "0"),
  }));
  const manifest = {
    cohortId: "00000000-0000-4000-8000-000000000001",
    manifestSha256: "9".repeat(64),
    sourceSha: "a".repeat(40),
    workflowRunId: "456",
  };
  const evidence = buildCalibrationEvidence(observed, rawReports, manifest);
  expect(evidence.reportCount).toBe(10);
  expect(evidence.binarySha256).toBe(HASHES.binary);
  expect(evidence.providerContractSha256).toBe(HASHES.contract);
  expect(evidence.comparisonCohortSha256).toBe(observed.comparisonCohortSha256);
  expect(evidence.reports).toHaveLength(10);
  expect(evidence.reports.every((report) => report.detected === 54)).toBe(true);
  expect(evidence.reports.every((report) => report.binarySha256 === HASHES.binary)).toBe(true);
  expect(evidence.reports.map((report) => report.runId)).toEqual(
    observed.perRun.map((run) => run.runId),
  );
  expect(evidence.reports.map((report) => report.rawSha256)).toEqual(
    rawReports.map((report) => report.rawSha256),
  );
  expect(() => buildCalibrationEvidence(observed, rawReports.slice(0, 9), manifest)).toThrow(
    "one raw digest per report",
  );
  const duplicateRunIds = [...rawReports];
  duplicateRunIds[9] = { ...duplicateRunIds[9]!, runId: duplicateRunIds[0]!.runId };
  expect(() => buildCalibrationEvidence(observed, duplicateRunIds, manifest)).toThrow(
    "raw report run IDs must be unique",
  );
  const releaseObserved = aggregateObservedMetrics(
    Array.from({ length: 5 }, () => fakeReport({ detected: 54 })),
  );
  expect(() => buildCalibrationEvidence(releaseObserved, [], manifest)).toThrow(
    "requires exactly 10 observed reports",
  );
});

function fakeReleaseCohort(reports: readonly LiveReportForComparison[]): {
  manifest: CohortManifest;
  receipts: Array<{ receipt: CohortReceipt; rawSha256: string }>;
  rawReportSha256: string[];
  parsedReports: unknown[];
  expectedRunIds: string[];
} {
  const createdAt = "2026-08-25T00:00:00.000Z";
  const slots = reports.map((report, index) => ({
    slot: index + 1,
    runId: report.summary.runId,
    nonce: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  }));
  const manifest: CohortManifest = {
    schemaVersion: 2,
    purpose: reports.length === 10 ? "calibration" : "release",
    cohortId: "00000000-0000-4000-8000-000000000099",
    createdAt,
    reportCount: reports.length as 5 | 10,
    binarySha256: HASHES.binary,
    evaluatorSha256: HASHES.evaluator,
    fixtureCorpusSha256: HASHES.corpus,
    screeningProfileSha256: HASHES.profile,
    providerContractSha256: HASHES.contract,
    execution: reports.length === 10
      ? {
          kind: "github-sigstore-v1",
          repository: "postil-dev/postil-cli",
          signerWorkflow: ".github/workflows/benchmark-calibration.yml",
          sourceSha: "b".repeat(40),
          sourceRef: "refs/heads/main",
          runId: "456",
          runAttempt: "1",
        }
      : {
          kind: "github-sigstore-v1",
          repository: "postil-dev/postil-cli",
          signerWorkflow: ".github/workflows/release.yml",
          sourceSha: "a".repeat(40),
          sourceRef: "refs/tags/v0.0.0",
          runId: "123",
          runAttempt: "1",
        },
    slots,
  };
  const parsedReports = reports.map((report) => structuredClone(report));
  const rawReportSha256 = parsedReports.map((report) => sha256(JSON.stringify(report)));
  const receipts = reports.map((report, index) => ({
    receipt: {
      schemaVersion: 2,
      state: "completed",
      manifestSha256: "9".repeat(64),
      cohortId: manifest.cohortId,
      purpose: manifest.purpose,
      slot: index + 1,
      nonce: slots[index]!.nonce,
      runId: report.summary.runId,
      startedAt: "2026-08-25T00:00:00.000Z",
      finishedAt: "2026-08-25T23:59:59.999Z",
      exitCode: 0,
      reportRawSha256: rawReportSha256[index]!,
    } as CohortReceipt,
    rawSha256: String(index + 31).padStart(64, "0"),
  }));
  return {
    manifest,
    receipts,
    rawReportSha256,
    parsedReports,
    expectedRunIds: slots.map((slot) => slot.runId),
  };
}

describe("predeclared cohort evidence", () => {
  test("accepts every completed immutable slot", () => {
    const reports = Array.from({ length: 5 }, (_, index) => fakeReport({
      durationMultiplier: index + 1,
    }));
    const cohort = fakeReleaseCohort(reports);
    expect(() => assertCompleteCohortEvidence({
      ...cohort,
      manifestSha256: "9".repeat(64),
      reports,
      record: false,
    })).not.toThrow();
  });

  test("allows identical semantic outcomes when every raw artifact is separately authenticated", () => {
    const original = fakeReport({ durationMultiplier: 7 });
    const reports = Array.from({ length: 5 }, (_, index) => {
      const report = cloneReport(original);
      report.summary.runId = `cloned-${index + 1}`;
      report.summary.ranAt = `2026-08-25T00:10:0${index}.000Z`;
      report.summary.providerGenerationIds = [`gen-cloned-${index + 1}`];
      return report;
    });
    const cohort = fakeReleaseCohort(reports);
    expect(() => assertCompleteCohortEvidence({
      ...cohort,
      manifestSha256: "9".repeat(64),
      reports,
      record: false,
    })).not.toThrow();
  });

  test("rejects missing, failed, and mismatched slots", () => {
    const reports = Array.from({ length: 5 }, (_, index) => fakeReport({
      durationMultiplier: index + 1,
    }));
    const cohort = fakeReleaseCohort(reports);
    expect(() => assertCompleteCohortEvidence({
      ...cohort,
      receipts: cohort.receipts.slice(0, 4),
      manifestSha256: "9".repeat(64),
      reports,
      record: false,
    })).toThrow("every declared report and receipt slot");

    const failed = structuredClone(cohort.receipts);
    failed[2]!.receipt = {
      ...failed[2]!.receipt,
      state: "failed",
      exitCode: 1,
      failure: "benchmark-exit",
    } as CohortReceipt;
    expect(() => assertCompleteCohortEvidence({
      ...cohort,
      receipts: failed,
      manifestSha256: "9".repeat(64),
      reports,
      record: false,
    })).toThrow("slot 3 is failed");

    expect(() => assertCompleteCohortEvidence({
      ...cohort,
      expectedRunIds: [...cohort.expectedRunIds.slice(0, 4), "substituted"],
      manifestSha256: "9".repeat(64),
      reports,
      record: false,
    })).toThrow("exactly match the predeclared cohort slots");
  });
});

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

  test("binds scorer and timeout settings to the calibration execution identity", () => {
    const report = fakeReport();
    const scorerChanged = cloneReport(report);
    scorerChanged.summary.scorerMode = "enabled";
    scorerChanged.summary.scorerModel = "openai/gpt-5.6-luna";
    const timeoutChanged = cloneReport(report);
    timeoutChanged.summary.timeoutOverrides.requestSeconds = "120";

    expect(comparisonCohortSha256(scorerChanged.summary)).not.toBe(
      comparisonCohortSha256(report.summary),
    );
    expect(comparisonCohortSha256(timeoutChanged.summary)).not.toBe(
      comparisonCohortSha256(report.summary),
    );
    const observed = extractObservedMetrics(report);
    expect(() => compareMetrics(populatedBaseline, {
      ...observed,
      comparisonCohortSha256: "f".repeat(64),
    })).toThrow("execution identity does not match");
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

describe("three-report aggregation compatibility", () => {
  test("52/54/53 passes the detection floor", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 54 }),
      fakeReport({ detected: 53 }),
    ]);
    expect(observed.detectionRate).toBe(53 / 57);
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric.includes("detection rate"))?.verdict).toBe("PASS");
    expect(comparison.ok).toBe(true);
  });

  test("51/52/52 fails the two-defect non-inferiority floor", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 51 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
    ]);
    expect(observed.detectionRate).toBe(155 / (57 * 3));
    const comparison = compareMetrics(populatedBaseline, observed);
    expect(comparison.rows.find((row) => row.metric.includes("detection rate"))?.verdict).toBe("FAIL");
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
    reformatted.summary.providerGenerationIds = ["gen-reformatted"];
    rewritten.summary.providerGenerationIds = ["gen-rewritten"];
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
      (row) => row.metric.includes("false/unrelated findings"),
    );
    const gateRow = comparison.rows.find(
      (row) => row.metric.includes("gate verdict correctness"),
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

describe("five-report release aggregation", () => {
  test("uses exact count arithmetic at the two-defect non-inferiority boundary", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 51 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 53 }),
    ]);
    expect(observed.reportCount).toBe(5);
    expect(observed.detectionRate).toBe(260 / (57 * 5));
    expect(compareMetrics(populatedBaseline, observed).rows.find(
      (row) => row.metric.includes("detection rate"),
    )?.verdict).toBe("PASS");
  });

  test("fails when the five-report cohort mean is one defect below the boundary", () => {
    const observed = aggregateObservedMetrics([
      fakeReport({ detected: 51 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
      fakeReport({ detected: 52 }),
    ]);
    expect(observed.detectionRate).toBe(259 / (57 * 5));
    expect(compareMetrics(populatedBaseline, observed).rows.find(
      (row) => row.metric.includes("detection rate"),
    )?.verdict).toBe("FAIL");
  });

  test("requires all five reports to share the cohort while retaining full ranges", () => {
    const reports = [
      fakeReport({ detected: 49, falsePositives: 0, durationMultiplier: 1 }),
      fakeReport({ detected: 50, falsePositives: 1, durationMultiplier: 2 }),
      fakeReport({ detected: 51, falsePositives: 0, durationMultiplier: 3 }),
      fakeReport({ detected: 52, falsePositives: 2, durationMultiplier: 4 }),
      fakeReport({ detected: 53, falsePositives: 1, durationMultiplier: 5 }),
    ];
    const observed = aggregateObservedMetrics(reports);
    expect(observed.ranges.falsePositives).toEqual({ min: 0, max: 2 });
    expect(observed.ranges.p95LatencyMs).toEqual({ min: 67, max: 335 });
    const mismatched = cloneReport(reports[4]!);
    mismatched.summary.binarySha256 = "6".repeat(64);
    expect(() => aggregateObservedMetrics([...reports.slice(0, 4), mismatched])).toThrow(
      "cohort mismatch for summary.binarySha256",
    );
  });

  test("accepts the ten-report cohort used by baseline recording", () => {
    const reports = Array.from({ length: 10 }, () => fakeReport({ detected: 52 }));
    const observed = aggregateObservedMetrics(reports);
    expect(observed.reportCount).toBe(10);
    expect(observed.detectionRate).toBe(52 / 57);
  });
});

describe("CLI report selection", () => {
  const releaseInputs = [
    "--binary", "target/release/postil",
    "--screen-profile", "provisional-models.json",
  ];
  const fiveCohortInputs = [
    "--cohort-manifest", "release-cohort.json",
    ...["one", "two", "three", "four", "five"].flatMap((path) => [
      "--receipt", `${path}.receipt.json`,
    ]),
  ];

  test("accepts exactly one, three, or five distinct --result paths", () => {
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
    expect(parseCliArguments([
      ...releaseInputs,
      ...["one", "two", "three", "four", "five"].flatMap((runId) => [
        "--expected-run-id", runId,
      ]),
      ...["one", "two", "three", "four", "five"].flatMap((path) => [
        "--result", `${path}.json`,
      ]),
      ...fiveCohortInputs,
    ]).resultPaths).toEqual([
      "one.json", "two.json", "three.json", "four.json", "five.json",
    ]);
  });

  test("rejects every other report count", () => {
    expect(() => parseCliArguments([])).toThrow("exactly 1, 3, or 5");
    expect(() => parseCliArguments(["--result", "one", "--result", "two"])).toThrow(
      "exactly 1, 3, or 5",
    );
    expect(() => parseCliArguments([
      "--result", "one",
      "--result", "two",
      "--result", "three",
      "--result", "four",
    ])).toThrow("exactly 1, 3, or 5");
    expect(() => parseCliArguments([
      "--result", "one",
      "--result", "two",
      "--result", "three",
      "--result", "four",
      "--result", "five",
      "--result", "six",
    ])).toThrow("exactly 1, 3, or 5");
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

  test("requires exactly ten reports for baseline recording", () => {
    expect(() => parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--result", "one.json",
      "--record",
    ])).toThrow("--record requires exactly ten --result reports");
    expect(parseCliArguments([
      ...releaseInputs,
      "--expected-run-id", "one",
      "--expected-run-id", "two",
      "--expected-run-id", "three",
      "--expected-run-id", "four",
      "--expected-run-id", "five",
      "--expected-run-id", "six",
      "--expected-run-id", "seven",
      "--expected-run-id", "eight",
      "--expected-run-id", "nine",
      "--expected-run-id", "ten",
      "--result", "one.json",
      "--result", "two.json",
      "--result", "three.json",
      "--result", "four.json",
      "--result", "five.json",
      "--result", "six.json",
      "--result", "seven.json",
      "--result", "eight.json",
      "--result", "nine.json",
      "--result", "ten.json",
      "--cohort-manifest", "calibration-cohort.json",
      ...["one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"].flatMap(
        (path) => ["--receipt", `${path}.receipt.json`],
      ),
      "--record",
    ]).record).toBe(true);
    expect(() => parseCliArguments([
      ...releaseInputs,
      ...["one", "two", "three", "four", "five"].flatMap((runId) => [
        "--expected-run-id", runId,
      ]),
      ...["one", "two", "three", "four", "five"].flatMap((path) => [
        "--result", `${path}.json`,
      ]),
      ...fiveCohortInputs,
      "--record",
    ])).toThrow("--record requires exactly ten --result reports");
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

  test("prints an executable ten-report calibration command only for a complete cohort", () => {
    expect(formatRebaselineGuidance({
      binaryPath: "target/release/postil",
      screeningProfilePath: "provisional models.json",
      expectedRunIds: [
        "one", "two", "three", "four", "five",
        "six", "seven", "eight", "nine", "ten",
      ],
      resultPaths: [
        "one.json", "two report.json", "three.json", "four.json", "five.json",
        "six.json", "seven.json", "eight.json", "nine.json", "ten.json",
      ],
      cohortManifestPath: "calibration cohort.json",
      receiptPaths: [
        "one.receipt.json", "two receipt.json", "three.receipt.json",
        "four.receipt.json", "five.receipt.json", "six.receipt.json",
        "seven.receipt.json", "eight.receipt.json", "nine.receipt.json",
        "ten.receipt.json",
      ],
    })).toBe([
      "  bun run bench:compare -- \\",
      "    --binary 'target/release/postil' \\",
      "    --screen-profile 'provisional models.json' \\",
      "    --cohort-manifest 'calibration cohort.json' \\",
      "    --expected-run-id 'one' \\",
      "    --expected-run-id 'two' \\",
      "    --expected-run-id 'three' \\",
      "    --expected-run-id 'four' \\",
      "    --expected-run-id 'five' \\",
      "    --expected-run-id 'six' \\",
      "    --expected-run-id 'seven' \\",
      "    --expected-run-id 'eight' \\",
      "    --expected-run-id 'nine' \\",
      "    --expected-run-id 'ten' \\",
      "    --result 'one.json' \\",
      "    --result 'two report.json' \\",
      "    --result 'three.json' \\",
      "    --result 'four.json' \\",
      "    --result 'five.json' \\",
      "    --result 'six.json' \\",
      "    --result 'seven.json' \\",
      "    --result 'eight.json' \\",
      "    --result 'nine.json' \\",
      "    --result 'ten.json' \\",
      "    --receipt 'one.receipt.json' \\",
      "    --receipt 'two receipt.json' \\",
      "    --receipt 'three.receipt.json' \\",
      "    --receipt 'four.receipt.json' \\",
      "    --receipt 'five.receipt.json' \\",
      "    --receipt 'six.receipt.json' \\",
      "    --receipt 'seven.receipt.json' \\",
      "    --receipt 'eight.receipt.json' \\",
      "    --receipt 'nine.receipt.json' \\",
      "    --receipt 'ten.receipt.json' \\",
      "    --record",
    ].join("\n"));

    expect(formatRebaselineGuidance({
      binaryPath: "target/release/postil",
      screeningProfilePath: "provisional-models.json",
      expectedRunIds: ["one"],
      resultPaths: ["one.json"],
      receiptPaths: [],
    })).toContain("predeclared ten-report calibration cohort");
  });
});
