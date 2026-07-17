import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  BINARY_GATES,
  BINARY_QUESTIONS,
  BINEVAL_BANK_VERSION,
  BINEVAL_CANONICAL_DEVELOPMENT_BANKS,
  BINEVAL_CONTRACT_VERSION,
  BINEVAL_DEVELOPMENT_BANK,
  BINEVAL_EVALUATION_DEVELOPMENT_BANK,
  EvaluationTransportError,
  MAX_SCORER_CALL_TIMEOUT_MS,
  MAX_SCORER_COST_USD_PER_CALL,
  MAX_SCORER_EXPERIMENT_REPEATS,
  MAX_SCORER_PROVIDER_FIELD_BYTES,
  MAX_SCORER_RESPONSE_BYTES,
  MAX_SCORER_TOKENS_PER_CALL,
  aggregateScorerExperiment,
  buildEvaluationRequests,
  buildScorerExperimentReport,
  evaluateScorerCase,
  evaluationRequestDigest,
  runCompleteDevelopmentScorerExperiment,
  runScorerExperiment,
  scorerBankDigest,
  scorerEvaluationContractDigest,
  scorerSourceDigest,
  type BinaryGate,
  type CallTelemetry,
  type EvaluationCallEvidence,
  type EvaluationMethod,
  type EvaluationRequest,
  type EvaluationResponse,
  type EvaluationTransport,
  type ExperimentProvenance,
  type ScorerCase,
  type ScorerExperimentCaseCapture,
} from "./bineval-scorer";

const provenance: ExperimentProvenance = {
  runId: "hermetic-development-experiment",
  model: "fixture/model",
  provider: "fixture-provider",
  settings: { temperature: 0, seed: 7 },
  sourceSha: scorerSourceDigest(),
  repeatCount: 2,
};

function scorerCase(id: string): ScorerCase {
  const candidate = BINEVAL_CANONICAL_DEVELOPMENT_BANKS
    .flatMap((bank) => bank.cases)
    .find((entry) => entry.id === id);
  if (!candidate) throw new Error(`missing development evaluation case ${id}`);
  return candidate;
}

function response(content: unknown, overrides: Partial<EvaluationResponse> = {}): EvaluationResponse {
  return {
    content: typeof content === "string" ? content : JSON.stringify(content),
    elapsedMs: 20,
    promptTokens: 100,
    completionTokens: 10,
    costUsd: 0.001,
    providerGenerationId: null,
    providerReceipt: null,
    ...overrides,
  };
}

function receiptResponse(request: EvaluationRequest, content: unknown): EvaluationResponse {
  const generationId = `generation-${request.method}-${request.caseId}-${request.gate ?? "all"}-${request.repeat}`;
  return response(content, {
    providerGenerationId: generationId,
    providerReceipt: {
      receiptId: `receipt-${generationId}`,
      generationId,
      provider: request.provenance.provider,
      model: request.provenance.model,
      requestDigest: evaluationRequestDigest(request),
      promptTokens: 100,
      completionTokens: 10,
      costUsd: 0.001,
    },
  });
}

function accurateTransport(requestLog: EvaluationRequest[] = []): EvaluationTransport {
  return async (request) => {
    requestLog.push(request);
    const candidate = scorerCase(request.caseId);
    if (request.method === "scalar") {
      return receiptResponse(request, [{
        index: 0,
        confidence: candidate.expectedPublish ? 0.9 : 0.1,
        kind: candidate.expectedPublish ? "risk" : "uncertainty",
        reason: "The publication-gate result is supported.",
      }]);
    }
    if (request.method === "binaryBatch") {
      return receiptResponse(request, {
        verdicts: BINARY_GATES.map((gate) => ({
          gate,
          pass: candidate.expectedGates[gate],
          reason: "The gate result is supported.",
        })),
      });
    }
    const gate = request.gate as BinaryGate;
    return receiptResponse(request, {
      gate,
      pass: candidate.expectedGates[gate],
      reason: "The gate result is supported.",
    });
  };
}

function replaceCapture(
  captures: ScorerExperimentCaseCapture[],
  index: number,
  replacement: ScorerExperimentCaseCapture,
): ScorerExperimentCaseCapture[] {
  const copy = [...captures];
  copy[index] = replacement;
  return copy;
}

function evidenceDigest(evidence: EvaluationCallEvidence[]): string {
  return createHash("sha256").update(JSON.stringify(evidence)).digest("hex");
}

function freezeCapture(capture: ScorerExperimentCaseCapture): ScorerExperimentCaseCapture {
  Object.freeze(capture.callEvidence);
  return Object.freeze(capture);
}

describe("development-only evidence banks", () => {
  test("does not claim an independently held-out partition", () => {
    expect(BINEVAL_DEVELOPMENT_BANK.version).toBe(BINEVAL_BANK_VERSION);
    expect(BINEVAL_EVALUATION_DEVELOPMENT_BANK.version).toBe(BINEVAL_BANK_VERSION);
    expect(BINEVAL_DEVELOPMENT_BANK.phase).toBe("development");
    expect(BINEVAL_EVALUATION_DEVELOPMENT_BANK.phase).toBe("evaluationDevelopment");
    expect(BINEVAL_EVALUATION_DEVELOPMENT_BANK.cases).toHaveLength(10);
    expect(BINEVAL_CANONICAL_DEVELOPMENT_BANKS).toHaveLength(2);
    expect(BINEVAL_CANONICAL_DEVELOPMENT_BANKS.reduce(
      (count, bank) => count + bank.cases.length,
      0,
    )).toBe(20);
    const implementation = readFileSync(new URL("./bineval-scorer.ts", import.meta.url), "utf8");
    const fixture = readFileSync(new URL("./bineval-evaluation-development.fixture.ts", import.meta.url), "utf8");
    expect(implementation).toContain("cannot support validation");
    expect(fixture).toContain("do not constitute a held-out validation partition");
    expect(implementation).not.toContain("FIXTURE_SEAL");
    expect(Object.isFrozen(BINEVAL_EVALUATION_DEVELOPMENT_BANK)).toBe(true);
    expect(Object.isFrozen(BINEVAL_EVALUATION_DEVELOPMENT_BANK.cases[0]!.finding)).toBe(true);
    expect(scorerBankDigest()).toMatch(/^[0-9a-f]{64}$/);
  });

  test("keeps development evaluation identities and evidence separate", () => {
    const families = new Set(BINEVAL_DEVELOPMENT_BANK.cases.map((candidate) => candidate.problemFamily));
    for (const candidate of BINEVAL_EVALUATION_DEVELOPMENT_BANK.cases) {
      expect(candidate.id.startsWith("evaluationDevelopment-")).toBe(true);
      expect(families.has(candidate.problemFamily)).toBe(false);
      expect(candidate.expectedPublish).toBe(BINARY_GATES.every((gate) => candidate.expectedGates[gate]));
      expect(candidate.classification === "clean").toBe(!candidate.expectedPublish);
    }
  });

  test("keeps negative fixture truth aligned with the claimed changed behavior", () => {
    const typeOnlyImport = scorerCase("evaluationDevelopment-type-only-import");
    expect(typeOnlyImport.expectedGates).toMatchObject({
      grounding: false,
      causality: false,
      diffNovelty: false,
      materiality: true,
      actionability: false,
    });
    expect(typeOnlyImport.expectedGateRationales.grounding).toContain("no evidence");
    expect(typeOnlyImport.expectedGateRationales.diffNovelty).toContain("claimed new runtime behavior is absent");

    const explicitEventFailure = scorerCase("evaluationDevelopment-explicit-event-failure");
    expect(explicitEventFailure.expectedGates).toMatchObject({
      grounding: false,
      causality: false,
      diffNovelty: false,
      materiality: true,
      actionability: false,
    });

    const validatedExportPath = scorerCase("evaluationDevelopment-validated-export-path");
    expect(validatedExportPath.expectedGates.diffNovelty).toBe(false);
    expect(validatedExportPath.expectedGateRationales.diffNovelty).toContain("claimed unvalidated path is absent");

  });

  test("exhaustively defines fixture materiality as impact independent of other gates", () => {
    expect(BINARY_QUESTIONS.materiality).toContain("Assuming the claimed behavior occurs");
    const expectedMateriality = new Map<string, boolean>([
      ["development-tenant-query", true],
      ["development-harmless-capitalization", true],
      ["development-existing-html-injection", true],
      ["development-credential-output", true],
      ["development-uncited-admin-check", true],
      ["development-preexisting-null", true],
      ["development-novel-format-choice", true],
      ["development-unsupported-pagination", false],
      ["development-unrelated-session", true],
      ["development-unrelated-header", true],
      ["evaluationDevelopment-workflow-permissions", true],
      ["evaluationDevelopment-ledger-units", true],
      ["evaluationDevelopment-icon-button-name", true],
      ["evaluationDevelopment-reservation-interleaving", true],
      ["evaluationDevelopment-false-sync-success", true],
      ["evaluationDevelopment-unreachable-cleanup", true],
      ["evaluationDevelopment-type-only-import", true],
      ["evaluationDevelopment-example-timeout", true],
      ["evaluationDevelopment-explicit-event-failure", true],
      ["evaluationDevelopment-validated-export-path", true],
    ]);
    const allCases = [
      ...BINEVAL_DEVELOPMENT_BANK.cases,
      ...BINEVAL_EVALUATION_DEVELOPMENT_BANK.cases,
    ];
    expect([...expectedMateriality.keys()].sort()).toEqual(allCases.map(({ id }) => id).sort());
    for (const candidate of allCases) {
      expect(candidate.expectedGates.materiality).toBe(expectedMateriality.get(candidate.id)!);
      expect(candidate.expectedGateRationales.materiality).not.toMatch(
        /\b(?:hunk|shown|unchanged|absent|predates|introduced|added|removed|reachable|evidenced|execution path)\b/i,
      );
    }
  });
});

describe("request contracts", () => {
  test("rebuilds complete frozen requests for every method", () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const requests = (["scalar", "binaryBatch", "binaryIndependent"] as const)
      .flatMap((method) => buildEvaluationRequests(method, candidate, 1, provenance));
    expect(requests).toHaveLength(7);
    for (const request of requests) {
      for (const gate of BINARY_GATES) {
        expect(request.systemPrompt).toContain(`${gate}: ${BINARY_QUESTIONS[gate]}`);
      }
      expect(request.provenance).toMatchObject({
        runId: provenance.runId,
        model: provenance.model,
        provider: provenance.provider,
        sourceSha: provenance.sourceSha,
      });
      expect(evaluationRequestDigest(request)).toMatch(/^[0-9a-f]{64}$/);
      expect(Object.isFrozen(request)).toBe(true);
      expect(Object.isFrozen(request.provenance.settings)).toBe(true);
      expect(request.userPrompt).not.toContain("expectedGates");
      expect(request.userPrompt).not.toContain("expectedPublish");
    }
  });

  test("rejects modified cases, methods, repeats, and provenance", () => {
    const canonical = scorerCase("evaluationDevelopment-ledger-units");
    const modified = structuredClone(canonical);
    modified.finding.body = "Modified after case construction.";
    expect(() => buildEvaluationRequests("scalar", modified, 1, provenance)).toThrow("canonical scorer bank");
    expect(() => buildEvaluationRequests("forged" as EvaluationMethod, canonical, 1, provenance)).toThrow("supported evaluation methods");
    expect(() => buildEvaluationRequests("scalar", canonical, 0, provenance)).toThrow("repeat must be a positive integer");
    expect(() => buildEvaluationRequests("scalar", canonical, 1, { ...provenance, sourceSha: "0".repeat(64) })).toThrow("scorer source inputs");
  });

  test("requires the exact canonical bank containing the exact case", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    let calls = 0;
    const transport = accurateTransport();
    const countedTransport: EvaluationTransport = async (request, signal) => {
      calls += 1;
      return transport(request, signal);
    };
    await expect(evaluateScorerCase(
      "scalar",
      candidate,
      countedTransport,
      1,
      provenance,
      BINEVAL_DEVELOPMENT_BANK,
    )).rejects.toThrow("canonical scorer bank");

    const clonedBank = structuredClone(BINEVAL_EVALUATION_DEVELOPMENT_BANK);
    const clonedCase = clonedBank.cases.find((entry) => entry.id === candidate.id)!;
    expect(() => buildEvaluationRequests(
      "scalar",
      clonedCase,
      1,
      provenance,
    )).toThrow("canonical scorer bank");
    await expect(evaluateScorerCase(
      "scalar",
      clonedCase,
      countedTransport,
      1,
      provenance,
      clonedBank,
    )).rejects.toThrow("canonical scorer bank");
    expect(calls).toBe(0);
  });

  test("accepts only bounded scorer parameters in provenance", () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    expect(() => buildEvaluationRequests("scalar", candidate, 1, {
      ...provenance,
      settings: {
        temperature: 0.25,
        topP: 0.9,
        seed: 42,
        maxOutputTokens: 1_024,
        reasoningEffort: "low",
      },
    })).not.toThrow();
    expect(() => buildEvaluationRequests("scalar", candidate, 1, {
      ...provenance,
      settings: { apiKey: "must-not-be-retained" },
    } as unknown as ExperimentProvenance)).toThrow("bounded scorer experiment fields");
    expect(() => buildEvaluationRequests("scalar", candidate, 1, {
      ...provenance,
      model: "m".repeat(MAX_SCORER_PROVIDER_FIELD_BYTES + 1),
    })).toThrow("bounded scorer experiment fields");
  });

  test("rejects noncanonical experiment banks and excessive repeats before transport", async () => {
    const clonedBank = structuredClone(BINEVAL_EVALUATION_DEVELOPMENT_BANK);
    let calls = 0;
    const countedTransport: EvaluationTransport = async (request, signal) => {
      calls += 1;
      return accurateTransport()(request, signal);
    };
    await expect(runScorerExperiment(
      clonedBank,
      ["scalar"],
      countedTransport,
      { ...provenance, repeatCount: 1 },
    )).rejects.toThrow("exact canonical development bank");
    await expect(runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      ["scalar"],
      countedTransport,
      { ...provenance, repeatCount: MAX_SCORER_EXPERIMENT_REPEATS + 1 },
    )).rejects.toThrow(`1 through ${MAX_SCORER_EXPERIMENT_REPEATS}`);
    expect(calls).toBe(0);
  });
});

describe("raw evidence derivation", () => {
  test("runs all 20 canonical development cases through every method", async () => {
    const methods: EvaluationMethod[] = ["scalar", "binaryBatch", "binaryIndependent"];
    const oneRepeat = { ...provenance, repeatCount: 1 };
    const suite = await runCompleteDevelopmentScorerExperiment(
      methods,
      accurateTransport(),
      oneRepeat,
    );
    const caseIds = new Set(suite.reports.flatMap((report) =>
      report.repeats[0]!.cases.map((result) => result.caseId)
    ));
    expect(suite).toMatchObject({
      evidenceScope: "developmentOnly",
      validationEligible: false,
      totalCanonicalCases: 20,
    });
    expect(suite.reports).toHaveLength(2);
    expect(suite.bankDigests).toEqual(
      BINEVAL_CANONICAL_DEVELOPMENT_BANKS.map((bank) => scorerBankDigest(bank)),
    );
    expect(caseIds.size).toBe(20);
    expect(suite.reports.every((report) => report.validationEligible === false)).toBe(true);
  });

  test("snapshots the exact method plan before transport can mutate caller input", async () => {
    const methods: EvaluationMethod[] = ["scalar", "binaryBatch"];
    const expectedMethods = [...methods];
    const oneRepeat = { ...provenance, repeatCount: 1 };
    const accurate = accurateTransport();
    let mutated = false;
    const captures = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      async (request, signal) => {
        if (!mutated) {
          methods.reverse();
          mutated = true;
        }
        return accurate(request, signal);
      },
      oneRepeat,
    );
    expect(methods).toEqual(["binaryBatch", "scalar"]);
    expect([...new Set(captures.map((capture) => capture.method))]).toEqual(expectedMethods);
    expect(new Set(captures.map((capture) => capture.experimentPlanDigest)).size).toBe(1);
    expect(() => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      expectedMethods,
      captures,
      oneRepeat,
    )).not.toThrow();
    expect(() => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      captures,
      oneRepeat,
    )).toThrow("exact experiment plan");
  });

  test("derives frozen reports and standalone aggregates from frozen raw evidence", async () => {
    const methods: EvaluationMethod[] = ["scalar", "binaryBatch", "binaryIndependent"];
    const requests: EvaluationRequest[] = [];
    const captures = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(requests),
      provenance,
    );
    expect(captures).toHaveLength(60);
    expect(captures.every((capture) => !("evaluatedPublish" in capture))).toBe(true);
    expect(captures.every((capture) => (
      capture.evidenceScope === "developmentOnly"
      && capture.validationEligible === false
      && /^[0-9a-f]{64}$/.test(capture.experimentPlanDigest)
    ))).toBe(true);
    for (const capture of JSON.parse(JSON.stringify(captures))) {
      expect(capture).toMatchObject({
        evidenceScope: "developmentOnly",
        validationEligible: false,
      });
      expect(capture.experimentPlanDigest).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(requests).toHaveLength(140);
    for (const capture of captures) {
      for (const evidence of capture.callEvidence) {
        expect(Object.isFrozen(evidence)).toBe(true);
        expect(Object.isFrozen(evidence.request)).toBe(true);
        expect(Object.isFrozen(evidence.response)).toBe(true);
        expect(evidence.requestDigest).toBe(evaluationRequestDigest(evidence.request));
        expect(evidence.responseDigest).toMatch(/^[0-9a-f]{64}$/);
      }
    }
    const report = buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      captures,
      provenance,
    );
    expect(report).toMatchObject({
      evidenceScope: "developmentOnly",
      validationEligible: false,
      bankPhase: "evaluationDevelopment",
      evaluationContractVersion: BINEVAL_CONTRACT_VERSION,
      evaluationContractDigest: scorerEvaluationContractDigest(),
      provenance,
      classificationCounts: { mustBlock: 3, advisory: 2, clean: 5 },
    });
    expect(report.experimentPlanDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(captures.every((capture) => capture.experimentPlanDigest === report.experimentPlanDigest)).toBe(true);
    const serialized = JSON.parse(JSON.stringify(report));
    expect(serialized).toMatchObject({
      evidenceScope: "developmentOnly",
      validationEligible: false,
      evaluationContractDigest: scorerEvaluationContractDigest(),
    });
    for (const repeat of serialized.repeats) {
      expect(repeat).toMatchObject({
        evidenceScope: "developmentOnly",
        validationEligible: false,
        experimentPlanDigest: report.experimentPlanDigest,
      });
      for (const aggregate of repeat.methods) {
        expect(aggregate).toMatchObject({
          evidenceScope: "developmentOnly",
          validationEligible: false,
          experimentPlanDigest: report.experimentPlanDigest,
        });
      }
      for (const result of repeat.cases) {
        expect(result).toMatchObject({
          evidenceScope: "developmentOnly",
          validationEligible: false,
          experimentPlanDigest: report.experimentPlanDigest,
        });
      }
    }
    expect(report.repeats.map((repeat) => repeat.repeat)).toEqual([1, 2]);
    expect(report.repeats.every((repeat) => repeat.cases.length === 30)).toBe(true);
    expect(report.evidenceDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(Object.isFrozen(report)).toBe(true);

    const firstRepeat = report.repeats[0]!.cases;
    const scalar = aggregateScorerExperiment("scalar", firstRepeat);
    expect(scalar).toMatchObject({
      evidenceScope: "developmentOnly",
      validationEligible: false,
      bankPhase: "evaluationDevelopment",
      casesRun: 10,
      evaluatorPassedCases: 10,
      promptTokens: null,
      completionTokens: null,
      totalCostUsd: null,
      observedPromptTokens: 1_000,
      observedCompletionTokens: 100,
    });
    expect(scalar.meanElapsedMs).toBeNull();
    expect(Object.isFrozen(scalar)).toBe(true);
    expect(Object.isFrozen(scalar.publicationConfusion)).toBe(true);

    const binary = aggregateScorerExperiment("binaryBatch", firstRepeat);
    expect(Object.isFrozen(binary)).toBe(true);
    expect(Object.isFrozen(binary.publicationConfusion)).toBe(true);
    expect(Object.isFrozen(binary.gateConfusion)).toBe(true);
    for (const gate of BINARY_GATES) {
      expect(Object.isFrozen(binary.gateConfusion![gate])).toBe(true);
    }
    expect(Reflect.set(binary, "casesRun", 0)).toBe(false);
    expect(Reflect.set(binary.publicationConfusion, "truePositive", 999)).toBe(false);
    expect(Reflect.set(binary.gateConfusion!.grounding, "truePositive", 999)).toBe(false);
  });

  test("rejects aggregate splices, mixed provenance, repeats, duplicates, and missing cases", async () => {
    const methods: EvaluationMethod[] = ["scalar"];
    const oneRepeat = { ...provenance, repeatCount: 1 };
    const run = async (runProvenance: ExperimentProvenance) => {
      const captures = await runScorerExperiment(
        BINEVAL_EVALUATION_DEVELOPMENT_BANK,
        methods,
        accurateTransport(),
        runProvenance,
      );
      return buildScorerExperimentReport(
        BINEVAL_EVALUATION_DEVELOPMENT_BANK,
        methods,
        captures,
        runProvenance,
      ).repeats[0]!.cases;
    };
    const primary = await run(oneRepeat);
    expect(aggregateScorerExperiment("scalar", primary).casesRun).toBe(10);

    const forgedPlanDigest = "f".repeat(64);
    const forgedPlan = primary.map((result) => ({
      ...result,
      experimentPlanDigest: forgedPlanDigest,
    }));
    expect(() => aggregateScorerExperiment("scalar", forgedPlan)).toThrow("execution-owned plan");

    const separateExecution = await run(oneRepeat);
    expect(() => aggregateScorerExperiment("scalar", [
      separateExecution[0]!,
      ...primary.slice(1),
    ])).toThrow("execution ownership");

    for (const changed of [
      { ...oneRepeat, model: "fixture/other-model" },
      { ...oneRepeat, provider: "other-provider" },
      { ...oneRepeat, settings: { temperature: 0.5, seed: 7 } },
    ]) {
      const foreignProvenance = await run(changed);
      expect(() => aggregateScorerExperiment("scalar", [
        foreignProvenance[0]!,
        ...primary.slice(1),
      ])).toThrow("mix provenance");
    }

    const forgedSource = {
      ...primary[0]!,
      provenance: {
        ...primary[0]!.provenance,
        sourceSha: "0".repeat(64),
      },
    };
    expect(() => aggregateScorerExperiment("scalar", [
      forgedSource,
      ...primary.slice(1),
    ])).toThrow("sourceSha");

    const twoRepeats = { ...provenance, repeatCount: 2 };
    const repeatedCaptures = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(),
      twoRepeats,
    );
    const repeatedReport = buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      repeatedCaptures,
      twoRepeats,
    );
    expect(() => aggregateScorerExperiment("scalar", [
      repeatedReport.repeats[1]!.cases[0]!,
      ...repeatedReport.repeats[0]!.cases.slice(1),
    ])).toThrow("mix repeats");

    expect(() => aggregateScorerExperiment("scalar", [
      primary[0]!,
      primary[0]!,
      ...primary.slice(2),
    ])).toThrow("duplicate case");
    expect(() => aggregateScorerExperiment("scalar", primary.slice(0, -1))).toThrow(
      "complete canonical case set",
    );
  });

  test("requires atomic binary gates to match even when publication matches", async () => {
    const candidate = scorerCase("evaluationDevelopment-type-only-import");
    const binary = await evaluateScorerCase(
      "binaryBatch",
      candidate,
      async () => response({
        verdicts: BINARY_GATES.map((gate) => ({
          gate,
          pass: gate !== "grounding",
          reason: "The supplied gate judgment is deliberate.",
        })),
      }),
      1,
      provenance,
    );
    expect(binary).toMatchObject({
      expectedPublish: false,
      evaluatedPublish: false,
      evaluatorPassed: false,
    });
    expect(binary.gates).not.toEqual(binary.expectedGates);

    const scalar = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => response([{
        index: 0,
        confidence: 0.1,
        kind: "uncertainty",
        reason: "The publication decision is negative.",
      }]),
      1,
      provenance,
    );
    expect(scalar).toMatchObject({
      expectedPublish: false,
      evaluatedPublish: false,
      evaluatorPassed: true,
    });
  });

  test("rejects swapped case, repeat, method-gate, and provenance evidence", async () => {
    const methods: EvaluationMethod[] = ["scalar", "binaryBatch", "binaryIndependent"];
    const captures = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(),
      provenance,
    );
    const build = (candidate: ScorerExperimentCaseCapture[]) => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      candidate,
      provenance,
    );

    const scalarIndexes = captures
      .map((capture, index) => ({ capture, index }))
      .filter(({ capture }) => capture.method === "scalar" && capture.repeat === 1);
    const first = scalarIndexes[0]!;
    const second = scalarIndexes[1]!;
    const swappedCase = {
      ...first.capture,
      callEvidence: second.capture.callEvidence,
      callEvidenceDigest: second.capture.callEvidenceDigest,
    } as ScorerExperimentCaseCapture;
    expect(() => build(replaceCapture(captures, first.index, freezeCapture(swappedCase)))).toThrow("execution");

    const sameCaseRepeatTwo = captures.find((capture) =>
      capture.caseId === first.capture.caseId && capture.method === "scalar" && capture.repeat === 2
    )!;
    const swappedRepeat = {
      ...first.capture,
      callEvidence: sameCaseRepeatTwo.callEvidence,
      callEvidenceDigest: sameCaseRepeatTwo.callEvidenceDigest,
    } as ScorerExperimentCaseCapture;
    expect(() => build(replaceCapture(captures, first.index, freezeCapture(swappedRepeat)))).toThrow("execution");

    const independent = captures.find((capture) => capture.method === "binaryIndependent")!;
    const reversedCalls = [...independent.callEvidence].reverse();
    const swappedGates = {
      ...independent,
      callEvidence: reversedCalls,
      callEvidenceDigest: evidenceDigest(reversedCalls),
    } as ScorerExperimentCaseCapture;
    const independentIndex = captures.indexOf(independent);
    expect(() => build(replaceCapture(captures, independentIndex, freezeCapture(swappedGates)))).toThrow("execution");

    const clonedProvenance = structuredClone(first.capture.callEvidence[0]!);
    clonedProvenance.request.provenance.runId = "other-run";
    const foreignProvenance = freezeCapture({
      ...first.capture,
      callEvidence: [clonedProvenance],
      callEvidenceDigest: evidenceDigest([clonedProvenance]),
    });
    expect(() => build(replaceCapture(captures, first.index, foreignProvenance))).toThrow("execution");
  });

  test("rejects valid captures spliced across separate executions", async () => {
    const methods: EvaluationMethod[] = ["scalar"];
    const oneRepeat = { ...provenance, repeatCount: 1 };
    const firstRun = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(),
      oneRepeat,
    );
    const secondRun = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(),
      oneRepeat,
    );
    expect(() => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      [secondRun[0]!, ...firstRun.slice(1)],
      oneRepeat,
    )).toThrow("separate executions");

    expect(() => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      [...firstRun].reverse(),
      oneRepeat,
    )).toThrow("execution order");
  });

  test("snapshots fulfilled responses and rejected errors when each call settles", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    let returnedResponse: EvaluationResponse | null = null;
    const returnedError = new EvaluationTransportError("original provider failure", {
      promptTokens: 7,
      completionTokens: null,
      costUsd: 0.0001,
    });
    const result = await evaluateScorerCase(
      "binaryIndependent",
      candidate,
      async (request) => {
        if (request.gate === "grounding") {
          returnedResponse = response({
            gate: request.gate,
            pass: true,
            reason: "Original response.",
          });
          setTimeout(() => {
            returnedResponse!.content = JSON.stringify({
              gate: "actionability",
              pass: false,
              reason: "Mutated response.",
            });
          }, 0);
          return returnedResponse;
        }
        if (request.gate === "causality") {
          setTimeout(() => {
            returnedError.message = "mutated provider failure";
            returnedError.telemetry.promptTokens = 999;
          }, 0);
          throw returnedError;
        }
        if (request.gate === "actionability") await Bun.sleep(20);
        return response({ gate: request.gate, pass: true, reason: "Supported." });
      },
      1,
      provenance,
    );
    expect(returnedResponse!.content).toContain("Mutated response");
    expect(returnedError.message).toBe("mutated provider failure");
    const grounding = result.callEvidence.find((entry) => entry.request.gate === "grounding")!;
    expect(grounding.response?.content).toContain("Original response");
    expect(grounding.response?.content).not.toContain("Mutated response");
    const causality = result.callEvidence.find((entry) => entry.request.gate === "causality")!;
    expect(causality.transportError).toMatchObject({
      message: "original provider failure",
      reportedTelemetry: { promptTokens: 7 },
    });
  });

  test("rejects response, digest, and elapsed tampering without accepting caller decisions", async () => {
    const methods: EvaluationMethod[] = ["scalar"];
    const oneRepeat = { ...provenance, repeatCount: 1 };
    const captures = await runScorerExperiment(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      accurateTransport(),
      oneRepeat,
    );
    const build = (candidate: ScorerExperimentCaseCapture[]) => buildScorerExperimentReport(
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      methods,
      candidate,
      oneRepeat,
    );
    const original = captures[0]!;
    expect("evaluatedPublish" in original).toBe(false);

    const clonedResponse = structuredClone(original.callEvidence[0]!);
    clonedResponse.response!.content = "[]";
    const responseTamper = {
      ...original,
      callEvidence: [clonedResponse],
      callEvidenceDigest: evidenceDigest([clonedResponse]),
    } as ScorerExperimentCaseCapture;
    expect(() => build(replaceCapture(captures, 0, freezeCapture(responseTamper)))).toThrow("execution");

    const clonedDigest = structuredClone(original.callEvidence[0]!);
    clonedDigest.requestDigest = "f".repeat(64);
    const digestTamper = {
      ...original,
      callEvidence: [clonedDigest],
      callEvidenceDigest: evidenceDigest([clonedDigest]),
    } as ScorerExperimentCaseCapture;
    expect(() => build(replaceCapture(captures, 0, freezeCapture(digestTamper)))).toThrow("execution");

    const clonedElapsed = structuredClone(original.callEvidence[0]!);
    clonedElapsed.measuredElapsedMs += 1;
    const elapsedTamper = {
      ...original,
      callEvidence: [clonedElapsed],
      callEvidenceDigest: evidenceDigest([clonedElapsed]),
    } as ScorerExperimentCaseCapture;
    expect(() => build(replaceCapture(captures, 0, freezeCapture(elapsedTamper)))).toThrow("execution");
  });

  test("keeps provider receipts and provider telemetry untrusted", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const result = await evaluateScorerCase("scalar", candidate, accurateTransport(), 1, provenance);
    expect(result).toMatchObject({
      promptTokens: null,
      completionTokens: null,
      costUsd: null,
      telemetryComplete: false,
      observedPromptTokens: 100,
      observedCompletionTokens: 10,
      observedCostUsd: 0.001,
    });
    expect(result.callEvidence[0]).toMatchObject({
      providerReceiptTrusted: false,
      providerReceiptBinding: "bound",
    });
  });

  test("keeps inconsistent receipts untrusted without changing evaluator correctness", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const mutations: Array<[string, (receipt: NonNullable<EvaluationResponse["providerReceipt"]>, responseValue: EvaluationResponse) => void]> = [
      ["request digest", (receipt) => { receipt.requestDigest = "0".repeat(64); }],
      ["provider", (receipt) => { receipt.provider = "foreign-provider"; }],
      ["model", (receipt) => { receipt.model = "foreign/model"; }],
      ["generation", (receipt) => { receipt.generationId = "foreign-generation"; }],
      ["response generation", (_receipt, responseValue) => { responseValue.providerGenerationId = "foreign-generation"; }],
    ];
    for (const [name, mutate] of mutations) {
      const result = await evaluateScorerCase(
        "scalar",
        candidate,
        async (request) => {
          const value = receiptResponse(request, [{
            index: 0,
            confidence: 0.9,
            kind: "risk",
            reason: "Supported.",
          }]);
          mutate(value.providerReceipt!, value);
          return value;
        },
        1,
        provenance,
      );
      expect(result.evaluationStatus, name).toBe("complete");
      expect(result.evaluatedPublish, name).toBe(true);
      expect(result.preserveCandidate, name).toBe(false);
      expect(result.evaluatorPassed, name).toBe(true);
      expect(result.callEvidence[0]?.providerReceiptBinding, name).toBe("inconsistent");
      expect(result.callEvidence[0]?.providerReceiptTrusted, name).toBe(false);
    }
  });

  test("strips malformed provider receipts before storing evidence", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const marker = "provider-only-field-must-not-be-stored";
    const result = await evaluateScorerCase(
      "scalar",
      candidate,
      async (request) => {
        const value = receiptResponse(request, [{
          index: 0,
          confidence: 0.9,
          kind: "risk",
          reason: "Supported.",
        }]);
        value.providerReceipt = {
          ...value.providerReceipt!,
          providerOnlyField: marker,
        } as unknown as NonNullable<EvaluationResponse["providerReceipt"]>;
        return value;
      },
      1,
      provenance,
    );
    expect(result).toMatchObject({
      evaluationStatus: "complete",
      evaluatedPublish: true,
      evaluatorPassed: true,
    });
    expect(result.callEvidence[0]).toMatchObject({
      providerReceiptBinding: "invalid",
      providerReceipt: null,
      providerReceiptId: null,
      providerReceiptDigest: null,
    });
    expect(JSON.stringify(result)).not.toContain(marker);
  });

  test("rejects response extras without retaining provider data", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const cases: Array<[string, unknown]> = [
      ["plain object", { marker: "plain-provider-extra" }],
      ["map", new Map([["marker", "map-provider-extra"]])],
      ["bigint", 123n],
    ];
    for (const [name, providerExtra] of cases) {
      const result = await evaluateScorerCase(
        "scalar",
        candidate,
        async () => ({
          ...response([{
            index: 0,
            confidence: 0.9,
            kind: "risk",
            reason: "Supported.",
          }]),
          providerExtra,
        }) as unknown as EvaluationResponse,
        1,
        provenance,
      );
      expect(result.evaluationStatus, name).toBe("transportFailure");
      expect(result.evaluatedPublish, name).toBeNull();
      expect(result.callEvidence[0]?.response, name).toBeNull();
      expect(result.callEvidence[0]?.transportError?.message, name).toBe(
        "transport returned an invalid response envelope",
      );
      expect(JSON.stringify(result), name).not.toContain("provider-extra");
    }
  });

  test("bounds transport duration, response bytes, and captured errors", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    let aborted = false;
    const timedOut = await evaluateScorerCase(
      "scalar",
      candidate,
      async (_request, signal) => new Promise((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("transport observed abort"));
        }, { once: true });
      }),
      1,
      provenance,
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      { transportTimeoutMs: 5 },
    );
    expect(aborted).toBe(true);
    expect(timedOut).toMatchObject({
      evaluationStatus: "transportFailure",
      evaluatedPublish: null,
      preserveCandidate: true,
    });
    expect(timedOut.callEvidence[0]?.transportError?.message).toContain("5 ms deadline");

    const waitStarted = performance.now();
    let ignoredSignalObserved = false;
    const ignoredAbort = await evaluateScorerCase(
      "scalar",
      candidate,
      async (_request, signal) => {
        ignoredSignalObserved = signal instanceof AbortSignal;
        return new Promise(() => {});
      },
      1,
      provenance,
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      { transportTimeoutMs: 5 },
    );
    expect(ignoredSignalObserved).toBe(true);
    expect(performance.now() - waitStarted).toBeLessThan(500);
    expect(ignoredAbort.evaluationStatus).toBe("transportFailure");

    const oversized = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => response("x".repeat(MAX_SCORER_RESPONSE_BYTES + 1)),
      1,
      provenance,
    );
    expect(oversized.callEvidence[0]).toMatchObject({
      outcome: "rejected",
      response: null,
      transportError: {
        message: "transport returned an invalid response envelope",
      },
    });

    const oversizedError = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => {
        throw new Error("e".repeat(MAX_SCORER_RESPONSE_BYTES));
      },
      1,
      provenance,
    );
    expect(oversizedError.callEvidence[0]?.transportError?.message).toBe(
      "transport rejected with an unreadable or non-Error value",
    );

    let calls = 0;
    await expect(evaluateScorerCase(
      "scalar",
      candidate,
      async () => {
        calls += 1;
        return response("not reached");
      },
      1,
      provenance,
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      { transportTimeoutMs: MAX_SCORER_CALL_TIMEOUT_MS + 1 },
    )).rejects.toThrow(`1 through ${MAX_SCORER_CALL_TIMEOUT_MS}`);
    expect(calls).toBe(0);
  });

  test("rejects or nulls provider telemetry outside safe bounds", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const oversizedResponseTelemetry = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => response([{
        index: 0,
        confidence: 0.9,
        kind: "risk",
        reason: "Supported.",
      }], {
        promptTokens: MAX_SCORER_TOKENS_PER_CALL + 1,
      }),
      1,
      provenance,
    );
    expect(oversizedResponseTelemetry.callEvidence[0]).toMatchObject({
      outcome: "rejected",
      response: null,
    });

    const oversizedErrorTelemetry = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => {
        throw new EvaluationTransportError("provider unavailable", {
          elapsedMs: MAX_SCORER_CALL_TIMEOUT_MS + 1,
          promptTokens: Number.MAX_SAFE_INTEGER,
          completionTokens: MAX_SCORER_TOKENS_PER_CALL + 1,
          costUsd: MAX_SCORER_COST_USD_PER_CALL + 1,
        });
      },
      1,
      provenance,
    );
    expect(oversizedErrorTelemetry).toMatchObject({
      observedElapsedMs: null,
      observedPromptTokens: null,
      observedCompletionTokens: null,
      observedCostUsd: null,
    });
  });

  test("excludes mutable same-process timing after later clock replacement", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const originalDescriptor = Object.getOwnPropertyDescriptor(performance, "now");
    Object.defineProperty(performance, "now", {
      configurable: true,
      value: () => 500_000,
    });
    try {
      const result = await evaluateScorerCase("scalar", candidate, accurateTransport(), 1, provenance);
      expect(result.callEvidence[0]?.latencySource).toBe("processMonotonicUntrusted");
      expect(result.elapsedMs).toBeNull();
    } finally {
      if (originalDescriptor === undefined) delete (performance as { now?: () => number }).now;
      else Object.defineProperty(performance, "now", originalDescriptor);
    }
  });

  test("excludes a process clock replaced before the module is imported", async () => {
    const moduleUrl = new URL("./bineval-scorer.ts", import.meta.url).href;
    const script = `
      Object.defineProperty(performance, "now", {
        configurable: true,
        value: (() => { let value = 0; return () => value += 500000; })(),
      });
      const module = await import(${JSON.stringify(`${moduleUrl}?preimport-clock-attack`)});
      const provenance = {
        runId: "fresh-process-clock-attack",
        model: "fixture/model",
        provider: "fixture-provider",
        settings: {},
        sourceSha: module.scorerSourceDigest(),
        repeatCount: 1,
      };
      const candidate = module.BINEVAL_EVALUATION_DEVELOPMENT_BANK.cases[0];
      const result = await module.evaluateScorerCase(
        "scalar",
        candidate,
        async () => ({
          content: JSON.stringify([{ index: 0, confidence: 0.9, kind: "risk", reason: "Supported." }]),
          elapsedMs: 1,
          promptTokens: 1,
          completionTokens: 1,
          costUsd: 0.001,
          providerGenerationId: null,
          providerReceipt: null,
        }),
        1,
        provenance,
      );
      console.log(JSON.stringify({
        elapsedMs: result.elapsedMs,
        latencySource: result.callEvidence[0].latencySource,
        measuredElapsedMs: result.callEvidence[0].measuredElapsedMs,
      }));
    `;
    const child = Bun.spawn([process.execPath, "-e", script], {
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exitCode] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(exitCode, stderr).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      elapsedMs: null,
      latencySource: "processMonotonicUntrusted",
      measuredElapsedMs: MAX_SCORER_CALL_TIMEOUT_MS,
    });
  });

  test("labels an injected test clock untrusted and excludes it from reportable latency", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    let time = 0;
    const result = await evaluateScorerCase(
      "scalar",
      candidate,
      accurateTransport(),
      1,
      provenance,
      BINEVAL_EVALUATION_DEVELOPMENT_BANK,
      { testOnlyNow: () => (time += 500_000) },
    );
    expect(result.elapsedMs).toBeNull();
    expect(result.callEvidence[0]).toMatchObject({
      latencySource: "testInjectedUntrusted",
      measuredElapsedMs: MAX_SCORER_CALL_TIMEOUT_MS,
    });
  });

  test("derives malformed and transport failure state from raw outcomes", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const malformed = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => response("not json"),
      1,
      provenance,
    );
    expect(malformed).toMatchObject({
      evaluationStatus: "malformed",
      evaluatedPublish: null,
      operationalPublish: true,
      preserveCandidate: true,
      evaluatorPassed: false,
    });

    const failed = await evaluateScorerCase(
      "binaryIndependent",
      candidate,
      async (request) => {
        if (request.gate === "actionability") {
          throw new EvaluationTransportError("provider unavailable", {
            elapsedMs: 44,
            promptTokens: 20,
            completionTokens: null,
            costUsd: 0.0002,
          });
        }
        return response({ gate: request.gate, pass: true, reason: "Supported." });
      },
      1,
      provenance,
    );
    expect(failed).toMatchObject({
      evaluationStatus: "transportFailure",
      evaluatedPublish: null,
      preserveCandidate: true,
      promptTokens: null,
      completionTokens: null,
      costUsd: null,
      observedPromptTokens: 420,
      observedCompletionTokens: 40,
    });
    const rejected = failed.callEvidence.find((entry) => entry.outcome === "rejected")!;
    expect(rejected.transportError).toMatchObject({
      name: "EvaluationTransportError",
      message: "provider unavailable",
    });
  });

  test("fails closed when rejected error fields or telemetry have hostile accessors", async () => {
    const candidate = scorerCase("evaluationDevelopment-ledger-units");
    const hostileMessage = new Error("replace me");
    delete (hostileMessage as { message?: string }).message;
    Object.defineProperty(hostileMessage, "message", {
      get() {
        throw new Error("message getter escaped");
      },
    });
    const malformedError = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => {
        throw hostileMessage;
      },
      1,
      provenance,
    );
    expect(malformedError).toMatchObject({
      evaluationStatus: "transportFailure",
      evaluatedPublish: null,
      preserveCandidate: true,
    });
    expect(malformedError.callEvidence[0]?.transportError).toMatchObject({
      name: "Error",
      message: "transport rejected with an unreadable or non-Error value",
    });

    const hostileTelemetry = new Proxy({}, {
      get() {
        throw new Error("telemetry getter escaped");
      },
    });
    const malformedTelemetry = await evaluateScorerCase(
      "scalar",
      candidate,
      async () => {
        throw new EvaluationTransportError(
          "provider failed",
          hostileTelemetry as Partial<CallTelemetry>,
        );
      },
      1,
      provenance,
    );
    expect(malformedTelemetry).toMatchObject({
      evaluationStatus: "transportFailure",
      evaluatedPublish: null,
      preserveCandidate: true,
      observedPromptTokens: null,
      observedCompletionTokens: null,
      observedCostUsd: null,
    });
  });
});
