import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cases as fixtureInputs } from "../fixtures/cases";
import {
  benchmarkCase,
  displayPlannerPath,
  envelopeV1,
  parseUnifiedDiffFiles,
} from "./harness";
import {
  canonicalProviderCost,
  FALSE_FINDING_CASES,
  GENERATOR_MODEL,
  SCORER_CASE_EXEC_TIMEOUT_MS,
  SCORER_CASE_HARNESS_ALLOWANCE_MS,
  SCORER_MAX_CASE_MS,
  SCORER_REASON_SCHEMA_PATTERN,
  TRUE_FINDING_CASES,
  aggregate,
  assertCleanScorerEvaluatorStatus,
  assertScorerEvaluatorFileMatches,
  assertQualificationPreflight,
  falseFinding,
  falseFindingFromSourceRequest,
  firstAddedLineForPath,
  finalizeScorerEvalReport,
  formatReport,
  generatorRequestMismatchCodes,
  isAdmissionFatalStructuralResult,
  isValidReason,
  isolatedEnv,
  loadEmbeddedScorerDefaults,
  parseModels,
  parseRepeatCount,
  percentile,
  plannerBatchIdForPath,
  qualificationExitCode,
  projectedQualificationSpendUsd,
  runBoundedChild,
  runScorerEvalCase,
  runScorerEvalMatrix,
  reviewCoverageFailure,
  safeSegment,
  scorerCasePasses,
  scorerCostProviderDecimal,
  scorerEvalRootDir,
  scorerEvaluatorDigest,
  providerCostDecimalFromResponse,
  scorerCheckpointPath,
  strictRequestMismatchCodes,
  scorerProxyRequestPhase,
  selectEvalCases,
  startScorerProxy,
  scorerStructuralFailureReason,
  scorerQualificationModels,
  scorerQualificationRequiredParameters,
  trueFinding,
  writeScorerEvalCheckpoint,
  writeScorerEvalSetupFailureArtifact,
  type ScorerEvalCase,
  type ScorerEvalReport,
  type ScorerProxyExpectedContract,
} from "./scorer-eval";

const fixtures = fixtureInputs.map((input) => benchmarkCase.parse(input));
const BOUNDED_SCORER_TARGET_PATH = 'src/ui/copy"quoted.ts';
const TEST_SCORER_MODEL = "z-ai/glm-5.2";

function scorerReportContract(): Pick<
  ScorerEvalReport,
  "evaluatorSha256" | "providerContractSha256" | "providerContract"
> {
  return {
    evaluatorSha256: "c".repeat(64),
    providerContractSha256: "d".repeat(64),
    providerContract: {
      version: 1,
      benchmarkProviderIdentity: "openrouter:managed-routing",
      upstreamProviderIdentity: "test-provider",
      upstreamProviderRoute: "test-provider/route",
      dataCollection: "deny",
      zeroDataRetention: true,
      allowFallbacks: false,
      generatorRequireParameters: false,
      scorerRequireParameters: true,
      maxPricePinned: true,
      maxPriceUnits: "USD per million tokens",
      modelPriceBounds: [],
    },
  };
}

function postilBinaryPath(): string {
  const cargoTarget = process.env.CARGO_TARGET_DIR;
  return resolve(
    process.env.POSTIL_BIN ??
      (cargoTarget === undefined
        ? resolve(import.meta.dir, "..", "..", "target", "release", "postil")
        : resolve(cargoTarget, "release", "postil")),
  );
}

function fixture(id: string) {
  const c = fixtures.find((candidate) => candidate.id === id);
  if (!c) throw new Error(`missing fixture ${id}`);
  return c;
}

function boundedScorerFixture() {
  const ordinaryFile = (ordinal: number) => {
    const path = `src/ordinary/segment-${ordinal}.ts`;
    const lines = Array.from(
      { length: 100 },
      (_, line) => ordinal === 0 && line === 0
        ? "+export const displayHeadingLabel = 'Account overview'; // ordinary display copy"
        : `+export const ordinary_${ordinal}_${line} = ${ordinal + line}; // ordinary source behavior`,
    );
    return [
      `diff --git a/${path} b/${path}`,
      "--- /dev/null",
      `+++ b/${path}`,
      `@@ -0,0 +1,${lines.length} @@`,
      ...lines,
      "",
    ].join("\n");
  };
  const displayedTargetPath = 'src/ui/copy\\"quoted.ts';
  const target = [
    `diff --git "a/${displayedTargetPath}" "b/${displayedTargetPath}"`,
    `--- "a/${displayedTargetPath}"`,
    `+++ "b/${displayedTargetPath}"`,
    "@@ -42,3 +42,4 @@",
    " export const heading = 'Account';",
    " export const description = 'Manage your account';",
    "+export const saveHint = 'Changes save automatically';",
    " export const action = 'Save';",
    "",
  ].join("\n");
  const diff = [
    ...Array.from({ length: 15 }, (_, index) => ordinaryFile(index)),
    target,
    ...Array.from({ length: 15 }, (_, index) => ordinaryFile(index + 15)),
  ].join("");
  const base = fixture("huge-low-signal-clean");
  return benchmarkCase.parse({
    ...base,
    id: "bounded-scorer-clean",
    name: "Bounded scorer clean calibration",
    pullNumber: 9_901,
    headSha: "a".repeat(40),
    diff,
    primaryChange: { path: BOUNDED_SCORER_TARGET_PATH, line: 44 },
    allowedContext: { files: [], docs: base.allowedContext.docs },
  });
}

function result(overrides: Partial<ScorerEvalCase>): ScorerEvalCase {
  return {
    repeat: 1,
    id: "case",
    name: "Case",
    scenario: "trueFinding",
    model: "scorer/model",
    timedOut: false,
    envelopeProduced: true,
    scorerModel: "scorer/model",
    scorerError: null,
    scorerConfidence: 0.9,
    scorerKind: "risk",
    finalConfidence: 0.9,
    finalKind: "risk",
    findingPublished: true,
    gateFailing: true,
    passed: true,
    reason: "ok",
    reasonContractValid: true,
    usageAccountingComplete: true,
    usageValid: true,
    routingValid: true,
    coverageValid: true,
    publicationValid: true,
    upstreamRequests: 2,
    durationMs: 1000,
    promptTokens: 10,
    completionTokens: 5,
    costUsd: 0.0001,
    costProviderDecimal: "0.0001",
    ...overrides,
  };
}

function qualificationCases(repeats: number): ScorerEvalCase[] {
  const cases: ScorerEvalCase[] = [];
  for (let repeat = 1; repeat <= repeats; repeat += 1) {
    for (const id of TRUE_FINDING_CASES) {
      cases.push(result({ id, repeat, scenario: "trueFinding", scorerConfidence: 0.9, scorerKind: "risk" }));
    }
    for (const id of FALSE_FINDING_CASES) {
      cases.push(
        result({
          id,
          repeat,
          scenario: "falseFinding",
          scorerConfidence: 0.2,
          scorerKind: "uncertainty",
          finalConfidence: 0.2,
          finalKind: "uncertainty",
          findingPublished: false,
          gateFailing: false,
        }),
      );
    }
  }
  return cases;
}

function listen(server: ReturnType<typeof createServer>): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address() as AddressInfo;
      resolvePromise(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server: ReturnType<typeof createServer>): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    server.close((err) => (err ? reject(err) : resolvePromise()));
  });
}

function requestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const TEST_PROXY_PRICING = {
  providerIdentity: "Azure",
  promptUsdPerToken: 0.00000022,
  completionUsdPerToken: 0.00000132,
  inputMicrosPerMillionTokens: 220_000,
  outputMicrosPerMillionTokens: 1_320_000,
};

function proxyContract(
  model = "scorer/model",
  providerIdentity = "Azure",
  providerRoute = "azure/eu",
): ScorerProxyExpectedContract {
  return { model, providerIdentity, providerRoute, pricing: TEST_PROXY_PRICING };
}

function strictProvider() {
  return {
    data_collection: "deny",
    zdr: true,
    order: ["azure/eu"],
    allow_fallbacks: false,
    require_parameters: true,
    max_price: { prompt: 0.22, completion: 1.32 },
  };
}

function generatorRequest() {
  const { require_parameters: _requireParameters, ...provider } = strictProvider();
  return {
    model: GENERATOR_MODEL,
    max_tokens: 4_000,
    temperature: 0.1,
    reasoning: { effort: "low" },
    provider,
    messages: [
      { role: "system", content: "You are Postil's low-noise code reviewer." },
      { role: "user", content: "Review this change." },
    ],
  };
}

function scorerRequest(model = "scorer/model") {
  return {
    model,
    max_completion_tokens: 400,
    reasoning: { effort: "low", exclude: true },
    provider: strictProvider(),
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "postil_finding_scores",
        strict: true,
        schema: {
          type: "object",
          properties: {
            scores: {
              type: "array",
              minItems: 1,
              maxItems: 1,
              items: {
                type: "object",
                properties: {
                  confidence: { type: "number", minimum: 0, maximum: 1 },
                  kind: {
                    type: "string",
                    enum: ["risk", "humanEscalation", "guardrail", "uncertainty", "contentPolicy"],
                  },
                  reason: {
                    type: "string",
                    minLength: 1,
                    maxLength: 240,
                    pattern: "^(?:[.!?。！？]|[^\\s\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029](?:[^\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029]*[.!?。！？]))$",
                  },
                },
                required: ["confidence", "kind", "reason"],
                additionalProperties: false,
              },
            },
          },
          required: ["scores"],
          additionalProperties: false,
        },
      },
    },
    messages: [
      { role: "system", content: "You are Postil's independent second-model scorer." },
      { role: "user", content: "Score this finding." },
    ],
  };
}

function adjudicationRequest(model = "scorer/model") {
  return {
    model,
    max_completion_tokens: 8_000,
    reasoning: { effort: "low", exclude: true },
    provider: strictProvider(),
    messages: [
      { role: "system", content: "You are Postil's single finding adjudicator." },
      { role: "user", content: "Adjudicate this finding." },
    ],
  };
}

function genericOpenAiCompatibleRequest(
  phase: "adjudication" | "scorer",
  model = "scorer/model",
) {
  return {
    model,
    max_tokens: 8_000,
    temperature: 0,
    reasoning: { effort: "low" },
    messages: [{
      role: "system",
      content: phase === "adjudication"
        ? "You are Postil's single finding adjudicator."
        : "You are Postil's independent second-model scorer.",
    }],
  };
}

function adjudicationResponse(body: string): string | null {
  let request: {
    messages?: Array<{ role?: string; content?: string }>;
  };
  try {
    request = JSON.parse(body) as typeof request;
  } catch {
    return null;
  }
  const isAdjudication = request.messages?.some((message) =>
    message.content?.includes("Postil's single finding adjudicator")
  ) ?? false;
  if (!isAdjudication) return null;
  const user = request.messages?.findLast((message) => message.role === "user")?.content ?? "{}";
  const payload = JSON.parse(user) as {
    candidates?: Array<{
      candidateId?: string;
      title?: string;
      body?: string;
      citedEvidence?: string | null;
    }>;
  };
  return JSON.stringify((payload.candidates ?? []).map((candidate) => {
    const body = candidate.body ?? "";
    return {
      candidateId: candidate.candidateId ?? "",
      status: "confirmed",
      revisedTitle: candidate.title ?? "",
      revisedBody: /[.!?。！？]$/u.test(body) ? body : `${body}.`,
      evidence: candidate.citedEvidence ?? "",
      duplicateOf: null,
    };
  }));
}

describe("parseModels", () => {
  test("uses caller-provided embedded candidates when no override is set", () => {
    const defaults = ["a/default", "b/default"];
    expect(parseModels(undefined, defaults)).toEqual(defaults);
    expect(parseModels("   ", defaults)).toEqual(defaults);
  });

  test("trims comma-separated model ids and drops blanks", () => {
    expect(parseModels(" a/model, ,b/model,a/model ", [])).toEqual(["a/model", "b/model"]);
  });

  test("uses the embedded Luna scorer qualification candidate", async () => {
    const defaults = await loadEmbeddedScorerDefaults();
    expect(defaults.enabled).toBe(true);
    expect(defaults.qualification_candidates).toEqual(["openai/gpt-5.6-luna"]);
    expect(parseModels(undefined, defaults.qualification_candidates)).toEqual(["openai/gpt-5.6-luna"]);
  });
});

describe("parseRepeatCount", () => {
  test("defaults qualification to five repeats and validates overrides", () => {
    expect(parseRepeatCount(undefined)).toBe(5);
    expect(parseRepeatCount("3")).toBe(3);
    expect(() => parseRepeatCount("0")).toThrow("1..10");
    expect(() => parseRepeatCount("11")).toThrow("1..10");
  });
});

describe("scorer run artifacts", () => {
  test("binds qualification to clean evaluator source bytes", () => {
    expect(() => assertCleanScorerEvaluatorStatus("")).not.toThrow();
    expect(() => assertCleanScorerEvaluatorStatus(" M bench/src/scorer-eval.ts\n")).toThrow(
      "sources differ from HEAD",
    );
    expect(() => assertScorerEvaluatorFileMatches(Buffer.from("same"), Buffer.from("same")))
      .not.toThrow();
    expect(() => assertScorerEvaluatorFileMatches(Buffer.from("dirty"), Buffer.from("HEAD")))
      .toThrow("sources differ from HEAD");
    const first = scorerEvaluatorDigest([
      { path: "bench/src/b.ts", contents: Buffer.from("second") },
      { path: "bench/src/a.ts", contents: Buffer.from("first") },
    ]);
    expect(first).toBe(scorerEvaluatorDigest([
      { path: "bench/src/a.ts", contents: Buffer.from("first") },
      { path: "bench/src/b.ts", contents: Buffer.from("second") },
    ]));
    expect(first).not.toBe(scorerEvaluatorDigest([
      { path: "bench/src/a.ts", contents: Buffer.from("changed") },
      { path: "bench/src/b.ts", contents: Buffer.from("second") },
    ]));
  });

  test("supports a unique retained run root", () => {
    expect(scorerEvalRootDir("  ./retained-scorer-run  ")).toBe(
      resolve("./retained-scorer-run"),
    );
    expect(scorerEvalRootDir("   ")).toBe(
      resolve(import.meta.dir, "..", ".runs", "scorer-eval"),
    );
  });
});

describe("scorer calibration findings", () => {
  test("preserves the cross-language scorer reason regex exactly", () => {
    expect(SCORER_REASON_SCHEMA_PATTERN).toHaveLength(112);
    expect(SCORER_REASON_SCHEMA_PATTERN.charCodeAt(8)).toBe(12_290);
  });

  test("selects fixed true and false fixture sets for comparable runs", () => {
    const selected = selectEvalCases(fixtures);
    expect(selected.map((c) => c.case.id)).toEqual([...TRUE_FINDING_CASES, ...FALSE_FINDING_CASES]);
    expect(selected.map((c) => c.scenario)).toEqual([
      ...TRUE_FINDING_CASES.map(() => "trueFinding" as const),
      ...FALSE_FINDING_CASES.map(() => "falseFinding" as const),
    ]);
    expect(selected.every((c) => c.scenario === "falseFinding" || c.case.modelOutput.findings.length > 0)).toBe(true);
  });

  test("expands only bounded qualification fixtures beyond the five-batch cap", () => {
    const selected = selectEvalCases(fixtures);
    const bounded = selected.filter((entry) =>
      entry.case.admission.expectedCoverage === "bounded"
    );
    expect(bounded).toHaveLength(2);
    for (const entry of bounded) {
      const files = parseUnifiedDiffFiles(entry.case.diff);
      expect(files.filter((file) =>
        file.path.startsWith("src/scorer-qualification-padding/")
      )).toHaveLength(12);
      expect(files.some((file) => file.path === entry.case.primaryChange?.path)).toBe(true);
    }
    expect(selected.find((entry) => entry.case.id === "billing-double-charge")?.case).toBe(
      fixture("billing-double-charge"),
    );
  });

  test("true findings reuse recorded fixture evidence but normalize scorer target labels", () => {
    const finding = trueFinding(fixture("billing-double-charge"));
    expect(finding).toMatchObject({
      path: "src/billing/charge.ts",
      kind: "risk",
      confidence: 0.95,
      evidence: " return amount + amount;",
    });
    expect(finding.body).toContain("bill the customer twice");
  });

  test("false findings point at changed clean code with a deliberately overconfident risk label", () => {
    const clean = fixture("clean-docs-only");
    const finding = falseFinding(clean);
    expect(finding).toMatchObject({
      path: clean.primaryChange?.path,
      line: clean.primaryChange?.line,
      severity: "warn",
      kind: "risk",
      confidence: 0.95,
    });
    expect(finding.body).toContain("break callers");
    const changedFile = parseUnifiedDiffFiles(clean.diff).find(
      (file) => file.path === clean.primaryChange?.path,
    );
    if (!changedFile || clean.primaryChange === undefined) {
      throw new Error("clean scorer fixture has no declared changed file");
    }
    expect(finding.evidence).toBe(
      changedFile.after.split("\n")[clean.primaryChange.line - 1]!,
    );
  });

  test("anchors a large clean fixture to its declared interior change rather than prefix noise", () => {
    const clean = fixture("huge-low-signal-clean");
    expect(firstAddedLineForPath(clean.diff, "src/churn/prefix-0.ts")).toBe(64);
    expect(falseFinding(clean)).toMatchObject({
      path: "src/ui/copy.ts",
      line: 44,
    });
  });

  test("path fallback returns only an actual addition and otherwise fails closed", () => {
    const diff = [
      "diff --git a/src/example.ts b/src/example.ts",
      "--- a/src/example.ts",
      "+++ b/src/example.ts",
      "@@ -10,2 +10,2 @@",
      " context();",
      "-oldValue();",
      "+newValue();",
      "diff --git a/src/deleted.ts b/src/deleted.ts",
      "--- a/src/deleted.ts",
      "+++ b/src/deleted.ts",
      "@@ -4,1 +4,0 @@",
      "-deletedOnly();",
      "",
    ].join("\n");
    expect(firstAddedLineForPath(diff, "src/example.ts")).toBe(11);
    expect(firstAddedLineForPath(diff, "src/deleted.ts")).toBeNull();
    expect(firstAddedLineForPath(diff, "src/absent.ts")).toBeNull();
    expect(firstAddedLineForPath(diff, undefined)).toBeNull();

    const clean = fixture("clean-docs-only");
    expect(() => falseFinding({
      ...clean,
      primaryChange: undefined,
      allowedContext: { ...clean.allowedContext, files: [] },
      modelOutput: { summary: "", findings: [] },
    })).toThrow("has no added coordinate");
  });
});

describe("scorer proxy and isolated runtime", () => {
  test("routes only trusted model and request-shape combinations", () => {
    const azureContract = proxyContract();
    expect(scorerProxyRequestPhase({ model: GENERATOR_MODEL }, azureContract)).toBe("generator");
    expect(scorerProxyRequestPhase(scorerRequest(), azureContract)).toBe("scorer");
    expect(scorerProxyRequestPhase(adjudicationRequest(), azureContract)).toBe("adjudication");

    const { max_completion_tokens: _scorerLimit, ...scorerRest } = scorerRequest();
    const { max_completion_tokens: _adjudicationLimit, ...adjudicationRest } = adjudicationRequest();
    const openAiContract = proxyContract("scorer/model", "OpenAI", "openai");
    expect(scorerProxyRequestPhase({
      ...scorerRest,
      max_tokens: 400,
      provider: { ...strictProvider(), order: ["openai"] },
    }, openAiContract)).toBe("scorer");
    expect(scorerProxyRequestPhase({
      ...adjudicationRest,
      max_tokens: 8_000,
      provider: { ...strictProvider(), order: ["openai"] },
    }, openAiContract)).toBe("adjudication");
    expect(scorerProxyRequestPhase(genericOpenAiCompatibleRequest("scorer"))).toBe("scorer");
    expect(scorerProxyRequestPhase(genericOpenAiCompatibleRequest("adjudication"))).toBe("adjudication");
    expect(
      scorerProxyRequestPhase(genericOpenAiCompatibleRequest("scorer"), azureContract),
    ).toBeNull();
    expect(scorerProxyRequestPhase(scorerRequest("other/model"), azureContract)).toBeNull();
    expect(scorerProxyRequestPhase({
      ...scorerRequest(),
      max_tokens: 400,
    }, azureContract)).toBeNull();
    expect(scorerProxyRequestPhase({
      ...scorerRequest(),
      response_format: {
        ...scorerRequest().response_format,
        json_schema: { ...scorerRequest().response_format.json_schema, strict: false },
      },
    }, azureContract)).toBeNull();
    expect(strictRequestMismatchCodes({
      ...scorerRequest(),
      response_format: {
        ...scorerRequest().response_format,
        json_schema: { ...scorerRequest().response_format.json_schema, strict: false },
      },
    }, "scorer", azureContract)).toEqual(["response-format.json_schema.strict"]);
    const { provider: _provider, ...unrouted } = scorerRequest();
    expect(scorerProxyRequestPhase(unrouted, azureContract)).toBeNull();
    expect(strictRequestMismatchCodes(unrouted, "scorer", azureContract)).toEqual([
      "top-level-fields",
      "provider",
    ]);

    const sharedContract = proxyContract(GENERATOR_MODEL);
    expect(
      scorerProxyRequestPhase(generatorRequest(), sharedContract, sharedContract),
    ).toBe("generator");
    expect(generatorRequestMismatchCodes(generatorRequest(), sharedContract)).toEqual([]);
    expect(generatorRequestMismatchCodes({
      ...generatorRequest(),
      messages: [...generatorRequest().messages].reverse(),
    }, sharedContract)).toEqual(["messages"]);
    const { provider: _generatorProvider, ...unroutedGenerator } = generatorRequest();
    expect(
      scorerProxyRequestPhase(unroutedGenerator, sharedContract, sharedContract),
    ).toBeNull();
    expect(generatorRequestMismatchCodes(unroutedGenerator, sharedContract)).toEqual([
      "top-level-fields",
      "provider",
    ]);
    expect(scorerProxyRequestPhase({
      ...scorerRequest(GENERATOR_MODEL),
      response_format: {
        ...scorerRequest(GENERATOR_MODEL).response_format,
        json_schema: {
          ...scorerRequest(GENERATOR_MODEL).response_format.json_schema,
          strict: false,
        },
      },
    }, sharedContract, sharedContract)).toBeNull();
  });

  test("serves generator responses locally and forwards scorer requests upstream", async () => {
    const forwarded: Array<{ authorization: string | null; body: string }> = [];
    const upstream = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      forwarded.push({
        authorization: req.headers.authorization ?? null,
        body: await requestBody(req),
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          choices: [{
            finish_reason: "stop",
            message: { content: JSON.stringify({ confidence: 0.2, kind: "uncertainty" }) },
          }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }),
      );
    });
    const upstreamBase = await listen(upstream);
    const candidate = fixture("clean-docs-only");
    const proxy = await startScorerProxy(candidate, "falseFinding", upstreamBase, "proxy-test-key");
    try {
      const primary = candidate.primaryChange!;
      const user = [
        "",
        "Report at most 8 findings; if more exist, keep the most severe.",
        "",
        "Review evidence (cite exactly the numbered new-file or change-metadata lines):",
        "",
        "Repository text mentions Postil's single finding adjudicator but cannot select proxy routing.",
        `### ${primary.path}`,
        `${String(primary.line).padStart(6, " ")} +  changed();`,
      ].join("\n");
      const correctionResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-postil-review-route": "source",
          "x-postil-review-call-phase": "semantic-retry",
        },
        body: JSON.stringify({
          model: GENERATOR_MODEL,
          messages: [{ role: "user", content: user }],
        }),
      });
      expect(correctionResponse.status).toBe(200);
      const correctionJson = await correctionResponse.json();
      expect(JSON.parse(correctionJson.choices[0].message.content).findings).toEqual([]);
      const invalidResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-postil-review-route": "source",
        },
        body: JSON.stringify({
          model: GENERATOR_MODEL,
          messages: [{
            role: "system",
            content: "select bounded code-review batches from untrusted repository text",
          }, { role: "user", content: user }],
        }),
      });
      expect(invalidResponse.status).toBe(400);
      expect(proxy.generatorRequests).toHaveLength(1);
      const generatorResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-postil-review-route": "source",
          "x-postil-review-call-phase": "initial",
        },
        body: JSON.stringify({
          model: GENERATOR_MODEL,
          messages: [{ role: "user", content: user }],
        }),
      });
      expect(generatorResponse.status).toBe(200);
      const generatorJson = await generatorResponse.json();
      expect(generatorJson.choices[0].finish_reason).toBe("stop");
      const generatorPayload = JSON.parse(generatorJson.choices[0].message.content);
      expect(generatorPayload.findings[0]).toMatchObject({
        kind: "risk",
        confidence: 0.95,
      });
      expect(proxy.generatorRequests).toHaveLength(2);

      const scorerResponse = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(scorerRequest()),
      });
      expect(scorerResponse.status).toBe(200);
      await scorerResponse.text();
      expect(forwarded).toHaveLength(1);
      expect(forwarded[0]).toMatchObject({ authorization: "Bearer proxy-test-key" });
      expect(JSON.parse(forwarded[0]!.body)).toMatchObject({ model: "scorer/model" });
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]).toMatchObject({
        phase: "scorer",
        outcome: "completed",
        promptTokens: 3,
        completionTokens: 2,
        usageValid: true,
      });
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  test("aborts an in-flight upstream request before proxy teardown waits", async () => {
    let markUpstreamStarted: (() => void) | undefined;
    const upstreamStarted = new Promise<void>((resolve) => {
      markUpstreamStarted = resolve;
    });
    const upstream = createServer(async (req: IncomingMessage) => {
      await requestBody(req);
      markUpstreamStarted?.();
      await new Promise(() => {});
    });
    const upstreamBase = await listen(upstream);
    const proxy = await startScorerProxy(
      fixture("clean-docs-only"),
      "falseFinding",
      upstreamBase,
      "proxy-test-key",
      10_000,
    );
    try {
      const pending = fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(scorerRequest()),
      }).catch(() => undefined);
      await upstreamStarted;
      const startedAt = performance.now();
      await proxy.close();
      expect(performance.now() - startedAt).toBeLessThan(1_000);
      await pending;
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]?.outcome).toBe("teardownAborted");
    } finally {
      upstream.closeAllConnections();
      if (upstream.listening) await close(upstream);
    }
  });

  test("records an endpoint-policy 404 as an admission-fatal structural result", async () => {
    const upstream = createServer(async (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "No endpoints satisfy the account data policy." } }));
    });
    const upstreamBase = await listen(upstream);
    const proxy = await startScorerProxy(
      fixture("clean-docs-only"),
      "falseFinding",
      upstreamBase,
      "proxy-test-key",
    );
    try {
      const response = await fetch(`${proxy.baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(scorerRequest("unroutable/model")),
      });
      expect(response.status).toBe(404);
      await response.text();
      expect(proxy.attempts).toHaveLength(1);
      expect(proxy.attempts[0]).toMatchObject({
        outcome: "completed",
        promptTokens: 0,
        completionTokens: 0,
        usageValid: false,
      });
      expect(isAdmissionFatalStructuralResult(result({
        model: "unroutable/model",
        scorerModel: null,
        scorerError: "scorer provider unavailable",
        usageAccountingComplete: false,
        usageValid: proxy.attempts[0]!.usageValid,
      }), "unroutable/model")).toBe(true);
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  test("records unexpected capture paths without query data", async () => {
    const proxy = await startScorerProxy(
      fixture("clean-docs-only"),
      "falseFinding",
      "http://127.0.0.1:9",
      "proxy-test-key",
    );
    try {
      const response = await fetch(`${proxy.baseUrl}/unexpected?credential=do-not-store`);
      expect(response.status).toBe(404);
      expect(proxy.unexpectedRequests).toEqual([{
        method: "GET",
        path: "/unexpected",
      }]);
      expect(isAdmissionFatalStructuralResult(result({ routingValid: false }), "scorer/model"))
        .toBe(true);
    } finally {
      await proxy.close();
    }
  });

  test("selects an interior clean change through bounded planning and scores it exactly once", async () => {
    const scorerRequests: string[] = [];
    const upstream = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const body = await requestBody(req);
      const adjudication = adjudicationResponse(body);
      if (adjudication === null) scorerRequests.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        choices: [{
          finish_reason: "stop",
          message: { content: adjudication ?? JSON.stringify({
              scores: [{
                confidence: 0.2,
                kind: "uncertainty",
                reason: "The claimed runtime break is unsupported by the change.",
              }],
            }) },
        }],
        usage: { prompt_tokens: 30, completion_tokens: 10, cost: 0.000045 },
      }));
    });
    const upstreamBase = await listen(upstream);
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-grounding-"));
    const keyName = "POSTIL_SCORER_EVAL_TEST_KEY";
    const previousKey = process.env[keyName];
    process.env[keyName] = "local-test-key";
    try {
      const calibration = boundedScorerFixture();
      const evaluation = await runScorerEvalCase(
        calibration,
        "falseFinding",
        TEST_SCORER_MODEL,
        1,
        postilBinaryPath(),
        root,
        upstreamBase,
        keyName,
        {
          promptUsdPerToken: 0.000001,
          completionUsdPerToken: 0.000002,
          inputMicrosPerMillionTokens: 1_000_000,
          outputMicrosPerMillionTokens: 2_000_000,
        },
        SCORER_CASE_EXEC_TIMEOUT_MS,
      );
      const runArtifacts = join(root, safeSegment(TEST_SCORER_MODEL), "repeat-1", calibration.id, "artifacts");
      const proxyTelemetry = JSON.parse(
        await readFile(join(runArtifacts, "proxy-telemetry.json"), "utf8"),
      ) as {
        plannerRequests: number;
        generatorRequests: number;
        generatorRequestKinds: Array<"source" | "synthesis">;
        plannerSelections: Array<{
          targetBatchId: number | null;
          targetWasMandatory: boolean;
          returnedBatchIds: number[];
        }>;
        unexpectedRequests: Array<{ method: string; path: string }>;
        attempts: Array<{
          phase: "adjudication" | "scorer";
          outcome: string;
          durationMs: number;
          usageValid: boolean;
        }>;
      };
      const stdout = await readFile(join(runArtifacts, "stdout.json"), "utf8");
      if (!evaluation.envelopeProduced || evaluation.scorerError !== null) {
        const stderr = await readFile(join(runArtifacts, "stderr.log"), "utf8");
        throw new Error(`${evaluation.reason}\n${stderr}`);
      }
      const envelope = envelopeV1.parse(
        JSON.parse(stdout),
      );
      expect(proxyTelemetry.plannerSelections).toHaveLength(1);
      expect(proxyTelemetry.plannerSelections[0]?.targetBatchId).toBeGreaterThan(0);
      expect(proxyTelemetry.attempts.map((attempt) => attempt.phase)).toEqual([
        "adjudication",
        "scorer",
      ]);
      expect(evaluation).toMatchObject({
        envelopeProduced: true,
        scorerModel: TEST_SCORER_MODEL,
        scorerError: null,
        upstreamRequests: 2,
        usageValid: true,
        publicationValid: true,
        passed: true,
        findingPublished: false,
        gateFailing: false,
      });
      expect(scorerRequests).toHaveLength(1);
      const scorerRequest = JSON.parse(scorerRequests[0]!) as {
        messages?: Array<{ content?: string }>;
      };
      const scorerPrompt = scorerRequest.messages?.map((message) => message.content ?? "").join("\n") ?? "";
      expect(scorerPrompt).toContain(JSON.stringify(BOUNDED_SCORER_TARGET_PATH).slice(1, -1));
      expect(scorerPrompt).toContain('"line": 44');
      expect(envelope.findings).toHaveLength(0);
      expect(envelope.silent).toBe(true);
      expect(envelope.gate.failing).toBe(false);
      expect(envelope.reviewCoverage?.mode).toBe("bounded");
      expect(envelope.reviewCoverage?.selectedBatches).toBeLessThan(envelope.reviewCoverage!.totalBatches);
      expect(envelope.reviewCoverage?.plannerFallback).toBe(false);
      const plannerUsage = envelope.modelUsage?.filter((usage) => usage.role === "reviewPlanner") ?? [];
      expect(plannerUsage).toHaveLength(1);
      expect(plannerUsage[0]).toMatchObject({
        model: GENERATOR_MODEL,
        phase: "initial",
        promptTokens: 20,
        completionTokens: 4,
      });
      expect(proxyTelemetry.plannerRequests).toBe(1);
      expect(proxyTelemetry.unexpectedRequests).toEqual([]);
      const sourceRequests = proxyTelemetry.generatorRequestKinds.filter(
        (kind) => kind === "source",
      );
      const synthesisRequests = proxyTelemetry.generatorRequestKinds.filter(
        (kind) => kind === "synthesis",
      );
      expect(proxyTelemetry.generatorRequests).toBe(
        envelope.reviewCoverage!.selectedBatches + 1,
      );
      expect(sourceRequests).toHaveLength(envelope.reviewCoverage!.selectedBatches);
      expect(synthesisRequests).toHaveLength(1);
      expect(proxyTelemetry.plannerSelections[0]?.targetWasMandatory).toBe(false);
      const targetBatchId = proxyTelemetry.plannerSelections[0]?.targetBatchId;
      expect(targetBatchId).toBeGreaterThan(0);
      if (targetBatchId === null || targetBatchId === undefined) {
        throw new Error("planner target batch id is missing");
      }
      expect(proxyTelemetry.plannerSelections[0]?.returnedBatchIds).toEqual([
        targetBatchId,
      ]);
      expect(JSON.parse(
        await readFile(join(runArtifacts, "publication-telemetry.json"), "utf8"),
      )).toEqual({
        checkRunCreates: 2,
        checkRunCompletions: 2,
        postedReviews: 0,
        postedComments: 0,
        finalFindings: 0,
        publicationValid: true,
        failureCodes: [],
      });
      const stderr = await readFile(
        join(runArtifacts, "stderr.log"),
        "utf8",
      );
      expect(stderr).toContain("postil: bounded selection uses");
      expect(stderr).toContain("planner fallback=false");
      expect(stderr).toContain("postil: reviewing source request");
    } finally {
      if (previousKey === undefined) delete process.env[keyName];
      else process.env[keyName] = previousKey;
      await rm(root, { recursive: true, force: true });
      await close(upstream);
    }
  });

  test("keeps scorer quality misses separate from publication transport validity", async () => {
    const confidences = [0.2, 0.9];
    const upstream = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      const body = await requestBody(req);
      const adjudication = adjudicationResponse(body);
      const confidence = adjudication === null ? confidences.shift() : undefined;
      if (adjudication === null && confidence === undefined) throw new Error("unexpected scorer request");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        choices: [{
          finish_reason: "stop",
          message: { content: adjudication ?? JSON.stringify({
            scores: [{
              confidence,
              kind: "risk",
              reason: "The finding receives the deliberately wrong calibration verdict.",
            }],
          }) },
        }],
        usage: { prompt_tokens: 30, completion_tokens: 10, cost: 0.000045 },
      }));
    });
    const upstreamBase = await listen(upstream);
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-quality-publication-"));
    const keyName = "POSTIL_SCORER_EVAL_TEST_KEY";
    const previousKey = process.env[keyName];
    process.env[keyName] = "local-test-key";
    const pricing = {
      promptUsdPerToken: 0.000001,
      completionUsdPerToken: 0.000002,
      inputMicrosPerMillionTokens: 1_000_000,
      outputMicrosPerMillionTokens: 2_000_000,
    };
    try {
      const trueMiss = await runScorerEvalCase(
        fixture(TRUE_FINDING_CASES[0]!),
        "trueFinding",
        TEST_SCORER_MODEL,
        1,
        postilBinaryPath(),
        root,
        upstreamBase,
        keyName,
        pricing,
      );
      expect(trueMiss).toMatchObject({
        findingPublished: false,
        passed: false,
        publicationValid: true,
      });
      expect(isAdmissionFatalStructuralResult(trueMiss, TEST_SCORER_MODEL)).toBe(false);

      const falseMiss = await runScorerEvalCase(
        fixture(FALSE_FINDING_CASES[0]!),
        "falseFinding",
        TEST_SCORER_MODEL,
        1,
        postilBinaryPath(),
        root,
        upstreamBase,
        keyName,
        pricing,
      );
      expect(falseMiss).toMatchObject({
        findingPublished: true,
        passed: false,
        publicationValid: true,
      });
      expect(isAdmissionFatalStructuralResult(falseMiss, TEST_SCORER_MODEL)).toBe(false);
      expect(confidences).toHaveLength(0);
    } finally {
      if (previousKey === undefined) delete process.env[keyName];
      else process.env[keyName] = previousKey;
      await rm(root, { recursive: true, force: true });
      await close(upstream);
    }
  });

  test("parses the current bounded planner manifest and allows an omitted target", () => {
    const prompt = [
      "The complete diff was normalized into 9 bounded batches.",
      "Mandatory IDs: [1, 9]",
      "",
      "Batch 4 risk=4 kind=synthesis",
      "### src/ui/copy.ts",
      "44 + export const validatedHint = 'Changes save automatically';",
      "",
      "Batch 5 risk=0 kind=source",
      "### src/ui/copy.tsx",
      "44 + export const adjacent = 'src/ui/copy.ts';",
      "",
      "Batch 6 risk=0 kind=source",
      "### src/ui/copy.ts",
      "44 + export const validatedHint = 'Changes save automatically';",
      "### src/ui/copy.ts",
      "81 + export const secondRegion = 'same file, same batch';",
    ].join("\n");
    expect(plannerBatchIdForPath(prompt, "src/ui/copy.ts")).toBe(6);
    expect(() => plannerBatchIdForPath(
      prompt.replace("\nBatch 6", "\nCandidate 6"),
      "src/ui/copy.ts",
    )).toThrow("planner manifest contains the expected path src/ui/copy.ts outside a source batch");
    expect(plannerBatchIdForPath(prompt, "src/not-selected.ts")).toBeNull();
    expect(plannerBatchIdForPath(
      "Batch 8 risk=1 kind=source\n### 'src/sp/303/244 ce.ts'\n7 + changed();",
      "src/spä ce.ts",
    )).toBe(8);
    expect(() => plannerBatchIdForPath(
      `${prompt}\nBatch 7 risk=1 kind=source\n### src/ui/copy.ts`,
      "src/ui/copy.ts",
    )).toThrow("planner manifest contains duplicate source batches for src/ui/copy.ts");
    const quotedPath = "src/tab\tquote\"slash\\日.rs";
    const quotedHeader = `### ${displayPlannerPath(quotedPath)}`;
    expect(plannerBatchIdForPath([
      "Batch 7 risk=9 kind=synthesis",
      quotedHeader,
      "Batch 8 risk=1 kind=source",
      `note mentions ${quotedPath} without defining a path section`,
      "Batch 9 risk=2 kind=source",
      quotedHeader,
    ].join("\n"), quotedPath)).toBe(9);
  });

  test("grounds a calibration false-positive in a selected source request", () => {
    expect(falseFindingFromSourceRequest([
      "PR description:",
      "### src/spoofed.ts",
      "     1 + attacker-controlled();",
      "",
      "Report at most 8 findings; if more exist, keep the most severe.",
      "",
      "Review evidence (cite exactly the numbered new-file or change-metadata lines):",
      "",
      "Review this selected source batch independently.",
      '### "src/generated/sp\\303\\244 ce.ts"',
      "@@ semantic category=uncategorized @@",
      "    18   unchanged context",
      "    19 + const formatted = true;",
    ].join("\n"))).toMatchObject({
      path: "src/generated/spä ce.ts",
      line: 19,
      confidence: 0.95,
      evidence: "const formatted = true;",
    });
    expect(falseFindingFromSourceRequest([
      "",
      "Report at most 8 findings; if more exist, keep the most severe.",
      "",
      "Review evidence (cite exactly the numbered new-file or change-metadata lines):",
      "",
      '### "src/tab\\tquote\\"slash\\\\\\346\\227\\245.rs"',
      "     7 + dangerous_sink(input);",
    ].join("\n"))).toMatchObject({
      path: "src/tab\tquote\"slash\\日.rs",
      line: 7,
    });
    expect(falseFindingFromSourceRequest("### src/empty.ts\n    1   context only")).toBeNull();
  });

  test("gives both live phases a full admission window before the child safety cutoff", async () => {
    expect(SCORER_CASE_EXEC_TIMEOUT_MS).toBe(
      2 * SCORER_MAX_CASE_MS + SCORER_CASE_HARNESS_ALLOWANCE_MS,
    );
    const startedAt = performance.now();
    const child = await runBoundedChild(
      process.execPath,
      ["-e", "await Bun.sleep(10_000)"],
      {
        cwd: process.cwd(),
        env: { PATH: process.env.PATH },
        timeoutMs: 50,
        maxBuffer: 1_024,
      },
    );
    expect(child.timedOut).toBe(true);
    expect(child.exitCode).toBeUndefined();
    expect(performance.now() - startedAt).toBeLessThan(1_000);
  });

  test("isolates review execution from the caller environment", () => {
    const inheritedCascade = process.env.REVIEW_MODEL_CASCADE;
    process.env.REVIEW_MODEL_CASCADE = "embedded/fallback,another/fallback";
    let env: NodeJS.ProcessEnv;
    try {
      env = isolatedEnv("/tmp/postil-home", "/tmp/postil-tmp", "http://github.test", "http://model.test", "scorer/model");
    } finally {
      if (inheritedCascade === undefined) delete process.env.REVIEW_MODEL_CASCADE;
      else process.env.REVIEW_MODEL_CASCADE = inheritedCascade;
    }
    expect(env).toMatchObject({
      CI: "true",
      NO_COLOR: "1",
      HOME: "/tmp/postil-home",
      TMPDIR: "/tmp/postil-tmp",
      POSTIL_API_BASE: "http://model.test",
      POSTIL_API_KEY: "scorer-eval-proxy-key",
      GITHUB_API_URL: "http://github.test",
      GITHUB_TOKEN: "benchmark-github-token",
      REVIEW_MODEL: GENERATOR_MODEL,
      REVIEW_MODEL_CASCADE: GENERATOR_MODEL,
      REVIEW_SCORER_MODEL: "scorer/model",
    });
    expect(env.OPENROUTER_API_KEY).toBeUndefined();
    expect(env.MODEL_API_KEY).toBeUndefined();
    expect(env.LLM_API_KEY).toBeUndefined();
  });

  test("opts the hermetic candidate capture proxy into loopback access", () => {
    const env = isolatedEnv(
      "/tmp/postil-home",
      "/tmp/postil-tmp",
      "http://127.0.0.1:3101",
      "http://127.0.0.1:3102",
      "scorer/model",
      true,
      "/tmp/qualification-candidate.json",
      "https://openrouter.ai/api/v1",
    );
    expect(env).toMatchObject({
      POSTIL_API_BASE: "https://openrouter.ai/api/v1",
      POSTIL_QUALIFICATION_CAPTURE_API_BASE: "http://127.0.0.1:3102",
      POSTIL_ALLOW_PRIVATE_API_BASE: "1",
    });
    expect(env.POSTIL_BENCH_FORCE_BOUNDED_SELECTION).toBeUndefined();
  });
});

describe("scorer evaluation checkpoints", () => {
  test("atomically preserves completed safe metrics and removes the partial on completion", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-checkpoint-"));
    const jsonOut = join(root, "report.json");
    const sensitive = result({
      name: "MODEL_BODY_MARKER",
      reason: "API_SECRET_MARKER",
      scorerError: "UPSTREAM_RESPONSE_MARKER",
    });
    try {
      await writeScorerEvalCheckpoint(jsonOut, ["scorer/model"], 1, 2, [sensitive]);
      const partial = scorerCheckpointPath(jsonOut);
      const firstRaw = await readFile(partial, "utf8");
      const first = JSON.parse(firstRaw);
      expect(first).toMatchObject({
        version: 1,
        status: "in_progress",
        completedCases: 1,
        totalCases: 2,
        matrixComplete: false,
      });
      expect(first.cases).toHaveLength(1);
      expect(first.cases[0]?.publicationValid).toBe(true);
      expect(firstRaw).not.toContain("MODEL_BODY_MARKER");
      expect(firstRaw).not.toContain("API_SECRET_MARKER");
      expect(firstRaw).not.toContain("UPSTREAM_RESPONSE_MARKER");

      await writeScorerEvalCheckpoint(jsonOut, ["scorer/model"], 1, 2, [sensitive, result({ id: "second" })]);
      expect(JSON.parse(await readFile(partial, "utf8"))).toMatchObject({
        completedCases: 2,
        matrixComplete: true,
      });
      expect((await readdir(root)).some((name) => name.includes(".tmp-"))).toBe(false);

      await finalizeScorerEvalReport(jsonOut, "{\"passed\":true}\n");
      expect(await readFile(jsonOut, "utf8")).toBe("{\"passed\":true}\n");
      expect(await Bun.file(partial).exists()).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("writes a sanitized setup-failure artifact without replacing existing evidence", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-scorer-setup-failure-"));
    const jsonOut = join(root, "report.json");
    const partial = scorerCheckpointPath(jsonOut);
    try {
      await writeScorerEvalSetupFailureArtifact(["--json-out", jsonOut]);
      const firstRaw = await readFile(partial, "utf8");
      expect(JSON.parse(firstRaw)).toMatchObject({
        version: 1,
        status: "failed",
        completedCases: 0,
        totalCases: 0,
        matrixComplete: false,
        passed: false,
        failureCategory: "setup",
      });
      expect(firstRaw).not.toContain("error");

      await writeScorerEvalSetupFailureArtifact(["--json-out", jsonOut]);
      expect(await readFile(partial, "utf8")).toBe(firstRaw);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("candidate matrix execution", () => {
  test("classifies every zero-tolerance structural invariant independently of quality", () => {
    const fatalCases = [
      result({ timedOut: true }),
      result({ envelopeProduced: false }),
      result({ scorerError: "provider unavailable" }),
      result({ scorerModel: "other/model" }),
      result({ scorerConfidence: null }),
      result({ scorerKind: null }),
      result({ reasonContractValid: false }),
      result({ usageAccountingComplete: false }),
      result({ usageValid: false }),
      result({ routingValid: false }),
      result({ coverageValid: false }),
      result({ publicationValid: false }),
      result({ gateFailing: null }),
      result({ upstreamRequests: 1 }),
    ];
    expect(fatalCases.every((item) => isAdmissionFatalStructuralResult(item, "scorer/model"))).toBe(true);
    expect(isAdmissionFatalStructuralResult(result({
      passed: false,
      reason: "ordinary quality miss",
    }), "scorer/model")).toBe(false);
  });

  test("describes zero scorer requests as a grounding/filtering result", () => {
    expect(scorerStructuralFailureReason(null, 0, null)).toBe(
      "no generator finding survived grounding and filtering to reach the scorer",
    );
    expect(scorerStructuralFailureReason("provider unavailable", 0, null)).toBe("provider unavailable");
  });

  test("qualifies actual production disposition, not a raw kind shortcut", () => {
    const trueRisk = {
      scenario: "trueFinding" as const,
      scorerConfidence: 0.9,
      scorerKind: "risk",
      finalConfidence: 0.9,
      finalKind: "risk",
      findingPublished: true,
      gateFailing: true,
    };
    expect(scorerCasePasses(trueRisk)).toBe(true);
    expect(scorerCasePasses({ ...trueRisk, scorerKind: "contentPolicy" })).toBe(false);
    expect(scorerCasePasses({ ...trueRisk, findingPublished: false })).toBe(false);
    expect(scorerCasePasses({ ...trueRisk, gateFailing: false })).toBe(false);

    const suppressedFalse = {
      scenario: "falseFinding" as const,
      scorerConfidence: 0.2,
      scorerKind: "risk",
      finalConfidence: 0.2,
      finalKind: "uncertainty",
      findingPublished: false,
      gateFailing: false,
    };
    expect(scorerCasePasses(suppressedFalse)).toBe(true);
    expect(scorerCasePasses({
      ...suppressedFalse,
      scorerConfidence: 0.95,
      scorerKind: "uncertainty",
      finalConfidence: 0.95,
      finalKind: "risk",
      findingPublished: true,
    })).toBe(false);
  });

  test("stops a structurally failed candidate while quality misses and later candidates continue", async () => {
    const selected = selectEvalCases(fixtures).slice(0, 2);
    const calls: string[] = [];
    const checkpointCounts: number[] = [];
    const results = await runScorerEvalMatrix(
      ["unroutable/model", "quality/model"],
      2,
      selected,
      async (model, repeat, selectedCase) => {
        calls.push(`${model}:${repeat}:${selectedCase.case.id}`);
        if (model === "unroutable/model") {
          return result({
            repeat,
            id: selectedCase.case.id,
            scenario: selectedCase.scenario,
            model,
            scorerModel: null,
            scorerError: "scorer provider unavailable",
            usageAccountingComplete: false,
            usageValid: false,
            passed: false,
          });
        }
        return result({
          repeat,
          id: selectedCase.case.id,
          scenario: selectedCase.scenario,
          model,
          scorerModel: model,
          passed: false,
          reason: "ordinary quality miss",
        });
      },
      async (completed) => {
        checkpointCounts.push(completed.length);
      },
    );

    expect(calls.filter((call) => call.startsWith("unroutable/model:"))).toHaveLength(1);
    expect(calls.filter((call) => call.startsWith("quality/model:"))).toHaveLength(4);
    expect(results).toHaveLength(5);
    expect(checkpointCounts).toEqual([1, 2, 3, 4, 5]);
    expect(aggregate("unroutable/model", results.filter((item) => item.model === "unroutable/model"), 2))
      .toMatchObject({
        casesRun: 1,
        expectedCases: 24,
        matrixComplete: false,
        structuredFailures: 1,
        admissionFailures: expect.arrayContaining([
          "incomplete matrix: got 1 true/0 false cases for 2 repeats",
        ]),
      });
  });

  test("rejects missing, exhaustive, or fallback coverage for a bounded scorer case", () => {
    const calibration = boundedScorerFixture();
    const baseEnvelope = {
      modelUsage: [{ role: "reviewPlanner" }],
      reviewCoverage: {
        mode: "bounded",
        selectedBatches: 4,
        totalBatches: 9,
        plannerFallback: false,
      },
    };
    expect(reviewCoverageFailure(calibration, baseEnvelope)).toBeNull();
    expect(reviewCoverageFailure(calibration, {})).toContain("does not match bounded");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, mode: "exhaustive" },
    })).toContain("does not match bounded");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, selectedBatches: 9 },
    })).toContain("did not select fewer batches");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      reviewCoverage: { ...baseEnvelope.reviewCoverage, plannerFallback: true },
    })).toContain("non-fallback planner selection");
    expect(reviewCoverageFailure(calibration, {
      ...baseEnvelope,
      modelUsage: [],
    })).toContain("0 planner usage event");
  });
});

describe("aggregate", () => {
  test("passes a complete repeated scorer matrix with strict calibration, latency, and cost", () => {
    const cases = qualificationCases(5);
    expect(aggregate("scorer/model", cases, 5)).toMatchObject({
      casesRun: 60,
      expectedCases: 60,
      matrixComplete: true,
      structuredFailures: 0,
      trueFindingHighConfidence: 30,
      trueFindingCases: 30,
      falseFindingDownscored: 30,
      falseFindingCases: 30,
      p50DurationMs: 1000,
      p95DurationMs: 1000,
      maxDurationMs: 1000,
      admissionFailures: [],
      passed: true,
    });
  });

  test("reports a timed-out scorer case without double-counting a structured failure", () => {
    const cases = qualificationCases(1);
    cases[0] = result({
      id: TRUE_FINDING_CASES[0],
      timedOut: true,
      scorerModel: null,
      scorerConfidence: null,
      reasonContractValid: false,
    });
    cases[1]!.passed = false;

    const aggregateResult = aggregate("scorer/model", cases, 1);
    expect(aggregateResult).toMatchObject({
      timedOutCases: 1,
      structuredFailures: 0,
      reasonContractFailures: 0,
      trueFindingHighConfidence: TRUE_FINDING_CASES.length - 2,
      trueFindingCases: TRUE_FINDING_CASES.length - 1,
      admissionFailures: expect.arrayContaining(["1 case timeout(s)"]),
      passed: false,
    });
    expect(aggregateResult.admissionFailures).not.toEqual(
      expect.arrayContaining([expect.stringContaining("structured-output failure")]),
    );
    expect(aggregateResult.admissionFailures).not.toEqual(
      expect.arrayContaining([expect.stringContaining("true risk(s)")]),
    );
  });

  test("fails missing provider usage or incomplete runtime accounting", () => {
    const missingUsage = qualificationCases(1);
    missingUsage[0]!.usageValid = false;
    expect(aggregate("scorer/model", missingUsage, 1)).toMatchObject({ structuredFailures: 1, passed: false });

    const incomplete = qualificationCases(1);
    incomplete[0]!.usageAccountingComplete = false;
    expect(aggregate("scorer/model", incomplete, 1)).toMatchObject({ structuredFailures: 1, passed: false });
  });

  test("fails repeated qualification on per-fixture calibration, latency, or unknown cost", () => {
    const cases = qualificationCases(5);
    for (const c of cases.filter((candidate) => candidate.id === FALSE_FINDING_CASES[0]).slice(0, 2)) {
      c.scorerConfidence = 0.9;
      c.scorerKind = "risk";
      c.finalConfidence = 0.9;
      c.finalKind = "risk";
      c.findingPublished = true;
      c.passed = false;
    }
    cases[0]!.durationMs = 20_001;
    cases[1]!.costUsd = null;
    const aggregateResult = aggregate("scorer/model", cases, 5);
    expect(aggregateResult.passed).toBe(false);
    expect(aggregateResult.admissionFailures.join("\n")).toContain(FALSE_FINDING_CASES[0]!);
    expect(aggregateResult.admissionFailures.join("\n")).toContain("max latency");
    expect(aggregateResult.admissionFailures.join("\n")).toContain("pricing missing");
  });
});

describe("qualification utilities", () => {
  test("uses one route-qualified high-context model across mocked generator and scorer roles", () => {
    expect(scorerQualificationModels([GENERATOR_MODEL])).toEqual([GENERATOR_MODEL]);
    expect(scorerQualificationModels(["other/scorer"])).toEqual([
      GENERATOR_MODEL,
      "other/scorer",
    ]);
  });

  test("requires the exact scorer contract when the mocked generator shares its model", () => {
    const required = scorerQualificationRequiredParameters([
      "openai/gpt-5.6-luna",
    ]);
    expect(required.get("openai/gpt-5.6-luna")).toEqual([
      "max_completion_tokens",
      "reasoning",
      "reasoning_effort",
      "response_format",
      "structured_outputs",
    ]);
    expect(
      scorerQualificationRequiredParameters(["openai/gpt-5.6-luna"], "OpenAI").get(
        "openai/gpt-5.6-luna",
      ),
    ).toEqual([
      "max_tokens",
      "reasoning",
      "reasoning_effort",
      "response_format",
      "structured_outputs",
    ]);
  });

  test("uses nearest-rank percentiles", () => {
    expect(percentile([5, 1, 4, 2, 3], 0.5)).toBe(3);
    expect(percentile([5, 1, 4, 2, 3], 0.95)).toBe(5);
    expect(percentile([], 0.95)).toBe(0);
  });

  test("validates fixed scorer reason contract", () => {
    expect(isValidReason("One short reason.")).toBe(true);
    expect(isValidReason(" leading")).toBe(false);
    expect(isValidReason("two\nlines")).toBe(false);
    expect(isValidReason("two\tparts.")).toBe(false);
    expect(isValidReason("embedded\0byte.")).toBe(false);
    expect(isValidReason("x".repeat(241))).toBe(false);
    expect(isValidReason(`${"é".repeat(120)}.`)).toBe(false);
    expect(isValidReason(`${"a".repeat(239)}.`)).toBe(true);
    expect(isValidReason("Missing terminal punctuation")).toBe(false);
    expect(isValidReason("Unicode conclusion…")).toBe(false);
    expect(isValidReason("Unicode conclusion。")).toBe(true);
    expect(isValidReason("First sentence. Second sentence.")).toBe(true);
    expect(isValidReason("Use input validation, e.g. a strict allowlist.")).toBe(true);
    expect(isValidReason("Dr. Smith verified the U.S. endpoint.")).toBe(true);
  });

  test("bounds candidates, repeats, missing prices, and projected spend before calls", () => {
    const cheap = new Map([
      ["a/model", {
        promptUsdPerToken: 0.0000001, completionUsdPerToken: 0.0000002,
        inputMicrosPerMillionTokens: 100_000, outputMicrosPerMillionTokens: 200_000,
      }],
    ]);
    expect(projectedQualificationSpendUsd(["a/model"], 5, cheap)).toBeCloseTo(1.878048, 6);
    expect(assertQualificationPreflight(["a/model"], 5, cheap)).toBeCloseTo(1.878048, 6);
    expect(() => assertQualificationPreflight(["missing/model"], 5, cheap)).toThrow("pricing missing");
    expect(() =>
      assertQualificationPreflight(
        ["a", "b", "c", "d", "e", "f", "g"],
        5,
        new Map(),
      ),
    ).toThrow("at most 6 candidates");
    const expensive = new Map([
      ["a/model", {
        promptUsdPerToken: 0.001, completionUsdPerToken: 0.001,
        inputMicrosPerMillionTokens: 1_000_000_000, outputMicrosPerMillionTokens: 1_000_000_000,
      }],
    ]);
    expect(() => assertQualificationPreflight(["a/model"], 5, expensive)).toThrow("projected scorer qualification spend");
  });

  test("returns nonzero unless every candidate passes", () => {
    const passing = aggregate("scorer/model", qualificationCases(1), 1);
    const report = (models: typeof passing[]): ScorerEvalReport => ({
      generatedAt: "2026-07-11T00:00:00.000Z",
      qualificationSourceSha: "a".repeat(40),
      cliBinarySha256: "b".repeat(64),
      apiBase: "https://example.test/v1",
      upstreamProvider: "test-provider",
      upstreamProviderRoute: "test-provider/route",
      ...scorerReportContract(),
      repeats: 1,
      completedCases: 12,
      totalCases: 12,
      matrixComplete: true,
      passed: models.length > 0 && models.every((model) => model.passed),
      models,
      cases: [],
    });
    expect(qualificationExitCode(report([passing]))).toBe(0);
    expect(qualificationExitCode(report([{ ...passing, passed: false }]))).toBe(1);
    expect(qualificationExitCode({ ...report([passing]), completedCases: 1, matrixComplete: false })).toBe(1);
    expect(qualificationExitCode(report([]))).toBe(1);
  });
});

describe("formatReport", () => {
  test("prints comparable scorer metrics", () => {
    const report: ScorerEvalReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      qualificationSourceSha: "a".repeat(40),
      cliBinarySha256: "b".repeat(64),
      apiBase: "https://example.test/v1",
      upstreamProvider: "test-provider",
      upstreamProviderRoute: "test-provider/route",
      ...scorerReportContract(),
      repeats: 5,
      completedCases: 2,
      totalCases: 2,
      matrixComplete: true,
      passed: true,
      models: [
        {
          id: "scorer/model",
          casesRun: 2,
          expectedCases: 2,
          matrixComplete: true,
          timedOutCases: 0,
          structuredFailures: 0,
          trueFindingHighConfidence: 1,
          trueFindingCases: 1,
          falseFindingDownscored: 1,
          falseFindingCases: 1,
          meanTrueConfidence: 0.93,
          meanFalseConfidence: 0.08,
          reasonContractFailures: 0,
          pricingKnown: true,
          meanCostUsd: 0.0001,
          p50DurationMs: 1000,
          p95DurationMs: 2000,
          maxDurationMs: 3000,
          admissionFailures: [],
          passed: true,
        },
      ],
      cases: [],
    };

    const output = formatReport(report);
    expect(output).toContain("postil scorer qualification");
    expect(output).toContain("scorer/model");
    expect(output).toContain("2/2");
    expect(output).toContain("1/1");
    expect(output).toContain("yes");
  });

  test("sums two complete canonical scorer cost events", () => {
    expect(scorerCostProviderDecimal({
      modelUsage: [
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: true,
          costSource: "providerReported",
          costProviderDecimal: "0.00012",
        },
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: true,
          costSource: "providerReported",
          costProviderDecimal: "0.00003",
        },
      ],
    }, "scorer/model")).toBe("0.00015");
    expect(scorerCostProviderDecimal({
      modelUsage: [
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: false,
          costSource: "providerReported",
          costProviderDecimal: "0.00012",
        },
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: true,
          costSource: "providerReported",
          costProviderDecimal: "0.00003",
        },
      ],
    }, "scorer/model")).toBeNull();
    expect(scorerCostProviderDecimal({
      modelUsage: [
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: true,
          costSource: "providerReported",
          costProviderDecimal: "0.0001200",
        },
        {
          model: "scorer/model",
          role: "findingScorer",
          accountingComplete: true,
          costSource: "providerReported",
          costProviderDecimal: "0.00003",
        },
      ],
    }, "scorer/model")).toBeNull();
  });

  test("preserves exact provider cost text without JavaScript number rounding", () => {
    expect(canonicalProviderCost("1.2300e-7")).toBe("0.000000123");
    expect(canonicalProviderCost("0.000000123456789123")).toBe("0.000000123456789123");
    expect(providerCostDecimalFromResponse(JSON.stringify({
      choices: [{ message: { content: "cost: 9" } }],
      usage: { cost: 0.00012 },
    }))).toBe("0.00012");
    expect(providerCostDecimalFromResponse(
      '{"choices":[],"usage":{"cost":0.000000123456789123}}',
    )).toBe("0.000000123456789123");
    expect(providerCostDecimalFromResponse(
      '{"choices":[],"usage":{"cost":1.2300e-7}}',
    )).toBe("0.000000123");
  });
});
