import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { access, chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ATTRIBUTION_BANK, type AttributionBankCase } from "../fixtures/attribution-bank";
import { cases as qualificationCases } from "../fixtures/cases";
import {
  ATTRIBUTION_CONTRACT_VERSION,
  ATTRIBUTION_MAX_CALLS_PER_FINDING_SET,
  ATTRIBUTION_SETTINGS,
  AttributionGovernor,
  attributeCandidates,
  attributionBankSha256,
  attributionContractSha256,
  attributionEvidenceSha256,
  exactRegionOverlap,
  projectedAttributionDecisionCostUsd,
  replayAttributionEvidence,
  type AttributionCallEvidence,
  type AttributionCandidate,
  type AttributionTarget,
} from "./attribution";

const target: AttributionTarget = {
  path: "src/payments.ts",
  startLine: 41,
  endLine: 41,
  contract: "A retry posts a second debit because it bypasses idempotency.",
};

const candidate: AttributionCandidate = {
  path: target.path,
  line: 41,
  endLine: 41,
  severity: "error",
  kind: "risk",
  title: "Retry duplicates a debit",
  body: "The retry bypasses idempotency and posts another debit.",
};

describe("atomic attribution contract", () => {
  test("binds only findings whose exact path and anchor are inside the target", () => {
    expect(exactRegionOverlap(candidate, target)).toBe(true);
    expect(exactRegionOverlap({ ...candidate, line: 40, endLine: 40 }, target)).toBe(false);
    expect(exactRegionOverlap({ ...candidate, line: 42, endLine: 42 }, target)).toBe(false);
    expect(exactRegionOverlap({ ...candidate, path: "src/other.ts" }, target)).toBe(false);
    expect(exactRegionOverlap({ ...candidate, line: 1, endLine: 100 }, target)).toBe(false);
    expect(exactRegionOverlap({ ...candidate, line: 41, endLine: 100 }, target)).toBe(true);
  });

  test("makes no transport call for off-region findings", async () => {
    const result = await attributeCandidates(
      target,
      [{ ...candidate, line: 42, endLine: 42 }],
      {
        binary: "/binary-that-must-not-run",
        runDir: "/tmp/postil-attribution-test-that-must-not-exist",
        env: {},
        sourceSha256: "a".repeat(64),
        binarySha256: "b".repeat(64),
        evaluatorModel: "provider/scorer",
        expectedProvider: "PinnedProvider",
        apiFormat: "openai-compatible",
        repeat: 1,
        governor: new AttributionGovernor(),
        projectedCostUsdDecimal: "0.01",
      },
    );
    expect(result).toEqual({ scored: true, detected: false, calls: [] });
  });

  test("rejects same-region finding spam before transport", async () => {
    const result = await attributeCandidates(
      target,
      Array.from({ length: ATTRIBUTION_MAX_CALLS_PER_FINDING_SET + 1 }, (_, index) => ({
        ...candidate,
        title: `Candidate ${index}`,
      })),
      {
        binary: "/binary-that-must-not-run",
        runDir: "/tmp/postil-attribution-spam-test-that-must-not-exist",
        env: {},
        sourceSha256: "a".repeat(64),
        binarySha256: "b".repeat(64),
        evaluatorModel: "provider/scorer",
        expectedProvider: "PinnedProvider",
        apiFormat: "openai-compatible",
        repeat: 1,
        governor: new AttributionGovernor(),
        projectedCostUsdDecimal: "0.01",
      },
    );
    expect(result).toEqual({
      scored: false,
      detected: false,
      calls: [],
      error: "attribution candidate count exceeds the fixed call cap",
    });
  });

  test("projects every possibly billed attempt from the enforced prompt ceiling", () => {
    const perDecision = projectedAttributionDecisionCostUsd({
      inputMicrosPerMillionTokens: 947_800,
      outputMicrosPerMillionTokens: 2_978_800,
    });
    expect(perDecision).toBe("0.031656");
    const positiveCases = qualificationCases.filter(
      (entry) => (entry.groundTruth?.findings?.length ?? 0) > 0,
    ).length;
    const decisions = (ATTRIBUTION_BANK.length +
      positiveCases * ATTRIBUTION_MAX_CALLS_PER_FINDING_SET) * 3;
    expect(decisions).toBe(501);
    expect(decisions * 6).toBeLessThanOrEqual(5_000);
    expect(Number(perDecision) * decisions).toBeCloseTo(15.859656, 9);
  });

  test("keeps evaluator labels and bank identifiers out of model requests", () => {
    for (const bankCase of ATTRIBUTION_BANK) {
      const request = JSON.stringify({
        model: "provider/scorer",
        expectedProvider: "PinnedProvider",
        target: bankCase.target,
        candidate: bankCase.candidate,
      });
      expect(request).not.toContain(bankCase.id);
      expect(request).not.toContain("expectedSameDefect");
    }
  });

  test("requires a separately authored bank with positive and adversarial negatives", () => {
    expect(ATTRIBUTION_BANK.length).toBeGreaterThanOrEqual(20);
    expect(ATTRIBUTION_BANK.some((entry) => entry.expectedSameDefect)).toBe(true);
    expect(ATTRIBUTION_BANK.some((entry) => !entry.expectedSameDefect)).toBe(true);
    expect(new Set(ATTRIBUTION_BANK.map((entry) => entry.id)).size).toBe(ATTRIBUTION_BANK.length);
    for (const required of [
      "explicit-contradiction",
      "successful-remediation",
      "hypothetical",
      "counterfactual",
      "metadata-column",
      "broad-range-generic",
      "authorization-cross-tenant-equivalence",
      "concurrency-lost-update-equivalence",
      "advisory-uncertainty-same-mechanism",
      "instruction-bearing-unrelated-body",
      "long-mixed-evidence-active-defect",
      "content-policy-same-anchor-unrelated",
    ]) {
      expect(ATTRIBUTION_BANK.some((entry) => entry.id === required)).toBe(true);
    }
    expect(new Set(ATTRIBUTION_BANK.map((entry) => entry.target.path)).size).toBeGreaterThanOrEqual(6);
    expect(new Set(ATTRIBUTION_BANK.map((entry) => entry.candidate.kind)).size).toBeGreaterThanOrEqual(5);
    expect(new Set(ATTRIBUTION_BANK.map((entry) => entry.candidate.severity)).size).toBe(3);
    expect(ATTRIBUTION_BANK.find((entry) => entry.id === "instruction-bearing-unrelated-body")?.expectedSameDefect)
      .toBe(false);
  });

  test("deep-freezes every authored bank field", () => {
    const bankCase = ATTRIBUTION_BANK[0]!;
    const mutations = [
      () => { (ATTRIBUTION_BANK as AttributionBankCase[]).push(bankCase); },
      () => { (bankCase as { id: string }).id = "mutated"; },
      () => { (bankCase as { expectedSameDefect: boolean }).expectedSameDefect = false; },
      () => { (bankCase.target as { path: string }).path = "mutated"; },
      () => { (bankCase.target as { startLine: number }).startLine = 1; },
      () => { (bankCase.target as { endLine: number }).endLine = 2; },
      () => { (bankCase.target as { contract: string }).contract = "mutated"; },
      () => { (bankCase.candidate as { path: string }).path = "mutated"; },
      () => { (bankCase.candidate as { line: number }).line = 1; },
      () => { (bankCase.candidate as { endLine: number }).endLine = 2; },
      () => { (bankCase.candidate as { severity: string }).severity = "warn"; },
      () => { (bankCase.candidate as { kind: string }).kind = "other"; },
      () => { (bankCase.candidate as { title: string }).title = "mutated"; },
      () => { (bankCase.candidate as { body: string }).body = "mutated"; },
    ];
    for (const mutate of mutations) expect(mutate).toThrow(TypeError);
  });

  test("removes per-call source files after success and failure", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-attribution-cleanup-"));
    const binary = join(root, "fake-atomic-attribution.ts");
    const runDir = join(root, "run");
    try {
      await writeFile(binary, `#!/usr/bin/env bun
import { readFile } from "node:fs/promises";
const request = JSON.parse(await readFile(process.argv.at(-1), "utf8"));
const raw = JSON.stringify({ sameDefect: true, reason: "Both identify the same retry bypass." });
console.log(JSON.stringify({ sameDefect: true, reason: "Both identify the same retry bypass.", model: request.model, provider: request.expectedProvider, responseIdentities: [{ model: request.model, provider: request.expectedProvider }], apiFormat: "openai-compatible", settings: { temperature: 0, maxTokens: 180, schemaRepairs: 1 }, rawResponses: [raw], modelUsage: [{ model: request.model, role: "findingScorer", phase: "initial", callOrdinal: 1, attempt: 1, promptTokens: 10, completionTokens: 5, costMicros: 100, costProviderDecimal: "0.0001", costSource: "providerReported", accountingComplete: true }], usageAccountingComplete: true }));
`);
      await chmod(binary, 0o700);
      const options = {
        binary,
        runDir,
        env: process.env,
        sourceSha256: "a".repeat(64),
        binarySha256: "b".repeat(64),
        evaluatorModel: "provider/scorer",
        expectedProvider: "PinnedProvider",
        apiFormat: "openai-compatible" as const,
        repeat: 1,
        governor: new AttributionGovernor(),
        projectedCostUsdDecimal: "0.01",
      };
      expect((await attributeCandidates(target, [candidate], options)).scored).toBe(true);
      await expect(access(join(runDir, "candidate-0", "request.json"))).rejects.toThrow();
      const capped = await attributeCandidates(
        target,
        Array.from({ length: ATTRIBUTION_MAX_CALLS_PER_FINDING_SET }, (_, index) => ({
          ...candidate,
          title: `Candidate ${index}`,
        })),
        options,
      );
      expect(capped.scored).toBe(true);
      expect(capped.calls).toHaveLength(ATTRIBUTION_MAX_CALLS_PER_FINDING_SET);
      expect((await attributeCandidates(target, [candidate], { ...options, binary: join(root, "missing") })).scored).toBe(false);
      await expect(access(join(runDir, "candidate-0", "request.json"))).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("reports a bounded subprocess category without exposing stderr", async () => {
    const root = await mkdtemp(join(tmpdir(), "postil-attribution-diagnostic-"));
    const binary = join(root, "fake-failed-attribution.ts");
    try {
      await writeFile(binary, `#!/usr/bin/env bun
process.stderr.write("private-prompt-and-response ".repeat(100));
process.stderr.write("\\npostil: llm response phase=attribution status=200\\n");
process.stderr.write("postil: error: atomic attribution failed: atomic attribution output invalid after schema repair: invalid reason\\n");
process.exit(1);
`);
      await chmod(binary, 0o700);
      const result = await attributeCandidates(target, [candidate], {
        binary,
        runDir: join(root, "run"),
        env: process.env,
        sourceSha256: "a".repeat(64),
        binarySha256: "b".repeat(64),
        evaluatorModel: "provider/scorer",
        expectedProvider: "PinnedProvider",
        apiFormat: "openai-compatible",
        repeat: 1,
        governor: new AttributionGovernor(),
        projectedCostUsdDecimal: "0.01",
      });
      expect(result.error).toBe(
        "atomic attribution transport failed: category=output-invalid-after-schema-repair exit=1 signal=none killed=false",
      );
      expect(result.error).not.toContain("private-prompt-and-response");
      expect(result.error).not.toContain("invalid reason");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("enforces one global concurrency, provider-call, and spend budget", async () => {
    const governor = new AttributionGovernor(2, 100, 0.02);
    let active = 0;
    let maximumActive = 0;
    const usage = [{
      model: "provider/scorer",
      role: "findingScorer" as const,
      phase: "initial" as const,
      callOrdinal: 1,
      attempt: 1,
      promptTokens: 10,
      completionTokens: 5,
      costProviderDecimal: "0.001",
      costSource: "providerReported" as const,
      accountingComplete: true as const,
    }];
    await Promise.all([0, 1].map((value) => governor.run("0.005", async () => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await Bun.sleep(10);
      active -= 1;
      return { value, usage };
    })));
    expect(maximumActive).toBe(2);
    expect(governor.actualCalls).toBe(2);
    expect(governor.actualSpendUsd).toBeCloseTo(0.002, 8);
    expect(governor.actualSpendUsdDecimal).toBe("0.002");
    expect(governor.failedExposureUsdDecimal).toBe("0");
    const callGovernor = new AttributionGovernor(1, 7, 1);
    await callGovernor.run("0.005", async () => ({ value: 1, usage }));
    await callGovernor.run("0.005", async () => ({ value: 2, usage }));
    await expect(callGovernor.run("0.005", async () => ({ value: 3, usage })))
      .rejects.toThrow("provider-call cap exhausted");

    const spendGovernor = new AttributionGovernor(1, 100, 0.004);
    await expect(spendGovernor.run("0.005", async () => ({ value: 1, usage })))
      .rejects.toThrow("spend cap exhausted");

    const failedGovernor = new AttributionGovernor(1, 100, "0.02");
    await expect(failedGovernor.run("0.005", async () => {
      throw new Error("provider failed without usage");
    })).rejects.toThrow("provider failed without usage");
    expect(failedGovernor.actualSpendUsdDecimal).toBe("0");
    expect(failedGovernor.failedExposureUsdDecimal).toBe("0.005");
    expect(failedGovernor.conservativeExposureUsdDecimal).toBe("0.005");
  });

  test("replays fenced raw evidence offline and rejects tampering", () => {
    const raw = "```json\n{\"sameDefect\":true,\"reason\":\"Both identify the same retry bypass.\"}\n```";
    const request = { model: "provider/scorer", expectedProvider: "PinnedProvider", target, candidate };
    const modelUsage = [{
      model: request.model,
      role: "findingScorer" as const,
      phase: "initial" as const,
      callOrdinal: 1,
      attempt: 1,
      promptTokens: 100,
      completionTokens: 20,
      costMicros: 100,
      costProviderDecimal: "0.0001",
      costSource: "providerReported" as const,
      accountingComplete: true as const,
    }];
    const material: Omit<AttributionCallEvidence, "evidenceSha256"> = {
      version: ATTRIBUTION_CONTRACT_VERSION,
      bankVersion: 2,
      sourceSha256: "a".repeat(64),
      binarySha256: "b".repeat(64),
      contractSha256: attributionContractSha256(),
      bankSha256: attributionBankSha256(),
      model: request.model,
      provider: request.expectedProvider,
      responseIdentities: [{ model: request.model, provider: request.expectedProvider }],
      apiFormat: "openai-compatible",
      settings: ATTRIBUTION_SETTINGS,
      repeat: 1,
      candidateOrdinal: 1,
      request,
      requestSha256: hash(request),
      rawResponses: [raw],
      responseSha256: [hash(raw)],
      modelUsage,
      usageSha256: hash(modelUsage),
      sameDefect: true,
      reason: "Both identify the same retry bypass.",
    };
    const evidence = { ...material, evidenceSha256: attributionEvidenceSha256(material) };
    expect(replayAttributionEvidence(evidence)).toBe(true);
    expect(replayAttributionEvidence({ ...evidence, sameDefect: false })).toBe(false);
    expect(replayAttributionEvidence({ ...evidence, rawResponses: [raw.replace("true", "false")] })).toBe(false);
    const substitutedMaterial = {
      ...material,
      provider: "substituted-provider",
      responseIdentities: [{ model: request.model, provider: "substituted-provider" }],
    };
    expect(replayAttributionEvidence({
      ...substitutedMaterial,
      evidenceSha256: attributionEvidenceSha256(substitutedMaterial),
    })).toBe(false);

    type MutableEvidence = AttributionCallEvidence & { unexpected?: boolean };
    const rehash = (mutate: (copy: MutableEvidence) => void) => {
      const copy = structuredClone(evidence) as MutableEvidence;
      mutate(copy);
      copy.requestSha256 = hash(copy.request);
      copy.responseSha256 = copy.rawResponses.map(hash);
      copy.usageSha256 = hash(copy.modelUsage);
      const { evidenceSha256: ignored, ...materialCopy } = copy;
      void ignored;
      copy.evidenceSha256 = attributionEvidenceSha256(materialCopy as Omit<AttributionCallEvidence, "evidenceSha256">);
      return copy as unknown as AttributionCallEvidence;
    };
    const invalidEvidence = [
      rehash((copy) => { copy.candidateOrdinal = 0; }),
      rehash((copy) => { copy.modelUsage[0]!.callOrdinal = 0; }),
      rehash((copy) => { copy.modelUsage[0]!.attempt = 0; }),
      rehash((copy) => { copy.modelUsage[0]!.promptTokens = -1; }),
      rehash((copy) => { copy.modelUsage[0]!.costMicros = 101; }),
      rehash((copy) => { copy.modelUsage[0]!.costProviderDecimal = "0.00010"; }),
      rehash((copy) => {
        (copy.modelUsage[0]! as { costSource: string }).costSource = "catalogEstimate";
      }),
      rehash((copy) => {
        (copy.modelUsage[0]! as { accountingComplete: boolean }).accountingComplete = false;
      }),
      rehash((copy) => { copy.responseIdentities[0]!.provider = "substituted-provider"; }),
      rehash((copy) => { copy.unexpected = true; }),
    ];
    for (const invalid of invalidEvidence) expect(replayAttributionEvidence(invalid)).toBe(false);
  });
});

function hash(value: unknown): string {
  return createHash("sha256").update(typeof value === "string" ? value : canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}
