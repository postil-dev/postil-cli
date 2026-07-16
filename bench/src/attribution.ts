import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import { ATTRIBUTION_BANK, ATTRIBUTION_BANK_VERSION, type AttributionBankCase } from "../fixtures/attribution-bank";
import {
  compareCanonicalDecimals,
  formatCanonicalDecimal,
  MAX_GENERATOR_COST_CAP_USD,
  parseCanonicalDecimal,
  sumCanonicalDecimals,
  type CanonicalDecimal,
} from "./livemodels-score";

const execFile = promisify(execFileCallback);

export const ATTRIBUTION_CONTRACT_VERSION = 2;
export const ATTRIBUTION_MAX_CONCURRENCY = 4;
export const ATTRIBUTION_CALL_TIMEOUT_MS = 60_000;
export const ATTRIBUTION_MAX_CALLS_PER_FINDING_SET = 3;
export const ATTRIBUTION_MAX_PROVIDER_CALLS = 5_000;
export const ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION = 6;
export const ATTRIBUTION_MAX_INPUT_BYTES = 4 * 1024;
export const ATTRIBUTION_MAX_PROVIDER_REQUEST_BYTES = 5_000;
export const ATTRIBUTION_SETTINGS = Object.freeze({ temperature: 0, maxTokens: 180, schemaRepairs: 1 });

export interface AttributionTarget {
  path: string;
  startLine: number;
  endLine: number;
  contract: string;
}

export interface AttributionCandidate {
  path: string;
  line: number;
  endLine: number;
  severity: string;
  kind: string;
  title: string;
  body: string;
}

export interface AttributionRequest {
  model: string;
  expectedProvider: string;
  target: AttributionTarget;
  candidate: AttributionCandidate;
}

const modelUsage = z.object({
  model: z.string().min(1),
  role: z.literal("findingScorer"),
  phase: z.enum(["initial", "schemaRepair"]),
  callOrdinal: z.number().int().positive(),
  attempt: z.number().int().positive(),
  promptTokens: z.number().int().nonnegative(),
  completionTokens: z.number().int().nonnegative(),
  costMicros: z.number().int().nonnegative().optional(),
  costProviderDecimal: z.string().refine((value) => {
    try {
      parseCanonicalDecimal(value);
      return true;
    } catch {
      return false;
    }
  }, "provider cost must be canonical"),
  costSource: z.literal("providerReported"),
  accountingComplete: z.literal(true),
}).strict().superRefine((usage, context) => {
  const rounded = providerCostMicrosRounded(usage.costProviderDecimal);
  if (
    usage.costMicros !== undefined &&
    rounded !== null &&
    BigInt(usage.costMicros) !== rounded
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["costMicros"],
      message: "rounded provider cost does not match exact provider cost",
    });
  }
});

function providerCostMicrosRounded(value: string): bigint | null {
  let parsed: CanonicalDecimal;
  try {
    parsed = parseCanonicalDecimal(value);
  } catch {
    return null;
  }
  if (parsed.scale <= 6) {
    return parsed.coefficient * 10n ** BigInt(6 - parsed.scale);
  }
  const divisor = 10n ** BigInt(parsed.scale - 6);
  const quotient = parsed.coefficient / divisor;
  const remainder = parsed.coefficient % divisor;
  return quotient + (remainder * 2n >= divisor ? 1n : 0n);
}

const transportOutput = z.object({
  sameDefect: z.boolean(),
  reason: z.string().trim().min(1).max(240),
  model: z.string().min(1),
  provider: z.string().trim().min(1),
  responseIdentities: z.array(z.object({
    model: z.string().trim().min(1),
    provider: z.string().trim().min(1),
  }).strict()).min(1).max(2),
  apiFormat: z.enum(["openai-compatible", "anthropic"]),
  settings: z.object({
    temperature: z.literal(0),
    maxTokens: z.literal(180),
    schemaRepairs: z.literal(1),
  }).strict(),
  rawResponses: z.array(z.string().min(1)).min(1).max(2),
  modelUsage: z.array(modelUsage).min(1).max(2),
  usageAccountingComplete: z.literal(true),
}).strict();

const verdict = z.object({
  sameDefect: z.boolean(),
  reason: z.string().trim().min(1).max(240),
}).strict();

export type AttributionTransportOutput = z.infer<typeof transportOutput>;

export interface AttributionCallEvidence {
  version: typeof ATTRIBUTION_CONTRACT_VERSION;
  bankVersion: typeof ATTRIBUTION_BANK_VERSION;
  sourceSha256: string;
  binarySha256: string;
  contractSha256: string;
  bankSha256: string;
  model: string;
  provider: string;
  responseIdentities: Array<{ model: string; provider: string }>;
  apiFormat: "openai-compatible" | "anthropic";
  settings: typeof ATTRIBUTION_SETTINGS;
  repeat: number;
  candidateOrdinal: number;
  request: AttributionRequest;
  requestSha256: string;
  rawResponses: string[];
  responseSha256: string[];
  modelUsage: z.infer<typeof modelUsage>[];
  usageSha256: string;
  sameDefect: boolean;
  reason: string;
  evidenceSha256: string;
}

export interface AttributionCaseEvidence {
  scored: boolean;
  detected: boolean;
  calls: AttributionCallEvidence[];
  error?: string;
}

export interface AttributionTransportOptions {
  binary: string;
  runDir: string;
  env: NodeJS.ProcessEnv;
  sourceSha256: string;
  binarySha256: string;
  evaluatorModel: string;
  expectedProvider: string;
  apiFormat: "openai-compatible" | "anthropic";
  repeat: number;
  timeoutMs?: number;
  governor: AttributionGovernor;
  projectedCostUsdDecimal: string;
}

const attributionTargetSchema = z.object({
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  contract: z.string().min(1),
}).strict().refine((target) => target.endLine >= target.startLine);

const attributionCandidateSchema = z.object({
  path: z.string().min(1),
  line: z.number().int().positive(),
  endLine: z.number().int().positive(),
  severity: z.string().min(1),
  kind: z.string().min(1),
  title: z.string().min(1),
  body: z.string().min(1),
}).strict().refine((candidate) => candidate.endLine >= candidate.line);

const attributionEvidenceRuntimeSchema = z.object({
  version: z.literal(ATTRIBUTION_CONTRACT_VERSION),
  bankVersion: z.literal(ATTRIBUTION_BANK_VERSION),
  sourceSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  binarySha256: z.string().regex(/^[0-9a-f]{64}$/u),
  contractSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  bankSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  model: z.string().min(1),
  provider: z.string().min(1),
  responseIdentities: z.array(z.object({ model: z.string().min(1), provider: z.string().min(1) }).strict()).min(1).max(2),
  apiFormat: z.enum(["openai-compatible", "anthropic"]),
  settings: z.object({ temperature: z.literal(0), maxTokens: z.literal(180), schemaRepairs: z.literal(1) }).strict(),
  repeat: z.number().int().positive(),
  candidateOrdinal: z.number().int().positive(),
  request: z.object({
    model: z.string().min(1),
    expectedProvider: z.string().min(1),
    target: attributionTargetSchema,
    candidate: attributionCandidateSchema,
  }).strict(),
  requestSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  rawResponses: z.array(z.string().min(1)).min(1).max(2),
  responseSha256: z.array(z.string().regex(/^[0-9a-f]{64}$/u)).min(1).max(2),
  modelUsage: z.array(modelUsage).min(1).max(2),
  usageSha256: z.string().regex(/^[0-9a-f]{64}$/u),
  sameDefect: z.boolean(),
  reason: z.string().trim().min(1).max(240),
  evidenceSha256: z.string().regex(/^[0-9a-f]{64}$/u),
}).strict();

export class AttributionGovernor {
  readonly callCap: number;
  readonly spendCapUsd: number;
  #active = 0;
  #reservedCalls = 0;
  #reservedSpend = parseCanonicalDecimal("0");
  #actualCalls = 0;
  #actualSpend = parseCanonicalDecimal("0");
  #spentExposure = parseCanonicalDecimal("0");
  #failedExposure = parseCanonicalDecimal("0");
  #waiters: Array<() => void> = [];

  constructor(
    readonly concurrency = ATTRIBUTION_MAX_CONCURRENCY,
    callCap = ATTRIBUTION_MAX_PROVIDER_CALLS,
    spendCapUsd: string | number = String(MAX_GENERATOR_COST_CAP_USD),
  ) {
    if (!Number.isSafeInteger(concurrency) || concurrency < 1) throw new Error("invalid attribution concurrency cap");
    if (!Number.isSafeInteger(callCap) || callCap < 1) throw new Error("invalid attribution provider-call cap");
    const spendCap = parseCanonicalDecimal(String(spendCapUsd));
    if (compareCanonicalDecimals(spendCap, parseCanonicalDecimal("0")) <= 0) throw new Error("invalid attribution spend cap");
    this.callCap = callCap;
    this.spendCapUsd = Number(formatCanonicalDecimal(spendCap));
    this.#spendCap = spendCap;
  }

  get actualCalls(): number { return this.#actualCalls; }
  readonly #spendCap: CanonicalDecimal;
  get actualSpendUsd(): number { return Number(this.actualSpendUsdDecimal); }
  get actualSpendUsdDecimal(): string { return formatCanonicalDecimal(this.#actualSpend); }
  get failedExposureUsdDecimal(): string { return formatCanonicalDecimal(this.#failedExposure); }
  get conservativeExposureUsdDecimal(): string { return formatCanonicalDecimal(this.#spentExposure); }

  async run<T>(projectedCostUsdDecimal: string, work: () => Promise<{ value: T; usage: z.infer<typeof modelUsage>[] }>): Promise<T> {
    const projectedCost = parseCanonicalDecimal(projectedCostUsdDecimal);
    if (compareCanonicalDecimals(projectedCost, parseCanonicalDecimal("0")) <= 0) throw new Error("atomic attribution projected cost must be positive");
    if (this.#actualCalls + this.#reservedCalls + ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION > this.callCap) {
      throw new Error("atomic attribution global provider-call cap exhausted");
    }
    if (compareCanonicalDecimals(sumCanonicalDecimals([this.#spentExposure, this.#reservedSpend, projectedCost]), this.#spendCap) > 0) {
      throw new Error("atomic attribution global spend cap exhausted");
    }
    this.#reservedCalls += ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION;
    this.#reservedSpend = sumCanonicalDecimals([this.#reservedSpend, projectedCost]);
    await this.#acquire();
    let completed = false;
    let usageObserved = false;
    try {
      const result = await work();
      const actualCost = sumCanonicalDecimals(result.usage.map((usage) => parseCanonicalDecimal(usage.costProviderDecimal)));
      this.#actualCalls += result.usage.length;
      this.#actualSpend = sumCanonicalDecimals([this.#actualSpend, actualCost]);
      this.#spentExposure = sumCanonicalDecimals([this.#spentExposure, actualCost]);
      usageObserved = true;
      if (this.#actualCalls > this.callCap || compareCanonicalDecimals(this.#spentExposure, this.#spendCap) > 0) {
        throw new Error("atomic attribution actual provider usage exceeded its global cap");
      }
      this.#reservedCalls -= ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION;
      this.#reservedSpend = subtractCanonicalDecimal(this.#reservedSpend, projectedCost);
      completed = true;
      return result.value;
    } finally {
      if (!completed) {
        this.#reservedCalls -= ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION;
        this.#reservedSpend = subtractCanonicalDecimal(this.#reservedSpend, projectedCost);
        if (!usageObserved) {
          this.#actualCalls += ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION;
          this.#spentExposure = sumCanonicalDecimals([this.#spentExposure, projectedCost]);
          this.#failedExposure = sumCanonicalDecimals([this.#failedExposure, projectedCost]);
        }
      }
      this.#release();
    }
  }

  async #acquire(): Promise<void> {
    if (this.#active < this.concurrency) {
      this.#active += 1;
      return;
    }
    await new Promise<void>((resolve) => this.#waiters.push(resolve));
    this.#active += 1;
  }

  #release(): void {
    this.#active -= 1;
    this.#waiters.shift()?.();
  }
}

export function projectedAttributionDecisionCostUsd(pricing: { inputMicrosPerMillionTokens: number; outputMicrosPerMillionTokens: number }): string {
  const micros = BigInt(ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION) * (
    divideCeiling(BigInt(ATTRIBUTION_MAX_PROVIDER_REQUEST_BYTES) * BigInt(pricing.inputMicrosPerMillionTokens), 1_000_000n) +
    divideCeiling(BigInt(ATTRIBUTION_SETTINGS.maxTokens) * BigInt(pricing.outputMicrosPerMillionTokens), 1_000_000n)
  );
  return canonicalUsdFromMicros(micros);
}

function subtractCanonicalDecimal(left: CanonicalDecimal, right: CanonicalDecimal): CanonicalDecimal {
  const scale = Math.max(left.scale, right.scale);
  const coefficient = left.coefficient * 10n ** BigInt(scale - left.scale) -
    right.coefficient * 10n ** BigInt(scale - right.scale);
  if (coefficient < 0n) throw new Error("canonical decimal subtraction underflow");
  if (coefficient === 0n) return parseCanonicalDecimal("0");
  return parseCanonicalDecimal(formatCanonicalDecimal({ coefficient, scale }));
}

function divideCeiling(numerator: bigint, denominator: bigint): bigint {
  return (numerator + denominator - 1n) / denominator;
}

function canonicalUsdFromMicros(micros: bigint): string {
  const whole = micros / 1_000_000n;
  const fraction = (micros % 1_000_000n).toString().padStart(6, "0").replace(/0+$/u, "");
  return formatCanonicalDecimal(parseCanonicalDecimal(fraction.length === 0 ? whole.toString() : `${whole}.${fraction}`));
}

export function attributionContractSha256(): string {
  return digest({
    version: ATTRIBUTION_CONTRACT_VERSION,
    question: "same underlying faulty mechanism and material consequence",
    negatives: ["unrelated", "contradiction", "successful remediation", "hypothetical", "counterfactual", "metadata", "unsupported broad claim"],
    settings: ATTRIBUTION_SETTINGS,
    maxCallsPerFindingSet: ATTRIBUTION_MAX_CALLS_PER_FINDING_SET,
    maxProviderAttemptsPerDecision: ATTRIBUTION_MAX_PROVIDER_ATTEMPTS_PER_DECISION,
    maxInputBytes: ATTRIBUTION_MAX_INPUT_BYTES,
    maxProviderRequestBytes: ATTRIBUTION_MAX_PROVIDER_REQUEST_BYTES,
  });
}

export function attributionBankSha256(): string {
  return digest({ version: ATTRIBUTION_BANK_VERSION, cases: ATTRIBUTION_BANK });
}

export function exactRegionOverlap(candidate: AttributionCandidate, target: AttributionTarget): boolean {
  return candidate.path === target.path && candidate.line >= target.startLine && candidate.line <= target.endLine;
}

export async function attributeCandidates(
  target: AttributionTarget | null,
  candidates: AttributionCandidate[],
  options: AttributionTransportOptions,
): Promise<AttributionCaseEvidence> {
  if (target === null) {
    return candidates.length === 0
      ? { scored: true, detected: false, calls: [] }
      : { scored: true, detected: false, calls: [] };
  }
  const matching = candidates
    .map((candidate, candidateOrdinal) => ({ candidate, candidateOrdinal }))
    .filter(({ candidate }) => exactRegionOverlap(candidate, target));
  if (matching.length === 0) return { scored: true, detected: false, calls: [] };
  if (matching.length > ATTRIBUTION_MAX_CALLS_PER_FINDING_SET) {
    return { scored: false, detected: false, calls: [], error: "attribution candidate count exceeds the fixed call cap" };
  }
  try {
    const calls = await mapBounded(matching, ATTRIBUTION_MAX_CONCURRENCY, async ({ candidate, candidateOrdinal }) =>
      runAtomicAttribution(
        { model: options.evaluatorModel, expectedProvider: options.expectedProvider, target, candidate },
        candidateOrdinal + 1,
        { ...options, runDir: join(options.runDir, `candidate-${candidateOrdinal}`) },
      ));
    return { scored: true, detected: calls.some((call) => call.sameDefect), calls };
  } catch (error) {
    return { scored: false, detected: false, calls: [], error: boundedError(error) };
  }
}

export async function qualifyAttributionEvaluator(
  options: Omit<AttributionTransportOptions, "repeat" | "runDir"> & { rootDir: string; repeats: number },
): Promise<{ eligible: boolean; evidence: AttributionCallEvidence[]; evidenceSha256: string }> {
  if (!Number.isSafeInteger(options.repeats) || options.repeats < 3 || options.repeats > 10) {
    throw new Error("attribution evaluator eligibility requires 3..10 repeats");
  }
  const jobs: Array<{ bankCase: AttributionBankCase; repeat: number; ordinal: number }> = [];
  for (let repeat = 1; repeat <= options.repeats; repeat += 1) {
    ATTRIBUTION_BANK.forEach((bankCase, ordinal) => jobs.push({ bankCase, repeat, ordinal }));
  }
  const evidence = await mapBounded(jobs, ATTRIBUTION_MAX_CONCURRENCY, async ({ bankCase, repeat, ordinal }) => {
    const runDir = join(options.rootDir, "attribution-bank", `repeat-${repeat}`, safeSegment(bankCase.id));
    return runAtomicAttribution(
      { model: options.evaluatorModel, expectedProvider: options.expectedProvider, target: bankCase.target, candidate: bankCase.candidate },
      ordinal + 1,
      { ...options, repeat, runDir },
    );
  });
  const eligible = evidence.length === jobs.length && evidence.every((call, index) => {
    const expected = jobs[index]?.bankCase.expectedSameDefect;
    return expected !== undefined && call.sameDefect === expected;
  });
  return { eligible, evidence, evidenceSha256: digest(evidence.map((call) => call.evidenceSha256)) };
}

export function replayAttributionEvidence(evidence: AttributionCallEvidence): boolean {
  const runtimeEvidence = attributionEvidenceRuntimeSchema.safeParse(evidence);
  if (!runtimeEvidence.success) return false;
  evidence = runtimeEvidence.data as AttributionCallEvidence;
  if (evidence.version !== ATTRIBUTION_CONTRACT_VERSION || evidence.bankVersion !== ATTRIBUTION_BANK_VERSION) return false;
  if (![evidence.sourceSha256, evidence.binarySha256].every(isSha256)) return false;
  if (evidence.contractSha256 !== attributionContractSha256() || evidence.bankSha256 !== attributionBankSha256()) return false;
  if (evidence.model !== evidence.request.model || evidence.provider !== evidence.request.expectedProvider || !exactRegionOverlap(evidence.request.candidate, evidence.request.target)) return false;
  if (!Number.isSafeInteger(evidence.repeat) || evidence.repeat < 1) return false;
  if (!Number.isSafeInteger(evidence.candidateOrdinal) || evidence.candidateOrdinal < 1) return false;
  if (JSON.stringify(evidence.settings) !== JSON.stringify(ATTRIBUTION_SETTINGS)) return false;
  if (evidence.requestSha256 !== digest(evidence.request)) return false;
  if (evidence.rawResponses.length < 1 || evidence.rawResponses.length > 2) return false;
  if (evidence.responseSha256.length !== evidence.rawResponses.length || evidence.modelUsage.length !== evidence.rawResponses.length) return false;
  if (evidence.responseIdentities.length !== evidence.rawResponses.length ||
      !evidence.responseIdentities.every((identity) => identity.model === evidence.model && identity.provider === evidence.provider)) return false;
  if (!evidence.rawResponses.every((raw, index) => digest(raw) === evidence.responseSha256[index])) return false;
  if (!evidence.modelUsage.every((usage, index) =>
    usage.model === evidence.model &&
    usage.role === "findingScorer" &&
    usage.phase === (index === 0 ? "initial" : "schemaRepair") &&
    usage.accountingComplete)) return false;
  if (evidence.usageSha256 !== digest(evidence.modelUsage)) return false;
  const parsed = verdict.safeParse(parseFirstJsonObject(evidence.rawResponses.at(-1)!));
  if (!parsed.success || parsed.data.sameDefect !== evidence.sameDefect || parsed.data.reason !== evidence.reason) return false;
  const { evidenceSha256: ignored, ...material } = evidence;
  void ignored;
  return evidence.evidenceSha256 === digest(material);
}

export function attributionEvidenceSha256(
  material: Omit<AttributionCallEvidence, "evidenceSha256">,
): string {
  return digest(material);
}

async function runAtomicAttribution(
  request: AttributionRequest,
  candidateOrdinal: number,
  options: AttributionTransportOptions,
): Promise<AttributionCallEvidence> {
  await rm(options.runDir, { recursive: true, force: true });
  await mkdir(options.runDir, { recursive: true, mode: 0o700 });
  try {
    return await options.governor.run(options.projectedCostUsdDecimal, async () => {
      const inputPath = join(options.runDir, "request.json");
      await writeFile(inputPath, JSON.stringify(request), { mode: 0o600 });
      let stdout = "";
      try {
        const result = await execFile(
          options.binary,
          ["atomic-attribution", "--input", inputPath],
          {
            cwd: options.runDir,
            env: options.env,
            timeout: options.timeoutMs ?? ATTRIBUTION_CALL_TIMEOUT_MS,
            maxBuffer: 1024 * 1024,
          },
        );
        stdout = result.stdout;
      } catch (error) {
        throw new Error(`atomic attribution transport failed: ${boundedError(error)}`);
      }
      const output = transportOutput.parse(JSON.parse(stdout));
      if (output.model !== options.evaluatorModel || output.provider !== options.expectedProvider ||
          output.apiFormat !== options.apiFormat) {
        throw new Error("atomic attribution model or provider identity mismatch");
      }
      if (JSON.stringify(output.settings) !== JSON.stringify(ATTRIBUTION_SETTINGS)) {
        throw new Error("atomic attribution settings mismatch");
      }
      if (output.rawResponses.length !== output.modelUsage.length) {
        throw new Error("atomic attribution raw response and usage cardinality mismatch");
      }
      if (output.responseIdentities.length !== output.rawResponses.length ||
          !output.responseIdentities.every((identity) =>
            identity.model === options.evaluatorModel && identity.provider === options.expectedProvider)) {
        throw new Error("atomic attribution response identity mismatch");
      }
      if (!output.modelUsage.every((usage) =>
        usage.model === options.evaluatorModel && usage.accountingComplete)) {
        throw new Error("atomic attribution usage identity mismatch");
      }
      const finalVerdict = verdict.parse(parseFirstJsonObject(output.rawResponses.at(-1)!));
      if (finalVerdict.sameDefect !== output.sameDefect || finalVerdict.reason !== output.reason) {
        throw new Error("atomic attribution parsed verdict does not match raw response");
      }
      const material = {
        version: ATTRIBUTION_CONTRACT_VERSION,
        bankVersion: ATTRIBUTION_BANK_VERSION,
        sourceSha256: options.sourceSha256,
        binarySha256: options.binarySha256,
        contractSha256: attributionContractSha256(),
        bankSha256: attributionBankSha256(),
        model: output.model,
        provider: output.provider,
        responseIdentities: output.responseIdentities,
        apiFormat: output.apiFormat,
        settings: ATTRIBUTION_SETTINGS,
        repeat: options.repeat,
        candidateOrdinal,
        request,
        requestSha256: digest(request),
        rawResponses: output.rawResponses,
        responseSha256: output.rawResponses.map(digest),
        modelUsage: output.modelUsage,
        usageSha256: digest(output.modelUsage),
        sameDefect: output.sameDefect,
        reason: output.reason,
      } satisfies Omit<AttributionCallEvidence, "evidenceSha256">;
      const evidence = { ...material, evidenceSha256: attributionEvidenceSha256(material) };
      if (!replayAttributionEvidence(evidence)) {
        throw new Error("atomic attribution evidence failed offline replay");
      }
      return { value: Object.freeze(evidence), usage: output.modelUsage };
    });
  } finally {
    await rm(options.runDir, { recursive: true, force: true });
  }
}

async function mapBounded<T, R>(items: readonly T[], concurrency: number, work: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const worker = async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await work(items[index]!);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length || 1)) }, worker));
  return results;
}

function digest(value: unknown): string {
  const bytes = typeof value === "string" ? value : canonicalJson(value);
  return createHash("sha256").update(bytes).digest("hex");
}

function parseFirstJsonObject(value: string): unknown {
  const start = value.indexOf("{");
  if (start < 0) throw new Error("atomic attribution raw response contains no JSON object");
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < value.length; index += 1) {
    const character = value[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") inString = false;
      continue;
    }
    if (character === "\"") inString = true;
    else if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return JSON.parse(value.slice(start, index + 1));
    }
  }
  throw new Error("atomic attribution raw response contains an incomplete JSON object");
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/u.test(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

function boundedError(error: unknown): string {
  const value = error instanceof Error ? error.message : String(error);
  return value.replace(/[\r\n\p{Cc}]+/gu, " ").slice(0, 500);
}

function safeSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/gu, "_").slice(0, 100);
}
