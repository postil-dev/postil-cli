#!/usr/bin/env bun
// CLI entry point.
//
// Mock mode (default, CI path): runs all cases against a release build with a
// mock forge and a mock model; it measures pipeline fidelity, not detection.
//
//   bun run bench [--json] [--json-out <path>]
//
// Live-models mode (opt-in, NOT run in CI, spends real tokens): keeps the
// per-case mock GitHub API but points the CLI at the selected provider endpoint,
// running each fixture repeatedly through exact generator/scorer pairs. It
// measures attributable detection and measured pair cost. Requires an inference
// key (POSTIL_API_KEY, OPENROUTER_API_KEY, MODEL_API_KEY, or LLM_API_KEY).
//
//   POSTIL_BENCH_MODE=live POSTIL_BENCH_PAIRS=generator::scorer \
//     MODEL_API_KEY=... bun run bench --json-out report.json
//
// Diff-file live mode (single model, no forge): measures detection with
// no mock GitHub at all. Selected by --live / BENCH_LIVE.
//
//   bun run bench:live              # or: BENCH_LIVE=1 bun run src/run.ts
//   bun run bench --live [--json] [--json-out <path>] [--model <id>] [--concurrency <n>]
//
// Environment:
//   POSTIL_BIN              path to the postil binary (default ../target/release/postil)
//   POSTIL_BENCH_KEEP_RUNS  set to 1 to keep run directories after a green run (mock mode)
//   POSTIL_BENCH_MODE       set to "live" to select live-models mode
//   POSTIL_BENCH_PAIRS      comma-separated generator::scorer model pairs
//   POSTIL_BENCH_REPEATS    complete matrix repetitions (admission requires at least 3)
//   POSTIL_API_BASE         provider API base (default https://openrouter.ai/api/v1)
//   POSTIL_API_FORMAT       provider interface (openai-compatible or anthropic)
//   POSTIL_BENCH_PRICING_FILE  exact-provider pricing for managed qualification
//   POSTIL_BENCH_PRIVATE_EVIDENCE_OUT  mode-0600 private replay bundle path
//   POSTIL_ENDPOINT_AUTH_HEADER additional private-gateway authentication header
//   POSTIL_ENDPOINT_AUTH_VALUE  value paired with POSTIL_ENDPOINT_AUTH_HEADER
//   MODEL_API_KEY           inference key for live modes; never printed
//   LLM_API_KEY             equivalent neutral inference-key alias
//   OPENROUTER_API_KEY      provider-specific inference-key alias
//   POSTIL_API_KEY          backward-compatible inference-key alias
//   REVIEW_MODEL            model id for diff-file live mode (else --model, else default)
//   BENCH_LIVE              set to 1 to select diff-file live mode
//   BENCH_CONCURRENCY       live-mode case parallelism (else --concurrency, else default)
//   POSTIL_BENCH_BOUNDED    set to 1 to qualify the bounded large-review path
//   POSTIL_BENCH_SCREEN_RUN_ID  optional live-screen artifact namespace
//   POSTIL_LLM_REQUEST_TIMEOUT_SECS  explicit per-request live-screen timeout
//   POSTIL_LLM_TOTAL_TIMEOUT_SECS    explicit total live-screen LLM timeout
//   --case <fixture-id>     repeatable non-admission fixture selection
//   --screen-profile <path> exact provider and price contract for selected cases
//   --scorer-model <id>     optional scorer for non-admission diff-file screening
//   --run-id <id>           optional live-screen artifact namespace

import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, rename, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { formatReport, runBenchmark, type BenchmarkCaseInput } from "./harness";
import { DEFAULT_LIVE_CONCURRENCY, formatLiveReport, runLive } from "./live";
import {
  DEFAULT_LIVE_CONCURRENCY as DEFAULT_LIVE_MODELS_CONCURRENCY,
  formatLiveModelsReport,
  liveModelsQualificationExitCode,
  MANAGED_OPENROUTER_PROVIDER_IDENTITY,
  managedAdmissionCapacityFailure,
  managedAdmissionCapacityFailureCategories,
  parseLiveModelsReport,
  parsePrivateEvidenceBundle,
  parseQualificationPairs,
  serializePrivateEvidenceBundle,
  runLiveModels,
  resolveQualificationSourceSha,
  pricingFromFile,
  verifyPrivateEvidenceBundle,
  type LiveModelsPrivateEvidenceBundle,
  type LiveModelsReport,
} from "./livemodels";
import {
  qualificationGeneratorModels,
  qualificationPairId,
  qualificationScorerModels,
  type QualificationPair,
} from "./livemodels-score";
import { atomicAttributionTransportFailure } from "./attribution";

const LIVE_MODELS_FAILURE_CATEGORIES = [
  "response-identity-missing",
  "response-identity-mismatch",
  "usage-accounting-incomplete",
  "output-invalid-after-schema-repair",
  "output-nonterminal-length",
  "invalid-output",
  "provider-request-too-large",
  "provider-timeout",
  "provider-deadline",
  "provider-transport",
  "provider-unclassified",
  "subprocess-timeout",
  "subprocess-signal",
  "subprocess-exit",
  ...managedAdmissionCapacityFailureCategories,
] as const;

type LiveModelsFailureCategory = typeof LIVE_MODELS_FAILURE_CATEGORIES[number] | `provider-http-${number}`;

export interface LiveModelsFailureReport {
  artifactType: "live-models-failure";
  qualificationSourceSha: string;
  profiles: Array<{
    id: string;
    generatorModels: string[];
    consensus: number;
    scorerModels: string[];
  }>;
  providerEndpointIdentity: typeof MANAGED_OPENROUTER_PROVIDER_IDENTITY;
  upstreamProviderIdentity: string;
  process: {
    category: LiveModelsFailureCategory;
    exitCode: number | null;
    signal: string | null;
    killed: boolean | null;
    phase: "attribution" | "preflight" | "unknown";
    providerAttemptCount: number | null;
    identityPresent: boolean | null;
    identityMatched: boolean | null;
    usagePresent: boolean | null;
    usageAccountingComplete: boolean | null;
  };
}

function flagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  const value = index === -1 ? undefined : args[index + 1];
  return value?.startsWith("--") === true ? undefined : value;
}

function repeatedFlagValues(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== flag) continue;
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${flag} requires a value`);
    }
    values.push(value);
    index += 1;
  }
  return values;
}

export function selectLiveScreeningCases(
  inputs: readonly BenchmarkCaseInput[],
  requestedIds: readonly string[],
): BenchmarkCaseInput[] {
  if (requestedIds.length === 0) return [...inputs];
  if (new Set(requestedIds).size !== requestedIds.length) {
    throw new Error("--case fixture IDs must not repeat");
  }
  const byId = new Map(inputs.map((input) => [input.id, input]));
  const unknown = requestedIds.filter((id) => !byId.has(id));
  if (unknown.length > 0) {
    throw new Error(`unknown --case fixture ID(s): ${unknown.join(", ")}`);
  }
  return requestedIds.map((id) => byId.get(id)!);
}

export function validateModeSpecificFlags(
  args: readonly string[],
  mode: "mock" | "live-screen" | "live-admission",
): void {
  for (const flag of ["--case", "--scorer-model", "--screen-profile", "--run-id"]) {
    if (!args.includes(flag)) continue;
    if (mode === "live-admission") {
      throw new Error(`${flag} is a non-admission diff-file screen option and is unavailable in live-models admission mode`);
    }
    if (mode === "mock") {
      throw new Error(`${flag} is available only with --live diff-file screening`);
    }
  }
}

export function validateRunIdentityEnvironment(
  runId: string | undefined,
  mode: "mock" | "live-screen" | "live-admission",
): void {
  if (runId !== undefined && mode !== "live-screen") {
    throw new Error("POSTIL_BENCH_SCREEN_RUN_ID is available only with --live diff-file screening");
  }
}

export function validateScreeningEnvironment(screenProfileEnv: string | undefined): void {
  if (screenProfileEnv !== undefined) {
    throw new Error(
      "POSTIL_BENCH_SCREEN_PROFILE is internal to a selected-case live screen; use --screen-profile with --live",
    );
  }
}

export function validateLiveScreenContract(
  selectedCaseIds: readonly string[],
  scorerModel: string | undefined,
  screenProfilePath: string | undefined,
): void {
  if (selectedCaseIds.length > 0 && screenProfilePath === undefined) {
    throw new Error("selected-case live screening requires --screen-profile with an exact provider and price contract");
  }
  if (scorerModel !== undefined && screenProfilePath === undefined) {
    throw new Error("scorer live screening requires --screen-profile with an exact provider and price contract");
  }
  if (scorerModel !== undefined && selectedCaseIds.length === 0) {
    throw new Error("scorer live screening requires at least one explicit --case fixture");
  }
}

/** Resolve live-mode concurrency from BENCH_CONCURRENCY, then --concurrency,
 * then the default. Non-positive or non-numeric inputs fall back to the default. */
function liveConcurrency(args: string[]): number {
  const raw = process.env.BENCH_CONCURRENCY ?? flagValue(args, "--concurrency");
  if (raw === undefined) return DEFAULT_LIVE_CONCURRENCY;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_LIVE_CONCURRENCY;
}

export function generatedLiveScreenRunId(now = new Date(), uuid = randomUUID()): string {
  const stamp = now.toISOString().replace(/[:.]/gu, "-");
  return `screen-${stamp}-${uuid}`;
}

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const jsonOut = flagValue(args, "--json-out");
  const manifestOut = flagValue(args, "--manifest-out");
  const privateEvidenceOut = process.env.POSTIL_BENCH_PRIVATE_EVIDENCE_OUT ??
    flagValue(args, "--private-evidence-out") ?? defaultPrivateEvidencePath();
  const cargoTarget = process.env.CARGO_TARGET_DIR;
  const binary = process.env.POSTIL_BIN ??
    (cargoTarget === undefined
      ? resolve(import.meta.dir, "..", "..", "target", "release", "postil")
      : resolve(cargoTarget, "release", "postil"));
  const liveModels =
    process.env.POSTIL_BENCH_MODE === "live" || args.includes("--live-models");
  const live = args.includes("--live") || process.env.BENCH_LIVE === "1";
  const mode = liveModels ? "live-admission" : live ? "live-screen" : "mock";
  validateScreeningEnvironment(process.env.POSTIL_BENCH_SCREEN_PROFILE);
  validateModeSpecificFlags(args, mode);
  validateRunIdentityEnvironment(process.env.POSTIL_BENCH_SCREEN_RUN_ID, mode);

  await prepareExplicitOutputs(jsonOut, manifestOut, liveModels ? privateEvidenceOut : undefined);
  if (args.includes("--json-out") && jsonOut === undefined) {
    throw new Error("--json-out requires a path");
  }
  if (args.includes("--manifest-out") && manifestOut === undefined) {
    throw new Error("--manifest-out requires a path");
  }
  if (args.includes("--private-evidence-out") && flagValue(args, "--private-evidence-out") === undefined) {
    throw new Error("--private-evidence-out requires a path");
  }
  if (manifestOut !== undefined && !liveModels) {
    throw new Error("--manifest-out is available only in live-models admission mode");
  }

  if (liveModels) {
    const pairs = parseQualificationPairs(
      process.env.POSTIL_BENCH_PAIRS ?? flagValue(args, "--pairs") ?? "",
    );
    const concurrency = liveModelsConcurrency(args);
    const costCapRaw = process.env.POSTIL_BENCH_COST_CAP_USD ?? flagValue(args, "--cost-cap");
    const repeatsRaw = process.env.POSTIL_BENCH_REPEATS ?? flagValue(args, "--repeats");
    const apiFormat = qualificationApiFormat(process.env.POSTIL_API_FORMAT);
    const pricingFile = process.env.POSTIL_BENCH_PRICING_FILE ?? flagValue(args, "--pricing-file");
    const upstreamProvider = process.env.POSTIL_BENCH_UPSTREAM_PROVIDER ?? flagValue(args, "--upstream-provider");
    if (!upstreamProvider?.trim()) {
      throw new Error("live-models admission needs POSTIL_BENCH_UPSTREAM_PROVIDER or --upstream-provider");
    }
    const qualificationSourceSha = await resolveQualificationSourceSha(
      resolve(import.meta.dir, "..", ".."),
    );
    let report: LiveModelsReport;
    let privateEvidence: LiveModelsPrivateEvidenceBundle;
    try {
      ({ report, privateEvidence } = await runLiveModels(cases, {
        binary,
        pairs,
        repeats: repeatsRaw === undefined ? undefined : Number.parseInt(repeatsRaw, 10),
        apiBase: process.env.POSTIL_API_BASE,
        apiFormat,
        upstreamProvider,
        pricing: pricingFile === undefined ? undefined : await pricingFromFile(pricingFile),
        concurrency,
        costCapUsd: costCapRaw,
      }));
    } catch (error) {
      await invalidateExplicitOutputs([manifestOut, privateEvidenceOut]);
      const failureReport = await createLiveModelsFailureReport(error, {
        qualificationSourceSha,
        pairs,
        upstreamProvider,
      });
      await writeLiveModelsReport(jsonOut, JSON.stringify(failureReport, null, 2));
      throw error;
    }
    await writePrivateEvidenceBundle(privateEvidenceOut, privateEvidence, report);
    await writeLiveModelsReport(jsonOut, JSON.stringify(report, null, 2));
    if (manifestOut) {
      if (!report.manifestCandidate) {
        throw new Error("qualification did not pass; no manifest candidate was emitted");
      }
      await atomicWriteOutput(manifestOut, `${JSON.stringify(report.manifestCandidate, null, 2)}\n`);
    }
    console.log(json ? JSON.stringify(report, null, 2) : formatLiveModelsReport(report));
    process.exitCode = liveModelsQualificationExitCode(report);
    return;
  }

  if (live) {
    const model = process.env.REVIEW_MODEL ?? flagValue(args, "--model");
    if (!model?.trim()) {
      throw new Error("live benchmark needs an explicit model: set REVIEW_MODEL or --model");
    }
    const concurrency = liveConcurrency(args);
    const scorerModel = flagValue(args, "--scorer-model");
    if (args.includes("--scorer-model") && scorerModel === undefined) {
      throw new Error("--scorer-model requires a value");
    }
    const screenProfilePath = flagValue(args, "--screen-profile");
    if (args.includes("--screen-profile") && screenProfilePath === undefined) {
      throw new Error("--screen-profile requires a path");
    }
    const bounded =
      args.includes("--bounded") || process.env.POSTIL_BENCH_BOUNDED === "1";
    const selectedCaseIds = repeatedFlagValues(args, "--case");
    const runIdFlag = flagValue(args, "--run-id");
    if (args.includes("--run-id") && runIdFlag === undefined) {
      throw new Error("--run-id requires a value");
    }
    const runId = runIdFlag ?? process.env.POSTIL_BENCH_SCREEN_RUN_ID ??
      generatedLiveScreenRunId();
    validateLiveScreenContract(selectedCaseIds, scorerModel, screenProfilePath);
    const report = await runLive(selectLiveScreeningCases(cases, selectedCaseIds), {
      binary,
      model,
      scorerModel,
      screenProfilePath,
      concurrency,
      bounded,
      selectedCaseIds,
      runId,
    });
    await writeReport(jsonOut, JSON.stringify(report, null, 2), runId);
    console.log(json ? JSON.stringify(report, null, 2) : formatLiveReport(report));
    // A run that scored nothing measured nothing. Exiting 0 here leaves the
    // release gate to infer an outage from an empty report, which reads as a
    // tooling problem rather than as "the provider was never reached".
    if (report.results.length > 0 && !report.results.some((result) => result.scored)) {
      console.error(
        `live benchmark produced no scored case out of ${report.results.length}: ` +
          "every case failed before a valid envelope was produced. This is an " +
          "operational failure, not a quality measurement. Check the provider " +
          "credential, the account's remaining credit, and the model's " +
          "availability before rerunning.",
      );
      process.exitCode = 1;
    }
    return;
  }

  const report = await runBenchmark(cases, {
    binary,
    keepRuns: process.env.POSTIL_BENCH_KEEP_RUNS === "1",
  });

  const jsonReport = JSON.stringify(report, null, 2);
  if (jsonOut) {
    await atomicWriteOutput(jsonOut, `${jsonReport}\n`);
  }
  console.log(json ? jsonReport : formatReport(report));

  if (!report.ok) {
    process.exitCode = 1;
  }
}

export async function createLiveModelsFailureReport(
  error: unknown,
  options: {
    qualificationSourceSha: string;
    pairs: QualificationPair[];
    upstreamProvider: string;
  },
): Promise<LiveModelsFailureReport> {
  const failure = fixedLiveModelsFailure(error);
  return Object.freeze(parseLiveModelsFailureReport({
    artifactType: "live-models-failure",
    qualificationSourceSha: options.qualificationSourceSha,
    profiles: options.pairs.map((pair) => ({
      id: qualificationPairId(pair),
      generatorModels: qualificationGeneratorModels(pair),
      consensus: pair.consensus ?? qualificationGeneratorModels(pair).length,
      scorerModels: qualificationScorerModels(pair),
    })),
    providerEndpointIdentity: MANAGED_OPENROUTER_PROVIDER_IDENTITY,
    upstreamProviderIdentity: options.upstreamProvider,
    process: failure,
  }));
}

export function parseLiveModelsFailureReport(value: unknown): LiveModelsFailureReport {
  if (!isRecord(value)) throw new Error("invalid live-models failure artifact");
  assertExactKeys(value, [
    "artifactType", "qualificationSourceSha", "profiles", "providerEndpointIdentity",
    "upstreamProviderIdentity", "process",
  ]);
  if (value.artifactType !== "live-models-failure" ||
      typeof value.qualificationSourceSha !== "string" ||
      !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(value.qualificationSourceSha) ||
      value.providerEndpointIdentity !== MANAGED_OPENROUTER_PROVIDER_IDENTITY ||
      typeof value.upstreamProviderIdentity !== "string" || value.upstreamProviderIdentity.trim() === "" ||
      !Array.isArray(value.profiles) || value.profiles.length === 0 ||
      !isRecord(value.process)) {
    throw new Error("invalid live-models failure artifact");
  }
  for (const profile of value.profiles) {
    if (!isRecord(profile)) throw new Error("invalid live-models failure profile");
    assertExactKeys(profile, ["id", "generatorModels", "consensus", "scorerModels"]);
    if (typeof profile.id !== "string" || profile.id.trim() === "" ||
        !Array.isArray(profile.generatorModels) || profile.generatorModels.length === 0 ||
        !profile.generatorModels.every((model) => typeof model === "string" && model.trim() !== "") ||
        !Number.isSafeInteger(profile.consensus) || (profile.consensus as number) < 1 ||
        !Array.isArray(profile.scorerModels) || profile.scorerModels.length === 0 ||
        !profile.scorerModels.every((model) => typeof model === "string" && model.trim() !== "")) {
      throw new Error("invalid live-models failure profile");
    }
  }
  assertExactKeys(value.process, [
    "category", "exitCode", "signal", "killed", "phase", "providerAttemptCount",
    "identityPresent", "identityMatched", "usagePresent", "usageAccountingComplete",
  ]);
  const category = value.process.category;
  const validCategory = typeof category === "string" && (
    (LIVE_MODELS_FAILURE_CATEGORIES as readonly string[]).includes(category) ||
    /^provider-http-[1-5][0-9]{2}$/u.test(category)
  );
  if (!validCategory ||
      !(value.process.exitCode === null || (Number.isSafeInteger(value.process.exitCode) && (value.process.exitCode as number) >= 0)) ||
      !(value.process.signal === null || (typeof value.process.signal === "string" && /^[A-Z0-9]+$/u.test(value.process.signal))) ||
      !isOptionalBoolean(value.process.killed) ||
      (value.process.phase !== "attribution" && value.process.phase !== "preflight" &&
        value.process.phase !== "unknown") ||
      !(value.process.providerAttemptCount === null ||
        (Number.isSafeInteger(value.process.providerAttemptCount) && (value.process.providerAttemptCount as number) >= 0)) ||
      !isOptionalBoolean(value.process.identityPresent) || !isOptionalBoolean(value.process.identityMatched) ||
      !isOptionalBoolean(value.process.usagePresent) || !isOptionalBoolean(value.process.usageAccountingComplete)) {
    throw new Error("invalid live-models failure process facts");
  }
  if (value.process.identityMatched === true && value.process.identityPresent !== true) {
    throw new Error("invalid live-models failure process facts");
  }
  if (value.process.usageAccountingComplete === true && value.process.usagePresent !== true) {
    throw new Error("invalid live-models failure process facts");
  }
  const managedAdmissionCategory =
    (managedAdmissionCapacityFailureCategories as readonly string[]).includes(category as string);
  const hasSubprocessFacts = value.process.exitCode !== null || value.process.signal !== null ||
    value.process.killed !== null || value.process.providerAttemptCount !== null ||
    value.process.identityPresent !== null || value.process.identityMatched !== null ||
    value.process.usagePresent !== null || value.process.usageAccountingComplete !== null;
  if ((managedAdmissionCategory && (value.process.phase !== "preflight" || hasSubprocessFacts)) ||
      (value.process.phase === "preflight" && !managedAdmissionCategory) ||
      (value.process.phase === "unknown" && hasSubprocessFacts)) {
    throw new Error("invalid live-models failure process facts");
  }
  return value as unknown as LiveModelsFailureReport;
}

function fixedLiveModelsFailure(error: unknown): LiveModelsFailureReport["process"] {
  const capacity = managedAdmissionCapacityFailure(error);
  if (capacity !== null) {
    return {
      category: capacity.category,
      exitCode: null,
      signal: null,
      killed: null,
      phase: "preflight",
      providerAttemptCount: null,
      identityPresent: null,
      identityMatched: null,
      usagePresent: null,
      usageAccountingComplete: null,
    };
  }
  const transport = atomicAttributionTransportFailure(error);
  if (transport === null) {
    return {
      category: "provider-unclassified", exitCode: null, signal: null, killed: null,
      phase: "unknown", providerAttemptCount: null, identityPresent: null, identityMatched: null,
      usagePresent: null, usageAccountingComplete: null,
    };
  }
  return {
    category: transport.diagnostic.category as LiveModelsFailureCategory,
    exitCode: transport.exitCode,
    signal: transport.signal,
    killed: transport.killed,
    phase: transport.diagnostic.phase,
    providerAttemptCount: transport.diagnostic.providerAttemptCount,
    identityPresent: transport.diagnostic.identityPresent,
    identityMatched: transport.diagnostic.identityMatched,
    usagePresent: transport.diagnostic.usagePresent,
    usageAccountingComplete: transport.diagnostic.usageAccountingComplete,
  };
}

function isOptionalBoolean(value: unknown): value is boolean | null {
  return value === null || typeof value === "boolean";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value: Record<string, unknown>, fields: readonly string[]): void {
  const expected = new Set(fields);
  if (Object.keys(value).length !== expected.size || Object.keys(value).some((field) => !expected.has(field))) {
    throw new Error("live-models failure artifact has unknown or missing fields");
  }
}

function qualificationApiFormat(
  value: string | undefined,
): "openai-compatible" | "anthropic" | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  if (value === "openai-compatible" || value === "anthropic") return value;
  throw new Error("POSTIL_API_FORMAT must be openai-compatible or anthropic");
}

/** Resolve live-models concurrency from BENCH_CONCURRENCY, then --concurrency,
 * then the default. Non-positive or non-numeric inputs fall back to the default. */
function liveModelsConcurrency(args: string[]): number {
  const raw = process.env.BENCH_CONCURRENCY ?? flagValue(args, "--concurrency");
  if (raw === undefined) return DEFAULT_LIVE_MODELS_CONCURRENCY;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_LIVE_MODELS_CONCURRENCY;
}

/** Live-models mode always writes a timestamped JSON report under
 * bench/.runs/live-models (gitignored), plus the optional explicit --json-out. */
async function writeLiveModelsReport(jsonOut: string | undefined, jsonReport: string) {
  const runsDir = resolve(import.meta.dir, "..", ".runs", "live-models");
  await mkdir(runsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await writeFile(resolve(runsDir, `live-models-${stamp}.json`), `${jsonReport}\n`);
  if (jsonOut) {
    await atomicWriteOutput(jsonOut, `${jsonReport}\n`);
  }
}

function defaultPrivateEvidencePath(): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return resolve(import.meta.dir, "..", ".runs", `live-models-private-${stamp}.json`);
}

/** Persist sensitive replay material as a private regular file, then re-read
 * and replay it before any public report or candidate is emitted. */
export async function writePrivateEvidenceBundle(
  path: string,
  bundle: LiveModelsPrivateEvidenceBundle,
  report: LiveModelsReport,
): Promise<void> {
  await mkdir(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  await atomicWriteOutput(path, serializePrivateEvidenceBundle(bundle));
  const metadata = await stat(path);
  if (!metadata.isFile() || (metadata.mode & 0o777) !== 0o600) {
    throw new Error("private evidence bundle must be a mode-0600 regular file");
  }
  const bytes = await readFile(path);
  if (createHash("sha256").update(bytes).digest("hex") !== report.privateEvidenceSha256) {
    throw new Error("persisted private evidence bundle digest does not match the public report");
  }
  const persisted = parsePrivateEvidenceBundle(JSON.parse(bytes.toString("utf8")));
  verifyPrivateEvidenceBundle(persisted, parseLiveModelsReport(report));
}

/** Live screening writes the aggregate report beside its raw run artifacts,
 * plus the optional explicit --json-out copy. */
async function writeReport(jsonOut: string | undefined, jsonReport: string, runId: string) {
  const runDir = resolve(import.meta.dir, "..", ".runs", "live", runId);
  await writeFile(resolve(runDir, "report.json"), `${jsonReport}\n`, { flag: "wx", mode: 0o600 });
  if (jsonOut) {
    await atomicWriteOutput(jsonOut, `${jsonReport}\n`);
  }
}

interface OutputPathIdentity {
  path: string;
  canonicalPath?: string;
  device?: number;
  inode?: number;
  inspectionError?: unknown;
}

async function inspectOutputPath(path: string): Promise<OutputPathIdentity> {
  const absolute = resolve(path);
  try {
    const canonicalPath = await canonicalProspectivePath(absolute);
    const identity: OutputPathIdentity = {
      path,
      canonicalPath,
    };
    try {
      const metadata = await stat(absolute);
      identity.device = metadata.dev;
      identity.inode = metadata.ino;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    return identity;
  } catch (inspectionError) {
    return { path, inspectionError };
  }
}

/** Resolve a prospective output through the nearest existing ancestor.
 * Missing output directories remain side-effect free while existing symlink
 * aliases still collapse to the same canonical identity. */
async function canonicalProspectivePath(path: string): Promise<string> {
  let ancestor = dirname(path);
  const missingSegments = [basename(path)];
  for (;;) {
    try {
      return resolve(await realpath(ancestor), ...missingSegments.reverse());
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) throw error;
      missingSegments.push(basename(ancestor));
      ancestor = parent;
    }
  }
}

/** Remove every explicit artifact before rejecting an aliased path or invalid
 * mode. Identity inspection is side-effect free and defers its errors until
 * cleanup has completed, so a failed invocation cannot leave stale evidence. */
export async function prepareExplicitOutputs(
  jsonOut: string | undefined,
  manifestOut: string | undefined,
  privateEvidenceOut?: string,
): Promise<void> {
  const identities = await Promise.all(
    [jsonOut, manifestOut, privateEvidenceOut]
      .filter((path): path is string => path !== undefined)
      .map(inspectOutputPath),
  );
  await invalidateExplicitOutputs([jsonOut, manifestOut, privateEvidenceOut]);
  for (const identity of identities) {
    if (identity.inspectionError !== undefined) throw identity.inspectionError;
  }
  for (let left = 0; left < identities.length; left += 1) {
    for (let right = left + 1; right < identities.length; right += 1) {
      const a = identities[left]!;
      const b = identities[right]!;
      const sameCanonicalPath = a.canonicalPath === b.canonicalPath;
      const sameExistingFile = a.device !== undefined && b.device !== undefined &&
        a.device === b.device && a.inode === b.inode;
      if (sameCanonicalPath || sameExistingFile) {
        throw new Error(privateEvidenceOut === undefined
          ? "--json-out and --manifest-out must use different paths"
          : "report, manifest, and private evidence outputs must use different paths");
      }
    }
  }
}

export async function invalidateExplicitOutputs(paths: Array<string | undefined>): Promise<void> {
  await Promise.all(paths.filter((path): path is string => path !== undefined).map((path) => rm(path, { force: true })));
}

export async function atomicWriteOutput(path: string, contents: string): Promise<void> {
  const absolute = resolve(path);
  const temporary = resolve(dirname(absolute), `.${basename(absolute)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, contents, { mode: 0o600 });
    await rename(temporary, absolute);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
