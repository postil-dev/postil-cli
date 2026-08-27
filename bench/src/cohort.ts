#!/usr/bin/env bun
// Predeclared execution contracts for release benchmark cohorts.

import { createHash, randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import { cases } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import { evaluatorSourceSha256, screeningProfileMetadata } from "./live";

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/u);
const gitShaSchema = z.string().regex(/^[0-9a-f]{40,64}$/u);
const nonemptyStringSchema = z.string().trim().min(1);
const REPOSITORY = "postil-dev/postil-cli";
const RELEASE_WORKFLOW = ".github/workflows/release.yml";
const CALIBRATION_WORKFLOW = ".github/workflows/benchmark-calibration.yml";

export const cohortSlotSchema = z.object({
  slot: z.number().int().positive(),
  runId: nonemptyStringSchema,
  nonce: z.string().uuid(),
}).strict();

const executionBindingSchema = z.object({
  kind: z.literal("github-sigstore-v1"),
  repository: z.literal(REPOSITORY),
  signerWorkflow: z.enum([RELEASE_WORKFLOW, CALIBRATION_WORKFLOW]),
  sourceSha: gitShaSchema,
  sourceRef: nonemptyStringSchema,
  runId: nonemptyStringSchema,
  runAttempt: z.literal("1"),
}).strict();

export const cohortManifestSchema = z.object({
  schemaVersion: z.literal(4),
  purpose: z.enum(["calibration", "release"]),
  cohortId: z.string().uuid(),
  createdAt: z.string().datetime({ offset: true }),
  reportCount: z.union([z.literal(5), z.literal(10)]),
  caseRetries: z.literal(1),
  binarySha256: sha256Schema,
  evaluatorSha256: sha256Schema,
  fixtureCorpusSha256: sha256Schema,
  screeningProfileSha256: sha256Schema,
  providerContractSha256: sha256Schema,
  execution: executionBindingSchema,
  slots: z.array(cohortSlotSchema),
}).strict().superRefine((manifest, context) => {
  const expectedCount = manifest.purpose === "calibration" ? 10 : 5;
  if (manifest.reportCount !== expectedCount) {
    context.addIssue({
      code: "custom",
      path: ["reportCount"],
      message: `${manifest.purpose} cohorts require exactly ${expectedCount} reports`,
    });
  }
  if (manifest.slots.length !== manifest.reportCount) {
    context.addIssue({
      code: "custom",
      path: ["slots"],
      message: "slot count must equal reportCount",
    });
  }
  const expectedSlots = Array.from({ length: manifest.reportCount }, (_, index) => index + 1);
  if (manifest.slots.some((slot, index) => slot.slot !== expectedSlots[index])) {
    context.addIssue({
      code: "custom",
      path: ["slots"],
      message: "slots must be ordered and contiguous starting at 1",
    });
  }
  if (new Set(manifest.slots.map((slot) => slot.runId)).size !== manifest.slots.length) {
    context.addIssue({ code: "custom", path: ["slots"], message: "slot run IDs must be unique" });
  }
  if (new Set(manifest.slots.map((slot) => slot.nonce)).size !== manifest.slots.length) {
    context.addIssue({ code: "custom", path: ["slots"], message: "slot nonces must be unique" });
  }
  if (
    manifest.purpose === "release" &&
    (
      manifest.execution.signerWorkflow !== RELEASE_WORKFLOW ||
      !/^refs\/tags\/v[^\s]+$/u.test(manifest.execution.sourceRef)
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["execution"],
      message: "release cohorts must be bound to the release workflow and a version tag",
    });
  }
  if (
    manifest.purpose === "calibration" &&
    (
      manifest.execution.signerWorkflow !== CALIBRATION_WORKFLOW ||
      manifest.execution.sourceRef !== "refs/heads/main"
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["execution"],
      message: "calibration cohorts must be bound to the main-branch calibration workflow",
    });
  }
});

export type CohortManifest = z.infer<typeof cohortManifestSchema>;
export type CohortSlot = z.infer<typeof cohortSlotSchema>;

const receiptBaseSchema = z.object({
  schemaVersion: z.literal(2),
  manifestSha256: sha256Schema,
  cohortId: z.string().uuid(),
  purpose: z.enum(["calibration", "release"]),
  slot: z.number().int().positive(),
  nonce: z.string().uuid(),
  runId: nonemptyStringSchema,
  startedAt: z.string().datetime({ offset: true }),
}).strict();

export const cohortReceiptSchema = z.discriminatedUnion("state", [
  receiptBaseSchema.extend({
    state: z.literal("running"),
  }).strict(),
  receiptBaseSchema.extend({
    state: z.literal("completed"),
    finishedAt: z.string().datetime({ offset: true }),
    exitCode: z.literal(0),
    reportRawSha256: sha256Schema,
  }).strict(),
  receiptBaseSchema.extend({
    state: z.literal("failed"),
    finishedAt: z.string().datetime({ offset: true }),
    exitCode: z.number().int().nullable(),
    failure: z.enum(["spawn-failed", "benchmark-exit", "report-unavailable", "report-invalid"]),
    reportRawSha256: sha256Schema.nullable(),
  }).strict(),
]);

export type CohortReceipt = z.infer<typeof cohortReceiptSchema>;
export type CompletedCohortReceipt = Extract<CohortReceipt, { state: "completed" }>;

export function sha256(bytes: Uint8Array | string): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function fixtureCorpusSha256(): string {
  return sha256(JSON.stringify(cases.map((input) => benchmarkCase.parse(input))));
}

export function reportSemanticSha256(value: unknown): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("benchmark report must be a JSON object");
  }
  const report = structuredClone(value) as Record<string, unknown>;
  if (typeof report.summary !== "object" || report.summary === null || Array.isArray(report.summary)) {
    throw new Error("benchmark report summary must be a JSON object");
  }
  const summary = report.summary as Record<string, unknown>;
  for (const field of [
    "runId",
    "ranAt",
    "durationMs",
    "observedProviderCostUsdDecimal",
  ]) delete summary[field];
  if (Array.isArray(report.results)) {
    report.results = report.results.map((result) => {
      if (typeof result !== "object" || result === null || Array.isArray(result)) return result;
      const normalized = { ...result } as Record<string, unknown>;
      for (const field of [
        "durationMs",
        "observedProviderCostUsdDecimal",
        "promptTokens",
        "completionTokens",
      ]) delete normalized[field];
      return normalized;
    });
  }
  return sha256(JSON.stringify(report));
}

export function cohortSlotPaths(manifestPath: string, slot: number): {
  directory: string;
  reportPath: string;
  receiptPath: string;
} {
  if (!Number.isSafeInteger(slot) || slot < 1 || slot > 99) {
    throw new Error("cohort slot must be an integer from 1 to 99");
  }
  const directory = resolve(dirname(manifestPath), "slots", String(slot).padStart(2, "0"));
  return {
    directory,
    reportPath: join(directory, "report.json"),
    receiptPath: join(directory, "receipt.json"),
  };
}

export async function readCohortManifest(path: string): Promise<{
  manifest: CohortManifest;
  raw: Uint8Array;
  rawSha256: string;
}> {
  const raw = await readFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    throw new Error(`could not parse cohort manifest: ${error instanceof Error ? error.message : String(error)}`);
  }
  return {
    manifest: cohortManifestSchema.parse(parsed),
    raw,
    rawSha256: sha256(raw),
  };
}

export async function readCohortReceipt(path: string): Promise<{
  receipt: CohortReceipt;
  raw: Uint8Array;
  rawSha256: string;
}> {
  const raw = await readFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    throw new Error(`could not parse cohort receipt: ${error instanceof Error ? error.message : String(error)}`);
  }
  return {
    receipt: cohortReceiptSchema.parse(parsed),
    raw,
    rawSha256: sha256(raw),
  };
}

export async function inputBindings(binaryPath: string, screeningProfilePath: string): Promise<{
  binarySha256: string;
  evaluatorSha256: string;
  fixtureCorpusSha256: string;
  screeningProfileSha256: string;
  providerContractSha256: string;
}> {
  const [binary, evaluatorSha, profile] = await Promise.all([
    readFile(binaryPath),
    evaluatorSourceSha256(),
    screeningProfileMetadata(screeningProfilePath),
  ]);
  return {
    binarySha256: sha256(binary),
    evaluatorSha256: evaluatorSha,
    fixtureCorpusSha256: fixtureCorpusSha256(),
    screeningProfileSha256: profile.sha256,
    providerContractSha256: profile.providerContractSha256,
  };
}

export async function assertManifestBoundToInputs(
  manifest: CohortManifest,
  binaryPath: string,
  screeningProfilePath: string,
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const bindings = await inputBindings(binaryPath, screeningProfilePath);
  for (const field of [
    "binarySha256",
    "evaluatorSha256",
    "fixtureCorpusSha256",
    "screeningProfileSha256",
    "providerContractSha256",
  ] as const) {
    if (manifest[field] !== bindings[field]) {
      throw new Error(`cohort manifest ${field} is not bound to the supplied benchmark input`);
    }
  }
  if (manifest.execution.kind === "github-sigstore-v1") {
    if (
      environment.GITHUB_REPOSITORY !== manifest.execution.repository ||
      environment.GITHUB_SHA !== manifest.execution.sourceSha ||
      environment.GITHUB_REF !== manifest.execution.sourceRef ||
      environment.GITHUB_RUN_ID !== manifest.execution.runId ||
      environment.GITHUB_RUN_ATTEMPT !== manifest.execution.runAttempt
    ) {
      throw new Error("cohort manifest is not bound to this GitHub Actions source, run, and attempt");
    }
  }
}

export async function createCohortManifest(options: {
  purpose: "calibration" | "release";
  binaryPath: string;
  screeningProfilePath: string;
  runPrefix: string;
  execution?: CohortManifest["execution"];
  now?: Date;
  uuid?: () => string;
}): Promise<CohortManifest> {
  const count = options.purpose === "calibration" ? 10 : 5;
  const uuid = options.uuid ?? randomUUID;
  const cohortId = uuid();
  const bindings = await inputBindings(options.binaryPath, options.screeningProfilePath);
  const execution = options.execution ?? {
    kind: "github-sigstore-v1",
    repository: process.env.GITHUB_REPOSITORY ?? "",
    signerWorkflow: options.purpose === "release" ? RELEASE_WORKFLOW : CALIBRATION_WORKFLOW,
    sourceSha: process.env.GITHUB_SHA ?? "",
    sourceRef: process.env.GITHUB_REF ?? "",
    runId: process.env.GITHUB_RUN_ID ?? "",
    runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? "",
  } as CohortManifest["execution"];
  return cohortManifestSchema.parse({
    schemaVersion: 4,
    purpose: options.purpose,
    cohortId,
    createdAt: (options.now ?? new Date()).toISOString(),
    reportCount: count,
    caseRetries: 1,
    ...bindings,
    execution,
    slots: Array.from({ length: count }, (_, index) => ({
      slot: index + 1,
      runId: `${options.runPrefix}-${String(index + 1).padStart(2, "0")}`,
      nonce: uuid(),
    })),
  });
}

function requiredValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let purpose: "calibration" | "release" | undefined;
  let binaryPath: string | undefined;
  let screeningProfilePath: string | undefined;
  let runPrefix: string | undefined;
  let outputPath: string | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]!;
    const value = argument === "--purpose" || argument === "--binary" ||
      argument === "--screen-profile" || argument === "--run-prefix" || argument === "--out"
      ? requiredValue(args, index, argument)
      : undefined;
    if (argument === "--purpose") {
      if (value !== "calibration" && value !== "release") throw new Error("--purpose must be calibration or release");
      purpose = value;
    } else if (argument === "--binary") binaryPath = value;
    else if (argument === "--screen-profile") screeningProfilePath = value;
    else if (argument === "--run-prefix") runPrefix = value;
    else if (argument === "--out") outputPath = value;
    else throw new Error(`unknown cohort-create argument ${argument}`);
    index += 1;
  }
  if (purpose === undefined || binaryPath === undefined || screeningProfilePath === undefined ||
      runPrefix === undefined || outputPath === undefined) {
    throw new Error("cohort-create requires --purpose, --binary, --screen-profile, --run-prefix, and --out");
  }
  const manifest = await createCohortManifest({
    purpose,
    binaryPath: resolve(binaryPath),
    screeningProfilePath: resolve(screeningProfilePath),
    runPrefix,
  });
  await writeFile(resolve(outputPath), `${JSON.stringify(manifest, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
