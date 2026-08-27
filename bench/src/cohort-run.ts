#!/usr/bin/env bun
// Reserves or executes exactly one predeclared benchmark slot.

import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import {
  assertManifestBoundToInputs,
  cohortReceiptSchema,
  cohortSlotPaths,
  readCohortManifest,
  sha256,
  type CohortManifest,
  type CohortReceipt,
  type CohortSlot,
} from "./cohort";

interface SlotOptions {
  manifestPath: string;
  slot: number;
  binaryPath: string;
  screeningProfilePath: string;
  environment?: NodeJS.ProcessEnv;
}

interface SlotContext {
  manifest: CohortManifest;
  manifestSha256: string;
  cohortSlot: CohortSlot;
  paths: ReturnType<typeof cohortSlotPaths>;
}

export function cohortBenchmarkArguments(options: {
  screeningProfilePath: string;
  runId: string;
  reportPath: string;
  caseRetries: number;
}): string[] {
  if (options.caseRetries !== 0) {
    throw new Error("formal cohort case retries must be zero");
  }
  return [
    process.execPath,
    "run",
    "src/run.ts",
    "--live",
    "--screen-profile",
    options.screeningProfilePath,
    "--run-id",
    options.runId,
    "--retries",
    String(options.caseRetries),
    "--json-out",
    options.reportPath,
  ];
}

async function slotContext(options: SlotOptions): Promise<SlotContext> {
  const { manifest, rawSha256: manifestSha256 } = await readCohortManifest(options.manifestPath);
  const cohortSlot = manifest.slots.find((candidate) => candidate.slot === options.slot);
  if (cohortSlot === undefined) throw new Error(`cohort manifest has no slot ${options.slot}`);
  await assertManifestBoundToInputs(
    manifest,
    options.binaryPath,
    options.screeningProfilePath,
    options.environment,
  );
  return {
    manifest,
    manifestSha256,
    cohortSlot,
    paths: cohortSlotPaths(options.manifestPath, options.slot),
  };
}

function runningReceipt(context: SlotContext): CohortReceipt {
  return cohortReceiptSchema.parse({
    schemaVersion: 2,
    state: "running",
    manifestSha256: context.manifestSha256,
    cohortId: context.manifest.cohortId,
    purpose: context.manifest.purpose,
    slot: context.cohortSlot.slot,
    nonce: context.cohortSlot.nonce,
    runId: context.cohortSlot.runId,
    startedAt: new Date().toISOString(),
  });
}

function assertReservedReceipt(context: SlotContext, receipt: CohortReceipt): asserts receipt is Extract<
  CohortReceipt,
  { state: "running" }
> {
  if (receipt.state !== "running") {
    throw new Error(`cohort slot ${context.cohortSlot.slot} reservation is already ${receipt.state}`);
  }
  for (const [field, actual, expected] of [
    ["manifestSha256", receipt.manifestSha256, context.manifestSha256],
    ["cohortId", receipt.cohortId, context.manifest.cohortId],
    ["purpose", receipt.purpose, context.manifest.purpose],
    ["slot", receipt.slot, context.cohortSlot.slot],
    ["nonce", receipt.nonce, context.cohortSlot.nonce],
    ["runId", receipt.runId, context.cohortSlot.runId],
  ] as const) {
    if (actual !== expected) {
      throw new Error(`cohort slot ${context.cohortSlot.slot} reserved ${field} does not match its manifest`);
    }
  }
}

async function replaceReceipt(path: string, receipt: CohortReceipt): Promise<void> {
  const parsed = cohortReceiptSchema.parse(receipt);
  const temporary = resolve(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(temporary, `${JSON.stringify(parsed, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, path);
}

async function reportDigests(path: string, expectedRunId: string): Promise<{
  rawSha256: string;
  ranAt: string;
}> {
  const raw = await readFile(path);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    throw new Error(`could not parse benchmark report: ${error instanceof Error ? error.message : String(error)}`);
  }
  const runId = (parsed as { summary?: { runId?: unknown } })?.summary?.runId;
  if (runId !== expectedRunId) throw new Error("benchmark report runId does not match its cohort slot");
  const ranAt = (parsed as { summary?: { ranAt?: unknown } })?.summary?.ranAt;
  if (typeof ranAt !== "string" || !Number.isFinite(Date.parse(ranAt))) {
    throw new Error("benchmark report contains an invalid ranAt timestamp");
  }
  return { rawSha256: sha256(raw), ranAt };
}

export async function reserveCohortSlot(options: SlotOptions): Promise<CohortReceipt> {
  const context = await slotContext(options);
  await mkdir(resolve(context.paths.directory, ".."), { recursive: true, mode: 0o700 });
  await mkdir(context.paths.directory, { mode: 0o700 });
  const receipt = runningReceipt(context);
  await writeFile(context.paths.receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return receipt;
}

export async function executeReservedCohortSlot(options: SlotOptions & {
  executeBenchmark?: (options: {
    reportPath: string;
    runId: string;
    caseRetries: number;
  }) => Promise<number>;
}): Promise<number> {
  const context = await slotContext(options);
  const receiptRaw = await readFile(context.paths.receiptPath).catch((error) => {
    throw new Error(
      `cohort slot ${context.cohortSlot.slot} has no authenticated reservation: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  });
  const reservation = cohortReceiptSchema.parse(JSON.parse(receiptRaw.toString("utf8")));
  assertReservedReceipt(context, reservation);

  const finishReceipt = async (receipt: CohortReceipt): Promise<void> => {
    await replaceReceipt(context.paths.receiptPath, receipt);
  };

  let exitCode: number | null = null;
  try {
    if (options.executeBenchmark !== undefined) {
      exitCode = await options.executeBenchmark({
        reportPath: context.paths.reportPath,
        runId: context.cohortSlot.runId,
        caseRetries: context.manifest.caseRetries,
      });
    } else {
      const child = Bun.spawn(cohortBenchmarkArguments({
        screeningProfilePath: options.screeningProfilePath,
        runId: context.cohortSlot.runId,
        reportPath: context.paths.reportPath,
        caseRetries: context.manifest.caseRetries,
      }), {
        cwd: resolve(import.meta.dir, ".."),
        env: { ...process.env, POSTIL_BIN: options.binaryPath },
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
      });
      exitCode = await child.exited;
    }
  } catch (error) {
    await finishReceipt({
      ...reservation,
      state: "failed",
      finishedAt: new Date().toISOString(),
      exitCode: null,
      failure: "spawn-failed",
      reportRawSha256: null,
    });
    throw error;
  }

  let digests: Awaited<ReturnType<typeof reportDigests>> | undefined;
  try {
    digests = await reportDigests(context.paths.reportPath, context.cohortSlot.runId);
  } catch (error) {
    await finishReceipt({
      ...reservation,
      state: "failed",
      finishedAt: new Date().toISOString(),
      exitCode,
      failure: exitCode === 0 ? "report-invalid" : "benchmark-exit",
      reportRawSha256: null,
    });
    if (exitCode === 0) throw error;
    return exitCode;
  }

  if (exitCode !== 0) {
    await finishReceipt({
      ...reservation,
      state: "failed",
      finishedAt: new Date().toISOString(),
      exitCode,
      failure: "benchmark-exit",
      reportRawSha256: digests.rawSha256,
    });
    return exitCode;
  }

  const finishedAt = new Date().toISOString();
  if (
    Date.parse(digests.ranAt) < Date.parse(reservation.startedAt) ||
    Date.parse(digests.ranAt) > Date.parse(finishedAt)
  ) {
    await finishReceipt({
      ...reservation,
      state: "failed",
      finishedAt,
      exitCode: 0,
      failure: "report-invalid",
      reportRawSha256: digests.rawSha256,
    });
    throw new Error("benchmark report ranAt is outside its receipt interval");
  }
  await finishReceipt({
    ...reservation,
    state: "completed",
    finishedAt,
    exitCode: 0,
    reportRawSha256: digests.rawSha256,
  });
  return 0;
}

export async function runCohortSlot(options: SlotOptions & {
  executeBenchmark?: (options: {
    reportPath: string;
    runId: string;
    caseRetries: number;
  }) => Promise<number>;
}): Promise<number> {
  await reserveCohortSlot(options);
  return executeReservedCohortSlot(options);
}

function requiredValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const values = new Map<string, string>();
  const allowed = new Set(["--mode", "--manifest", "--slot", "--binary", "--screen-profile"]);
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index]!;
    if (!allowed.has(flag)) throw new Error(`unknown cohort-run argument ${flag}`);
    if (values.has(flag)) throw new Error(`${flag} may be specified only once`);
    values.set(flag, requiredValue(args, index, flag));
  }
  for (const flag of allowed) {
    if (!values.has(flag)) throw new Error(`cohort-run requires ${flag}`);
  }
  const mode = values.get("--mode");
  if (mode !== "reserve" && mode !== "execute") {
    throw new Error("--mode must be reserve or execute");
  }
  const slot = Number(values.get("--slot"));
  if (!Number.isSafeInteger(slot) || slot < 1) throw new Error("cohort slot must be a positive integer");
  const options = {
    manifestPath: resolve(values.get("--manifest")!),
    slot,
    binaryPath: resolve(values.get("--binary")!),
    screeningProfilePath: resolve(values.get("--screen-profile")!),
  };
  if (mode === "reserve") {
    await reserveCohortSlot(options);
  } else {
    process.exitCode = await executeReservedCohortSlot(options);
  }
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
