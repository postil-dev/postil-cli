import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  assertManifestBoundToInputs,
  cohortSlotPaths,
  cohortManifestSchema,
  createCohortManifest,
  readCohortReceipt,
  reportSemanticSha256,
  type CohortManifest,
} from "./cohort";
import { executeReservedCohortSlot, reserveCohortSlot } from "./cohort-run";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })));
});

async function temporaryDirectory(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "postil-cohort-test-"));
  temporaryDirectories.push(path);
  return path;
}

const screeningProfilePath = resolve(import.meta.dir, "..", "..", "provisional-models.json");

function calibrationExecution(): CohortManifest["execution"] {
  return {
    kind: "github-sigstore-v1",
    repository: "postil-dev/postil-cli",
    signerWorkflow: ".github/workflows/benchmark-calibration.yml",
    sourceSha: "b".repeat(40),
    sourceRef: "refs/heads/main",
    runId: "456",
    runAttempt: "1",
  };
}

function githubEnvironment(execution: CohortManifest["execution"]): NodeJS.ProcessEnv {
  return {
    GITHUB_REPOSITORY: execution.repository,
    GITHUB_SHA: execution.sourceSha,
    GITHUB_REF: execution.sourceRef,
    GITHUB_RUN_ID: execution.runId,
    GITHUB_RUN_ATTEMPT: execution.runAttempt,
  };
}

describe("cohort manifests", () => {
  test("predeclares exactly ten immutable calibration slots", async () => {
    let sequence = 0;
    const execution = calibrationExecution();
    const manifest = await createCohortManifest({
      purpose: "calibration",
      binaryPath: process.execPath,
      screeningProfilePath,
      runPrefix: "calibration-e",
      execution,
      now: new Date("2026-08-26T00:00:00.000Z"),
      uuid: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    });
    expect(manifest.reportCount).toBe(10);
    expect(manifest.slots.map((slot) => slot.slot)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(manifest.slots.map((slot) => slot.runId)).toEqual([
      "calibration-e-01", "calibration-e-02", "calibration-e-03", "calibration-e-04",
      "calibration-e-05", "calibration-e-06", "calibration-e-07", "calibration-e-08",
      "calibration-e-09", "calibration-e-10",
    ]);
    await expect(
      assertManifestBoundToInputs(
        manifest,
        process.execPath,
        screeningProfilePath,
        githubEnvironment(execution),
      ),
    ).resolves.toBeUndefined();

    const tampered = structuredClone(manifest);
    tampered.evaluatorSha256 = "f".repeat(64);
    await expect(
      assertManifestBoundToInputs(
        tampered,
        process.execPath,
        screeningProfilePath,
        githubEnvironment(execution),
      ),
    ).rejects.toThrow("evaluatorSha256 is not bound");
  });

  test("rejects wrong counts, unordered slots, and unbound release execution", async () => {
    let sequence = 100;
    const execution = calibrationExecution();
    const calibration = await createCohortManifest({
      purpose: "calibration",
      binaryPath: process.execPath,
      screeningProfilePath,
      runPrefix: "calibration",
      execution,
      uuid: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    });
    expect(() => cohortManifestSchema.parse({
      ...calibration,
      purpose: "release",
    })).toThrow("release cohorts require exactly 5 reports");
    expect(() => cohortManifestSchema.parse({
      ...calibration,
      slots: [calibration.slots[1], calibration.slots[0], ...calibration.slots.slice(2)],
    })).toThrow("ordered and contiguous");
  });

  test("binds GitHub release execution to the first run attempt", async () => {
    let sequence = 200;
    const manifest = await createCohortManifest({
      purpose: "release",
      binaryPath: process.execPath,
      screeningProfilePath,
      runPrefix: "release",
      execution: {
        kind: "github-sigstore-v1",
        repository: "postil-dev/postil-cli",
        signerWorkflow: ".github/workflows/release.yml",
        sourceSha: "a".repeat(40),
        sourceRef: "refs/tags/v0.9.4",
        runId: "123",
        runAttempt: "1",
      },
      uuid: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
    });
    await expect(assertManifestBoundToInputs(
      manifest,
      process.execPath,
      screeningProfilePath,
      {
        GITHUB_REPOSITORY: "postil-dev/postil-cli",
        GITHUB_SHA: "a".repeat(40),
        GITHUB_REF: "refs/tags/v0.9.4",
        GITHUB_RUN_ID: "123",
        GITHUB_RUN_ATTEMPT: "1",
      },
    )).resolves.toBeUndefined();
    await expect(assertManifestBoundToInputs(
      manifest,
      process.execPath,
      screeningProfilePath,
      {
        GITHUB_REPOSITORY: "postil-dev/postil-cli",
        GITHUB_SHA: "a".repeat(40),
        GITHUB_REF: "refs/tags/v0.9.4",
        GITHUB_RUN_ID: "123",
        GITHUB_RUN_ATTEMPT: "2",
      },
    )).rejects.toThrow("not bound to this GitHub Actions source, run, and attempt");
  });
});

test("semantic digest excludes execution noise", () => {
  const original = {
    summary: { runId: "one", ranAt: "2026-08-26T00:00:00.000Z", durationMs: 10 },
    results: [{ id: "case", detected: true, durationMs: 9 }],
  };
  const renamed = structuredClone(original);
  renamed.summary.runId = "two";
  renamed.summary.ranAt = "2026-08-26T00:01:00.000Z";
  expect(reportSemanticSha256(renamed)).toBe(reportSemanticSha256(original));
  renamed.results[0]!.durationMs += 1;
  expect(reportSemanticSha256(renamed)).toBe(reportSemanticSha256(original));
  renamed.results[0]!.detected = false;
  expect(reportSemanticSha256(renamed)).not.toBe(reportSemanticSha256(original));
});

test("the canonical slot directory permanently blocks a path-based rerun", async () => {
  const directory = await temporaryDirectory();
  let sequence = 300;
  const execution = calibrationExecution();
  const manifest = await createCohortManifest({
    purpose: "calibration",
    binaryPath: process.execPath,
    screeningProfilePath,
    runPrefix: "calibration",
    execution,
    uuid: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
  });
  const manifestPath = join(directory, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await mkdir(join(directory, "slots", "01"), { recursive: true });
  await expect(reserveCohortSlot({
    manifestPath,
    slot: 1,
    binaryPath: process.execPath,
    screeningProfilePath,
    environment: githubEnvironment(execution),
  })).rejects.toThrow("EEXIST");
});

test("an authenticated reservation is required before slot execution", async () => {
  const directory = await temporaryDirectory();
  let sequence = 400;
  const execution = calibrationExecution();
  const manifest = await createCohortManifest({
    purpose: "calibration",
    binaryPath: process.execPath,
    screeningProfilePath,
    runPrefix: "calibration",
    execution,
    uuid: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`,
  });
  const manifestPath = join(directory, "manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const environment = githubEnvironment(execution);

  await expect(executeReservedCohortSlot({
    manifestPath,
    slot: 1,
    binaryPath: process.execPath,
    screeningProfilePath,
    environment,
    executeBenchmark: async () => 0,
  })).rejects.toThrow("no authenticated reservation");

  const reservation = await reserveCohortSlot({
    manifestPath,
    slot: 1,
    binaryPath: process.execPath,
    screeningProfilePath,
    environment,
  });
  expect(reservation.state).toBe("running");
  await expect(executeReservedCohortSlot({
    manifestPath,
    slot: 1,
    binaryPath: process.execPath,
    screeningProfilePath,
    environment,
    executeBenchmark: async ({ reportPath, runId }) => {
      await writeFile(reportPath, JSON.stringify({
        summary: { runId, ranAt: new Date().toISOString() },
      }));
      return 0;
    },
  })).resolves.toBe(0);
  const receipt = await readCohortReceipt(cohortSlotPaths(manifestPath, 1).receiptPath);
  expect(receipt.receipt.state).toBe("completed");
  await expect(executeReservedCohortSlot({
    manifestPath,
    slot: 1,
    binaryPath: process.execPath,
    screeningProfilePath,
    environment,
    executeBenchmark: async () => 0,
  })).rejects.toThrow("already completed");
}, 20_000);
