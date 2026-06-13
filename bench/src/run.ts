#!/usr/bin/env bun
// CLI entry point.
//
// Mock mode (default, CI path): runs all cases against a release build with a
// mock forge and a mock model — measures pipeline fidelity, not detection.
//
//   bun run bench [--json] [--json-out <path>]
//
// Live mode (opt-in, NOT run in CI, spends real tokens): runs the real binary
// against the same fixtures with a real model and no mocked model server —
// measures detection ability. Requires POSTIL_API_KEY in the environment.
//
//   bun run bench:live              # or: BENCH_LIVE=1 bun run src/run.ts
//   bun run bench --live [--json] [--json-out <path>] [--model <id>] [--concurrency <n>]
//
// Environment:
//   POSTIL_BIN              path to the postil binary (default ../target/release/postil)
//   POSTIL_BENCH_KEEP_RUNS  set to 1 to keep run directories after a green run (mock mode)
//   POSTIL_API_KEY          required in live mode; never logged or printed
//   REVIEW_MODEL            model id for live mode (else --model, else default)
//   BENCH_LIVE              set to 1 to select live mode
//   BENCH_CONCURRENCY       live-mode case parallelism (else --concurrency, else default 6)

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { formatReport, runBenchmark } from "./harness";
import { DEFAULT_LIVE_CONCURRENCY, DEFAULT_LIVE_MODEL, formatLiveReport, runLive } from "./live";

function flagValue(args: string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index === -1 ? undefined : args[index + 1];
}

/** Resolve live-mode concurrency from BENCH_CONCURRENCY, then --concurrency,
 * then the default. Non-positive or non-numeric inputs fall back to the default. */
function liveConcurrency(args: string[]): number {
  const raw = process.env.BENCH_CONCURRENCY ?? flagValue(args, "--concurrency");
  if (raw === undefined) return DEFAULT_LIVE_CONCURRENCY;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_LIVE_CONCURRENCY;
}

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const jsonOut = flagValue(args, "--json-out");
  const binary =
    process.env.POSTIL_BIN ??
    resolve(import.meta.dir, "..", "..", "target", "release", "postil");
  const live = args.includes("--live") || process.env.BENCH_LIVE === "1";

  if (live) {
    const model = process.env.REVIEW_MODEL ?? flagValue(args, "--model") ?? DEFAULT_LIVE_MODEL;
    const concurrency = liveConcurrency(args);
    const report = await runLive(cases, { binary, model, concurrency });
    await writeReport(jsonOut, JSON.stringify(report, null, 2));
    console.log(json ? JSON.stringify(report, null, 2) : formatLiveReport(report));
    return;
  }

  const report = await runBenchmark(cases, {
    binary,
    keepRuns: process.env.POSTIL_BENCH_KEEP_RUNS === "1",
  });

  const jsonReport = JSON.stringify(report, null, 2);
  if (jsonOut) {
    await writeFile(jsonOut, `${jsonReport}\n`);
  }
  console.log(json ? jsonReport : formatReport(report));

  if (!report.ok) {
    process.exitCode = 1;
  }
}

/** Live mode always writes a JSON report under bench/.runs (gitignored), plus
 * the optional explicit --json-out path. */
async function writeReport(jsonOut: string | undefined, jsonReport: string) {
  const runsDir = resolve(import.meta.dir, "..", ".runs");
  await mkdir(runsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await writeFile(resolve(runsDir, `live-${stamp}.json`), `${jsonReport}\n`);
  if (jsonOut) {
    await writeFile(jsonOut, `${jsonReport}\n`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
