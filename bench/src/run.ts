#!/usr/bin/env bun
// CLI entry point.
//
// Mock mode (default, CI path): runs all cases against a release build with a
// mock forge and a mock model — measures pipeline fidelity, not detection.
//
//   bun run bench [--json] [--json-out <path>]
//
// Live-models mode (opt-in, NOT run in CI, spends real tokens): keeps the
// per-case mock GitHub API but points the CLI at the real OpenRouter endpoint,
// running each fixture once per model in POSTIL_BENCH_MODELS — measures
// detection efficacy and measured cost per real model. Requires an inference
// key (OPENROUTER_API_KEY or POSTIL_API_KEY).
//
//   POSTIL_BENCH_MODE=live POSTIL_BENCH_MODELS=id1,id2 \
//     OPENROUTER_API_KEY=... bun run bench --json-out report.json
//
// Diff-file live mode (older, single model, no forge): measures detection with
// no mock GitHub at all. Selected by --live / BENCH_LIVE.
//
//   bun run bench:live              # or: BENCH_LIVE=1 bun run src/run.ts
//   bun run bench --live [--json] [--json-out <path>] [--model <id>] [--concurrency <n>]
//
// Environment:
//   POSTIL_BIN              path to the postil binary (default ../target/release/postil)
//   POSTIL_BENCH_KEEP_RUNS  set to 1 to keep run directories after a green run (mock mode)
//   POSTIL_BENCH_MODE       set to "live" to select live-models mode
//   POSTIL_BENCH_MODELS     comma-separated OpenRouter model ids for live-models mode
//   POSTIL_API_BASE         OpenRouter-compatible base (default https://openrouter.ai/api/v1)
//   OPENROUTER_API_KEY      inference key for live-models mode (or POSTIL_API_KEY); never printed
//   POSTIL_API_KEY          required in diff-file live mode; never logged or printed
//   REVIEW_MODEL            model id for diff-file live mode (else --model, else default)
//   BENCH_LIVE              set to 1 to select diff-file live mode
//   BENCH_CONCURRENCY       live-mode case parallelism (else --concurrency, else default)

import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { formatReport, runBenchmark } from "./harness";
import { DEFAULT_LIVE_CONCURRENCY, DEFAULT_LIVE_MODEL, formatLiveReport, runLive } from "./live";
import {
  DEFAULT_LIVE_CONCURRENCY as DEFAULT_LIVE_MODELS_CONCURRENCY,
  formatLiveModelsReport,
  runLiveModels,
} from "./livemodels";

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
  const liveModels =
    process.env.POSTIL_BENCH_MODE === "live" || args.includes("--live-models");

  if (liveModels) {
    const models = parseModels(process.env.POSTIL_BENCH_MODELS ?? flagValue(args, "--models"));
    const concurrency = liveModelsConcurrency(args);
    const report = await runLiveModels(cases, {
      binary,
      models,
      apiBase: process.env.POSTIL_API_BASE,
      concurrency,
    });
    await writeLiveModelsReport(jsonOut, JSON.stringify(report, null, 2));
    console.log(json ? JSON.stringify(report, null, 2) : formatLiveModelsReport(report));
    return;
  }

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

/** Parse a comma-separated model list, trimming blanks. */
function parseModels(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m.length > 0);
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
    await writeFile(jsonOut, `${jsonReport}\n`);
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
