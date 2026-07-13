#!/usr/bin/env bun
// Pre-run cost guardrail for live-models mode. Fetches OpenRouter pricing once,
// projects an upper-bound total cost of running every fixture against every
// requested model (from fixture diff sizes), and exits non-zero if the
// projection exceeds the cap. Intended to run in CI immediately before the live
// bench so an over-budget matrix aborts before spending anything.
//
//   POSTIL_BENCH_MODELS=id1,id2 bun run src/cost-guard.ts [--cap 15]
//
// No API key is needed: the /models catalog is public. The key is never read
// here.

import { cases } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import { DEFAULT_API_BASE } from "./livemodels";
import {
  assertGeneratorQualificationPreflight,
  normalizeGeneratorModels,
  pricingFromCatalog,
  type OpenRouterModelsResponse,
  validateGeneratorQualificationBounds,
} from "./livemodels-score";

const DEFAULT_CAP_USD = 15;
export function validateGeneratorPreflight(models: string[], cap: number): void {
  validateGeneratorQualificationBounds(models, cap);
}

function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

async function main() {
  const args = process.argv.slice(2);
  const models = normalizeGeneratorModels(
    (process.env.POSTIL_BENCH_MODELS ?? flagValue(args, "--models") ?? "").split(","),
  );
  const capRaw = flagValue(args, "--cap") ?? process.env.POSTIL_BENCH_COST_CAP_USD;
  const cap = capRaw ? Number.parseFloat(capRaw) : DEFAULT_CAP_USD;
  validateGeneratorPreflight(models, cap);

  const apiBase = process.env.POSTIL_API_BASE ?? DEFAULT_API_BASE;
  const url = `${apiBase.replace(/\/$/, "")}/models`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`failed to fetch OpenRouter pricing (${res.status}) from ${url}`);
  }
  const catalog = (await res.json()) as OpenRouterModelsResponse;
  const pricing = pricingFromCatalog(catalog, models);

  const diffs = cases.map((c) => benchmarkCase.parse(c).diff);
  const projected = assertGeneratorQualificationPreflight({ diffs, models, pricing, costCapUsd: cap });
  const lines = [
    `Cost guardrail: ${cases.length} fixtures x ${models.length} model(s)`,
    `Models: ${models.join(", ")}`,
    `Projected upper-bound total cost: $${projected.toFixed(4)} (cap $${cap.toFixed(2)})`,
  ];
  console.log(lines.join("\n"));
}

if (import.meta.main) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
