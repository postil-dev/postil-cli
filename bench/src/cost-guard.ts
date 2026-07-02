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
  pricingFromCatalog,
  projectTotalCostUsd,
  type OpenRouterModelsResponse,
} from "./livemodels-score";

const DEFAULT_CAP_USD = 15;

function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

async function main() {
  const args = process.argv.slice(2);
  const models = (process.env.POSTIL_BENCH_MODELS ?? flagValue(args, "--models") ?? "")
    .split(",")
    .map((m) => m.trim())
    .filter(Boolean);
  if (models.length === 0) {
    throw new Error("no models: set POSTIL_BENCH_MODELS or pass --models id1,id2");
  }
  const capRaw = flagValue(args, "--cap") ?? process.env.POSTIL_BENCH_COST_CAP_USD;
  const cap = capRaw ? Number.parseFloat(capRaw) : DEFAULT_CAP_USD;

  const apiBase = process.env.POSTIL_API_BASE ?? DEFAULT_API_BASE;
  const url = `${apiBase.replace(/\/$/, "")}/models`;
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`failed to fetch OpenRouter pricing (${res.status}) from ${url}`);
  }
  const catalog = (await res.json()) as OpenRouterModelsResponse;
  const pricing = pricingFromCatalog(catalog, models);

  const diffs = cases.map((c) => benchmarkCase.parse(c).diff);
  const projected = projectTotalCostUsd({ diffs, models, pricing });

  const missing = models.filter((m) => !pricing.has(m));
  const lines = [
    `Cost guardrail: ${cases.length} fixtures x ${models.length} model(s)`,
    `Models: ${models.join(", ")}`,
    `Projected upper-bound total cost: $${projected.toFixed(4)} (cap $${cap.toFixed(2)})`,
  ];
  if (missing.length > 0) {
    lines.push(
      `WARNING: no pricing for ${missing.join(", ")} — their spend is NOT in the projection.`,
    );
  }
  console.log(lines.join("\n"));

  if (missing.length > 0) {
    console.error(
      "Refusing to proceed: at least one model has unknown pricing, so the projection is not an " +
        "upper bound. Remove the unpriced model(s) or verify their ids.",
    );
    process.exitCode = 1;
    return;
  }
  if (projected > cap) {
    console.error(
      `Refusing to proceed: projected $${projected.toFixed(4)} exceeds the $${cap.toFixed(2)} cap. ` +
        "Reduce the model list or the case set.",
    );
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
