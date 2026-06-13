#!/usr/bin/env bun
// CLI entry point: run all benchmark cases against a release build.
//
//   bun run bench [--json] [--json-out <path>]
//
// Environment:
//   POSTIL_BIN              path to the postil binary (default ../target/release/postil)
//   POSTIL_BENCH_KEEP_RUNS  set to 1 to keep run directories after a green run

import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { formatReport, runBenchmark } from "./harness";

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const jsonOutIndex = args.indexOf("--json-out");
  const jsonOut = jsonOutIndex === -1 ? undefined : args[jsonOutIndex + 1];

  const report = await runBenchmark(cases, {
    binary: process.env.POSTIL_BIN ?? resolve(import.meta.dir, "..", "..", "target", "release", "postil"),
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

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
