import { expect, test } from "bun:test";
import { resolve } from "node:path";

const workflowPath = resolve(import.meta.dir, "..", "..", ".github", "workflows", "release.yml");
const waivedRef = "refs/tags/v0.9.22";

function job(workflow: string, name: string): string {
  const match = workflow.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-z-]+:|(?![\\s\\S]))`, "mu"));
  expect(match).not.toBeNull();
  return match![1]!;
}

function condition(source: string, indent: number): string {
  const prefix = " ".repeat(indent);
  const block = source.match(new RegExp(`^${prefix}if: >-\\n((?:${prefix}  .*\\n)+)`, "mu"));
  if (block) return block[1]!.trim().replace(/\s+/gu, " ");
  const inline = source.match(new RegExp(`^${prefix}if: (.+)$`, "mu"));
  expect(inline).not.toBeNull();
  return inline![1]!;
}

function stepCondition(source: string, name: string): string {
  const step = source.match(new RegExp(`^      - name: ${name}\\n(        if: .+)$`, "mu"));
  expect(step).not.toBeNull();
  return condition(step![1]!, 8);
}

// Only the literal release expressions below may be evaluated by this focused test.
function evaluate(
  expression: string,
  state: { ref: string; validation?: string; benchmark?: string; build?: string; cancelled?: boolean; target?: string },
): boolean {
  const allowed = new Set([
    `github.ref != '${waivedRef}'`,
    `always() && github.ref != '${waivedRef}'`,
    `\${{ !cancelled() && needs.validate-tag.result == 'success' && ((github.ref == '${waivedRef}' && needs.bench-live.result == 'skipped') || (github.ref != '${waivedRef}' && needs.bench-live.result == 'success')) }}`,
    "${{ !cancelled() && needs.build.result == 'success' }}",
    `matrix.target == 'x86_64-unknown-linux-gnu' && github.ref != '${waivedRef}'`,
    `matrix.target != 'x86_64-unknown-linux-gnu' || github.ref == '${waivedRef}'`,
  ]);
  expect(allowed.has(expression)).toBe(true);
  const substituted = expression
    .replace(/^\$\{\{ | \}\}$/gu, "")
    .replace(/!cancelled\(\)/gu, String(!state.cancelled))
    .replace(/always\(\)/gu, "true")
    .replace(/needs\.validate-tag\.result/gu, JSON.stringify(state.validation))
    .replace(/needs\.bench-live\.result/gu, JSON.stringify(state.benchmark))
    .replace(/needs\.build\.result/gu, JSON.stringify(state.build))
    .replace(/matrix\.target/gu, JSON.stringify(state.target))
    .replace(/github\.ref/gu, JSON.stringify(state.ref));
  expect(substituted).toMatch(/^[\s()!&|=.'"a-z0-9_/-]+$/iu);
  return Boolean(Function(`"use strict"; return (${substituted});`)());
}

test("v0.9.22 alone skips the baseline and every live benchmark/scorer job", async () => {
  const workflow = await Bun.file(workflowPath).text();
  const validate = job(workflow, "validate-tag");
  const prepare = job(workflow, "bench-live-prepare");
  const sample = job(workflow, "bench-live-sample");
  const final = job(workflow, "bench-live");
  expect(validate).toMatch(/name: Verify the attested Azure\/US Luna calibration baseline\n        if: github\.ref != 'refs\/tags\/v0\.9\.22'/u);
  expect(prepare).toContain("needs: validate-tag");
  expect(sample).toContain("needs: [validate-tag, bench-live-prepare]");
  expect(final).toContain("needs: [bench-live-prepare, bench-live-sample]");
  for (const ref of [waivedRef, "refs/tags/v0.9.220", "refs/tags/v0.9.23"]) {
    const expected = ref !== waivedRef;
    expect(evaluate(stepCondition(validate, "Verify the attested Azure/US Luna calibration baseline"), { ref })).toBe(expected);
    expect(evaluate(condition(prepare, 4), { ref })).toBe(expected);
    expect(evaluate(condition(sample, 4), { ref })).toBe(expected);
    expect(evaluate(condition(final, 4), { ref })).toBe(expected);
  }
  expect(prepare).toContain("bun run scorer-eval --json-out");
  expect(sample).toContain("bun run bench:cohort-run --");
  expect(final).toContain("bun run bench:compare --");
});

test("build admits only validated waiver skips or successful normal benchmarks", async () => {
  const workflow = await Bun.file(workflowPath).text();
  const build = job(workflow, "build");
  expect(build).toContain("needs: [validate-tag, bench-live]");
  expect(job(workflow, "release")).toContain("needs: build");
  const gate = condition(build, 4);
  for (const ref of [waivedRef, "refs/tags/v0.9.220", "refs/tags/v0.9.23"]) {
    for (const validation of ["success", "failure", "cancelled", "skipped"]) {
      for (const benchmark of ["success", "failure", "cancelled", "skipped"]) {
        for (const cancelled of [false, true]) {
          const expected = !cancelled && validation === "success" &&
            (ref === waivedRef ? benchmark === "skipped" : benchmark === "success");
          expect(evaluate(gate, { ref, validation, benchmark, cancelled })).toBe(expected);
        }
      }
    }
  }
});

test("waived GNU target builds from its tag while other releases use the benchmarked binary", async () => {
  const workflow = await Bun.file(workflowPath).text();
  const build = job(workflow, "build");
  expect(build).toContain("run: cargo build --quiet --release --target ${{ matrix.target }}");
  expect(build).toContain("name: benchmarked-x86_64-unknown-linux-gnu-${{ github.run_attempt }}");
  for (const ref of [waivedRef, "refs/tags/v0.9.220", "refs/tags/v0.9.23"]) {
    for (const target of ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]) {
      const download = evaluate(stepCondition(build, "Download benchmarked Linux binary"), { ref, target });
      const restore = evaluate(stepCondition(build, "Restore benchmarked binary mode"), { ref, target });
      const compile = evaluate(stepCondition(build, "Build release binary"), { ref, target });
      expect(download).toBe(target === "x86_64-unknown-linux-gnu" && ref !== waivedRef);
      expect(restore).toBe(download);
      expect(compile).toBe(!download);
    }
  }
});

test("publication handles skipped benchmark ancestors and requires every build to succeed", async () => {
  const workflow = await Bun.file(workflowPath).text();
  const release = job(workflow, "release");
  expect(release).toContain("needs: build");
  const gate = condition(release, 4);
  for (const build of ["success", "failure", "cancelled", "skipped"]) {
    for (const cancelled of [false, true]) {
      expect(evaluate(gate, { ref: waivedRef, build, cancelled })).toBe(!cancelled && build === "success");
    }
  }
});
