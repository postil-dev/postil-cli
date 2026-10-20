import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { evaluatorSourceSha256 } from "./live";
import { calibrationMain, validateCalibrationDispatch, verifyLegacyCalibration } from "./verify-calibration";

const root = resolve(import.meta.dir, "../..");
const historicalSource = "356ba691999c737551506039d2ad4bc26c6c1354";
const historicalImport = "7ae07f4c2c62256d837860deb76e498706e3ac5b";
const historicalBytes = (source: string, path: string) =>
  execFileSync("git", ["show", `${source}:${path}`], { cwd: root });
const temporary: string[] = [];
const candidate = randomBytes(20).toString("hex");
const admission = {
  POSTIL_DISPATCH_PAIRS: "provider/generator::provider/scorer",
  POSTIL_DISPATCH_UPSTREAM_PROVIDER: "example-provider",
  POSTIL_DISPATCH_UPSTREAM_PROVIDER_ROUTE: "example-provider/route",
  POSTIL_DISPATCH_COST_CAP_USD: "70",
};

afterEach(async () => {
  for (const directory of temporary.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture() {
  const directory = await mkdtemp(resolve(tmpdir(), "postil-calibration-verifier-"));
  temporary.push(directory);
  const paths: string[] = JSON.parse(await readFile(resolve(root, "bench/evaluator-contract-sources.json"), "utf8"));
  for (const path of [...paths, "bench/baseline-us.json", "bench/baseline-us.attestation.json", "provisional-models-us.json"]) {
    await mkdir(dirname(resolve(directory, path)), { recursive: true });
    const source = paths.includes(path) ? historicalSource : historicalImport;
    await writeFile(resolve(directory, path), historicalBytes(source, path));
  }
  return directory;
}

async function transport() {
  const historicalRoot = await fixture();
  const bundle = JSON.parse(await readFile(resolve(historicalRoot, "bench/baseline-us.attestation.json"), "utf8"));
  const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
  const calls: string[][] = [];
  const runGh = async (args: string[]) => {
    calls.push(args);
    if (args[0] === "api") return statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit;
    // Injected CLI transport output tests the consumer, not cryptographic validity.
    return JSON.stringify([{ verificationResult: {
      statement, signature: { certificate: {} }, verifiedTimestamps: [{ type: "Tlog" }],
    } }]);
  };
  const runGit = async (args: string[]) => execFileSync("git", args, { cwd: root });
  return { root: historicalRoot, runGh, runGit, calls, statement };
}

test("default admission retains all four effective required inputs without granting calibration authority", async () => {
  expect(await calibrationMain(["dispatch"], admission)).toBe("mode=admission\n");
  for (const name of Object.keys(admission)) {
    await expect(calibrationMain(["dispatch"], { ...admission, [name]: " " })).rejects.toThrow("Admission requires");
  }
  expect(validateCalibrationDispatch({ POSTIL_DISPATCH_MODE: "calibration-bootstrap", POSTIL_DISPATCH_CANDIDATE_SHA: candidate }))
    .toEqual({ mode: "calibration-bootstrap", candidateSha: candidate });
});

test("malformed source, unknown mode and measurement arguments cannot be normalized into supported dispatch", async () => {
  for (const sha of [undefined, "main", candidate.toUpperCase(), `${candidate}\n`, `${candidate};echo`, candidate.slice(1)]) {
    expect(() => validateCalibrationDispatch({ POSTIL_DISPATCH_MODE: "calibration-bootstrap", POSTIL_DISPATCH_CANDIDATE_SHA: sha })).toThrow();
  }
  expect(() => validateCalibrationDispatch({ ...admission, POSTIL_DISPATCH_MODE: "unknown" })).toThrow();
  for (const args of [
    ["legacy", "--concurrency", "6"], ["dispatch", "--bounded"],
    ["bootstrap", candidate, "--concurrency", "6junk"], ["bootstrap", candidate, "--retries", "0"],
    ["bootstrap", candidate, "--scorer-model", "provider/scorer"], ["legacy", "legacy"],
  ]) await expect(calibrationMain(args, admission)).rejects.toThrow("additional arguments are unsupported");
});

test("every bootstrap source and claimed capability remains refused before candidate or provider execution", async () => {
  for (const ref of ["refs/heads/main", "refs/heads/candidate", "refs/tags/candidate"]) {
    await expect(calibrationMain(["bootstrap", candidate], {
      GITHUB_REF: ref, GITHUB_REPOSITORY: "example/fork", GITHUB_RUN_ATTEMPT: "2",
      POSTIL_CREDENTIAL_ISOLATION: "verified", OPENROUTER_API_KEY: randomBytes(32).toString("base64"),
    })).rejects.toThrow("credential isolation is UNKNOWN and no candidate is admitted");
  }
});

test("frozen historical evidence stays legacy-only and pins the actual signature verification policy", async () => {
  const context = await transport();
  const result = await verifyLegacyCalibration(context);
  expect(result).toMatchObject({ protocol: "legacy-v2", behaviorCompatibility: "UNKNOWN", observedRuntimeIdentity: "UNKNOWN", executionEnabled: false });
  const baseline = JSON.parse(await readFile(resolve(context.root, "bench/baseline-us.json"), "utf8"));
  expect(result.evaluatorSha256).toBe(baseline.corpus.evaluatorSha256);
  expect(result.workflowRunId).toBe("35951227818");
  expect(result).not.toHaveProperty("effectiveConcurrency");
  expect(result).not.toHaveProperty("behaviorSha256");
  const verification = context.calls[1]!;
  const values = Object.fromEntries(verification.flatMap((value, index) => value.startsWith("--") ? [[value, verification[index + 1]]] : []));
  expect(values["--signer-workflow"]).toBe("postil-dev/postil-cli/.github/workflows/benchmark-calibration.yml");
  expect(values["--signer-digest"]).toBe(result.sourceSha);
  expect(values["--source-digest"]).toBe(result.sourceSha);
  expect(values["--source-ref"]).toBe("refs/heads/main");
  expect(values["--cert-oidc-issuer"]).toBe("https://token.actions.githubusercontent.com");
  expect(values["--predicate-type"]).toBe("https://slsa.dev/provenance/v1");
  expect(verification).toContain("--deny-self-hosted-runners");
});

test("current evaluator sources cannot reuse the historical calibration", async () => {
  const context = await transport();
  const paths: string[] = JSON.parse(await readFile(resolve(root, "bench/evaluator-contract-sources.json"), "utf8"));
  for (const path of paths) await cp(resolve(root, path), resolve(context.root, path));
  const baseline = JSON.parse(await readFile(resolve(context.root, "bench/baseline-us.json"), "utf8"));
  expect(await evaluatorSourceSha256()).not.toBe(baseline.corpus.evaluatorSha256);
  await expect(verifyLegacyCalibration(context)).rejects.toThrow("evaluator is stale");
  expect(context.calls).toHaveLength(0);
});

test("calibration workflow verifies retained provenance before reserving a changed current-main evaluator", async () => {
  const workflow = Bun.YAML.parse(await readFile(resolve(root, ".github/workflows/benchmark-calibration.yml"), "utf8")) as {
    jobs: { validate: { steps: { name?: string; run?: string }[] } };
  };
  const steps = workflow.jobs.validate.steps;
  const script = (name: string) => {
    const step = steps.find(value => value.name === name);
    expect(step?.run).toBeDefined();
    return step!.run!;
  };
  const initial = script("Verify the current main calibration source");
  const validation = script("Verify the calibration baseline input");
  const reservation = script("Reserve the current main calibration source");
  expect(steps.findIndex(step => step.name === "Verify embedded model admission")).toBeLessThan(
    steps.findIndex(step => step.name === "Verify the calibration baseline input"),
  );
  expect(steps.findIndex(step => step.name === "Verify the calibration baseline input")).toBeLessThan(
    steps.findIndex(step => step.name === "Reserve the current main calibration source"),
  );
  const directory = await fixture();
  const baselinePath = resolve(directory, "bench/baseline-us.json");
  const baselineBytes = await readFile(baselinePath);
  const baseline = JSON.parse(baselineBytes.toString());
  const source = baseline.profiles["openai/gpt-5.6-luna"].calibration.sourceSha;
  const bin = resolve(directory, "bin");
  await mkdir(bin);
  const callsPath = resolve(directory, "calls");
  const shim = resolve(bin, "gh");
  await writeFile(shim, `#!/bin/bash
set -euo pipefail
printf '%s\\t' "$@" >> "$CALLS_FILE"
printf '\\n' >> "$CALLS_FILE"
if [[ "$1" == api ]]; then
  case "$*" in
    *'--method POST'*) exit "$RESERVATION_EXIT" ;;
    *'heads/main'*) printf '%s' "$MAIN_SHA" ;;
    *) printf '%s' "$REGISTRY_SHA" ;;
  esac
else
  exit "$VERIFICATION_EXIT"
fi
`);
  await chmod(shim, 0o700);
  const currentEvaluator = await evaluatorSourceSha256();
  const run = async (options: Record<string, string> = {}) => {
    await writeFile(callsPath, "");
    const child = Bun.spawn(["bash", "-c", initial + "\n(\n" + validation + "\n)\n" + reservation], {
      cwd: directory, stdout: "pipe", stderr: "pipe", timeout: 10_000,
      env: {
        PATH: `${bin}:${process.env.PATH}`, CALLS_FILE: callsPath,
        GITHUB_REF: "refs/heads/main", GITHUB_RUN_ATTEMPT: "1", GITHUB_SHA: candidate,
        GITHUB_REPOSITORY: "postil-dev/postil-cli", MAIN_SHA: candidate,
        REGISTRY_SHA: source, VERIFICATION_EXIT: "0", RESERVATION_EXIT: "0",
        CURRENT_EVALUATOR_SHA256: currentEvaluator, ...options,
      },
    });
    const [code, stdout, stderr] = await Promise.all([
      child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
    ]);
    const calls = (await readFile(callsPath, "utf8")).trim().split("\n").filter(Boolean).map(line => line.trim().split("\t"));
    return { code, output: stdout + stderr, calls };
  };
  const accepted = await run();
  expect(accepted.code).toBe(0);
  const verification = accepted.calls.find(args => args[0] === "attestation")!;
  expect(verification).toEqual([
    "attestation", "verify", "bench/baseline-us.json", "--bundle", "bench/baseline-us.attestation.json",
    "--repo", "postil-dev/postil-cli", "--signer-workflow", "postil-dev/postil-cli/.github/workflows/benchmark-calibration.yml",
    "--signer-digest", source, "--source-digest", source, "--source-ref", "refs/heads/main",
    "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--predicate-type", "https://slsa.dev/provenance/v1",
    "--deny-self-hosted-runners", "--format", "json",
  ]);
  expect(accepted.calls.at(-1)).toContain(`ref=refs/tags/postil-calibration-${candidate}`);
  for (const [options, message] of [
    [{ GITHUB_REF: "refs/heads/topic" }, "only from main"],
    [{ GITHUB_RUN_ATTEMPT: "2" }, "retries are not authoritative"],
    [{ MAIN_SHA: source }, "not the current main commit"],
    [{ GITHUB_SHA: source, MAIN_SHA: source }, "requires a new main source commit"],
    [{ CURRENT_EVALUATOR_SHA256: baseline.corpus.evaluatorSha256 }, "changed evaluator contract"],
    [{ CURRENT_EVALUATOR_SHA256: "invalid" }, "evaluator digest is invalid"],
    [{ REGISTRY_SHA: candidate }, "registry source mismatch"],
    [{ VERIFICATION_EXIT: "1" }, ""],
  ] as const) {
    const refused = await run(options);
    expect(refused.code).not.toBe(0);
    expect(refused.output).toContain(message);
    expect(refused.calls.some(args => args.includes("POST"))).toBe(false);
  }
  expect((await run({ RESERVATION_EXIT: "1" })).code).not.toBe(0);
  for (const update of [
    { profiles: {} },
    { profiles: { "openai/gpt-5.6-luna": { populated: "false" } } },
    { profiles: { "openai/gpt-5.6-luna": { populated: true, calibration: { sourceSha: "invalid" } } } },
    { ...baseline, corpus: { evaluatorSha256: "invalid" } },
  ]) {
    await writeFile(baselinePath, JSON.stringify(update));
    const refused = await run();
    expect(refused.code).not.toBe(0);
    expect(refused.calls.some(args => args.includes("POST"))).toBe(false);
  }
  await writeFile(baselinePath, baselineBytes);
  const retainedBundlePath = resolve(directory, "bench/baseline-us.attestation.json");
  const retainedBundleBytes = await readFile(retainedBundlePath);
  await writeFile(retainedBundlePath, "");
  const missingBundle = await run();
  expect(missingBundle.output).toContain("requires the retained baseline attestation");
  expect(missingBundle.calls.some(args => args.includes("POST"))).toBe(false);
  await writeFile(baselinePath, baselineBytes);
  await writeFile(retainedBundlePath, retainedBundleBytes);
  const restored = await run();
  expect(restored.code).toBe(0);
  expect(restored.calls.find(args => args[0] === "attestation")).toEqual(verification);
  expect(await readFile(baselinePath)).toEqual(baselineBytes);
  expect(await readFile(retainedBundlePath)).toEqual(retainedBundleBytes);
  // The exact retained current pair also supports a later changed evaluator.
  const currentPair = await readFile(resolve(root, "bench/baseline-us.json"));
  const currentBundle = await readFile(resolve(root, "bench/baseline-us.attestation.json"));
  const currentSource = JSON.parse(currentPair.toString()).profiles["openai/gpt-5.6-luna"].calibration.sourceSha;
  await writeFile(baselinePath, currentPair);
  await writeFile(retainedBundlePath, currentBundle);
  const restoredCurrent = await run({ REGISTRY_SHA: currentSource });
  expect(restoredCurrent.code).toBe(0);
  const currentVerification = restoredCurrent.calls.find(args => args[0] === "attestation")!;
  expect(currentVerification[currentVerification.indexOf("--source-digest") + 1]).toBe(currentSource);
  expect(await readFile(baselinePath)).toEqual(currentPair);
  expect(await readFile(retainedBundlePath)).toEqual(currentBundle);
  await writeFile(baselinePath, JSON.stringify({ profiles: { "openai/gpt-5.6-luna": { populated: false } } }));
  const bootstrap = await run();
  expect(bootstrap.code).toBe(0);
  expect(bootstrap.calls.some(args => args[0] === "attestation")).toBe(false);
});

test("source rollback restores the exact historical pair and refuses partial or cross-paired restoration", async () => {
  const context = await transport();
  const sourcePath = resolve(context.root, "bench/src/live.ts");
  const baselinePath = resolve(context.root, "bench/baseline-us.json");
  const bundlePath = resolve(context.root, "bench/baseline-us.attestation.json");
  const [source, baseline, bundle] = await Promise.all([readFile(sourcePath), readFile(baselinePath), readFile(bundlePath)]);
  const original = await verifyLegacyCalibration(context);
  await cp(resolve(root, "bench/src/live.ts"), sourcePath);
  await expect(verifyLegacyCalibration(context)).rejects.toThrow("evaluator is stale");
  // An incomplete source/pair rollback and a substituted pair remain refused.
  await writeFile(baselinePath, JSON.stringify({ ...JSON.parse(baseline.toString()), schemaVersion: 3 }));
  await writeFile(sourcePath, source);
  await expect(verifyLegacyCalibration(context)).rejects.toThrow("Unsupported legacy calibration artifact pair");
  await writeFile(baselinePath, baseline);
  await writeFile(bundlePath, JSON.stringify({ dsseEnvelope: { payload: "cross-paired" } }));
  await expect(verifyLegacyCalibration(context)).rejects.toThrow("Unsupported legacy calibration artifact pair");
  await writeFile(bundlePath, bundle);
  expect(await verifyLegacyCalibration(context)).toEqual(original);
  expect(await readFile(baselinePath)).toEqual(baseline);
  expect(await readFile(bundlePath)).toEqual(bundle);
  expect(context.calls.at(-1)).toContain("--source-digest");
});

test("actual evaluator, effective-launch and workflow mutations invalidate legacy freshness", async () => {
  const directory = await fixture();
  const context = await transport();
  for (const [path, before, after] of [
    ["bench/src/harness.ts", "export", "/* altered confidence acceptance */ export"],
    ["bench/src/cohort-run.ts", '"--live",', '"--live", "--concurrency", "1",'],
    [".github/workflows/benchmark-calibration.yml", "workflow_dispatch: {}", "workflow_dispatch: { inputs: { candidate_sha: { required: true } } }"],
    ["bench/bun.lock", "zod", "changed-zod"],
  ]) {
    const file = resolve(directory, path);
    const original = await readFile(file, "utf8");
    expect(original.includes(before)).toBe(true);
    await writeFile(file, original.replace(before, after));
    await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("evaluator is stale");
    await writeFile(file, original);
  }
  expect(context.calls).toHaveLength(0);
});

test("fake attestation, modified baseline and invented legacy parameters cannot enter the frozen adapter", async () => {
  const directory = await fixture();
  const context = await transport();
  const baselinePath = resolve(directory, "bench/baseline-us.json");
  const baselineBytes = await readFile(baselinePath);
  const baseline = JSON.parse(baselineBytes.toString());
  for (const update of [
    { schemaVersion: 3 }, { effectiveConcurrency: 6 },
    { corpus: { ...baseline.corpus, behaviorSha256: randomBytes(32).toString("hex") } },
  ]) {
    await writeFile(baselinePath, JSON.stringify({ ...baseline, ...update }));
    await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("Unsupported legacy calibration artifact pair");
  }
  await writeFile(baselinePath, baselineBytes);
  await writeFile(resolve(directory, "bench/baseline-us.attestation.json"), JSON.stringify({ dsseEnvelope: { payload: "fabricated" } }));
  await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("Unsupported legacy calibration artifact pair");
  expect(context.calls).toHaveLength(0);
});

test("historical blob mutation, registry substitution, failed verification and wrong verified statement are refused", async () => {
  const context = await transport();
  await expect(verifyLegacyCalibration({ ...context, runGit: async () => Buffer.from("substituted source") })).rejects.toThrow("Historical calibration source inventory");
  await expect(verifyLegacyCalibration({ ...context, runGh: async () => candidate })).rejects.toThrow("registry source mismatch");
  for (const response of ["[]", "[{}]", JSON.stringify([{ verificationResult: { statement: context.statement } }])]) {
    await expect(verifyLegacyCalibration({ ...context, runGh: async args => args[0] === "api" ? context.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit : response }))
      .rejects.toThrow("exact cryptographically verified statement");
  }
  const wrappedGh = async (args: string[]) => {
    const response = await context.runGh(args);
    if (args[0] === "api") return response;
    const verified = JSON.parse(response);
    verified[0].verificationResult.statement.predicate.runDetails.metadata.invocationId += "/wrong-attempt";
    return JSON.stringify(verified);
  };
  await expect(verifyLegacyCalibration({ ...context, runGh: wrappedGh })).rejects.toThrow("exact cryptographically verified statement");
  await expect(verifyLegacyCalibration({ ...context, runGh: async args => {
    if (args[0] === "api") return context.runGh(args);
    throw new Error("verification failed");
  } })).rejects.toThrow("verification failed");
});

test("manifest substitution and symlink subjects are rejected before external verification", async () => {
  const directory = await fixture();
  const context = await transport();
  const file = resolve(directory, "bench/evaluator-contract-sources.json");
  await writeFile(file, JSON.stringify(["../outside-repository"]));
  await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("Unsupported legacy evaluator manifest");
  await rm(file);
  await symlink(resolve(root, "bench/evaluator-contract-sources.json"), file);
  await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("regular file");
  expect(context.calls).toHaveLength(0);
});

test("profile drift cannot retain legacy acceptance", async () => {
  const directory = await fixture();
  const context = await transport();
  const profilePath = resolve(directory, "provisional-models-us.json");
  const originalProfile = await readFile(profilePath);
  await writeFile(profilePath, Buffer.concat([originalProfile, Buffer.from("\n")]));
  await expect(verifyLegacyCalibration({ ...context, root: directory })).rejects.toThrow("screening profile");
});

test("a source change during successful attestation transport cannot retain legacy acceptance", async () => {
  const directory = await fixture();
  const context = await transport();
  const runGh = async (args: string[]) => {
    const output = await context.runGh(args);
    if (args[0] === "attestation") await writeFile(resolve(directory, "bench/src/cohort-run.ts"), "changed during verification");
    return output;
  };
  await expect(verifyLegacyCalibration({ ...context, root: directory, runGh })).rejects.toThrow("changed during verification");
});

test("parsed workflow isolates bootstrap from admission credentials and signing permissions", async () => {
  const workflow = Bun.YAML.parse(await readFile(resolve(root, ".github/workflows/bench-live.yml"), "utf8")) as any;
  expect(workflow.on.workflow_dispatch.inputs.mode.default).toBe("admission");
  for (const jobName of ["validate-dispatch", "calibration-bootstrap"]) {
    const job = workflow.jobs[jobName];
    expect(job.permissions).toEqual({ contents: "read" });
    expect(job.env).toBeUndefined();
    expect(JSON.stringify(job)).not.toContain("secrets.");
    expect(job.steps.filter((step: any) => step.uses?.startsWith("actions/checkout@")).every((step: any) => step.with["persist-credentials"] === false)).toBe(true);
    expect(job.steps.every((step: any) => !step.uses?.startsWith("actions/cache@") && !step.uses?.startsWith("actions/attest@"))).toBe(true);
    expect(job.steps.filter((step: any) => step.uses?.startsWith("oven-sh/setup-bun@"))[0].with["bun-version"]).toBe("1.3.14");
  }
  expect(workflow.jobs["bench-live"].needs).toBe("validate-dispatch");
  expect(workflow.jobs["bench-live"].if).toBe("needs.validate-dispatch.outputs.mode == 'admission'");
  expect(workflow.jobs["calibration-bootstrap"].if).toBe("needs.validate-dispatch.outputs.mode == 'calibration-bootstrap'");
});

test("actual bootstrap command exposes neither generated canaries nor a success artifact", async () => {
  const canary = randomBytes(32).toString("base64");
  const child = Bun.spawn([process.execPath, "run", resolve(import.meta.dir, "verify-calibration.ts"), "bootstrap", candidate], {
    env: { PATH: process.env.PATH, OPENROUTER_API_KEY: canary, ACTIONS_ID_TOKEN_REQUEST_TOKEN: canary },
    stdout: "pipe", stderr: "pipe", timeout: 10_000,
  });
  const [exit, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
  expect(exit).toBe(1);
  expect(stdout).toBe("");
  expect(stderr).toContain("credential isolation is UNKNOWN");
  expect(stderr.includes(canary)).toBe(false);
});
