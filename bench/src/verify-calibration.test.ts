import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { evaluatorSourceSha256 } from "./live";
import { calibrationMain, validateCalibrationDispatch, verifyLegacyCalibration } from "./verify-calibration";

const root = resolve(import.meta.dir, "../..");
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
    await cp(resolve(root, path), resolve(directory, path));
  }
  return directory;
}

async function transport() {
  const bundle = JSON.parse(await readFile(resolve(root, "bench/baseline-us.attestation.json"), "utf8"));
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
  return { runGh, runGit, calls, statement };
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
  expect(result.evaluatorSha256).toBe(await evaluatorSourceSha256());
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
