import { expect, test } from "bun:test";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { cases } from "../fixtures/cases";
import { causalityScreenCases, causalitySource, causalitySpecs } from "../fixtures/causality-screen";
import { benchmarkCase, parseUnifiedDiffFiles } from "./harness";
import { runLive } from "./live";

function moduleAt(index: number, side: "before" | "after", name: string) {
  const source = causalitySource(causalitySpecs[index], side).replaceAll("export ", "");
  return new Function(`${source}\nreturn ${name};`)();
}

test("supplemental cases preserve context markers, source reconstruction and release isolation", async () => {
  const manifest = JSON.parse(await readFile(new URL("../evaluator-contract-sources.json", import.meta.url), "utf8"));
  expect(manifest).not.toContain("bench/fixtures/causality-screen.ts");
  expect(manifest).not.toContain("bench/src/causality-screen.test.ts");
  expect(cases).toHaveLength(70);
  expect(causalityScreenCases).toHaveLength(5);
  for (const [index, input] of causalityScreenCases.entries()) {
    benchmarkCase.parse(input);
    expect(cases.some((original) => original.id === input.id)).toBe(false);
    const [file] = parseUnifiedDiffFiles(input.diff);
    expect(file.before.trimEnd()).toBe(causalitySource(causalitySpecs[index], "before"));
    expect(file.after.trimEnd()).toBe(causalitySource(causalitySpecs[index], "after"));
  }
  expect(causalitySpecs[0].lines).toContain(" const ALLOW_ALL_USERS = true;");
  expect(causalitySpecs[3].lines).toContain("   return renderHtml(value);");
  expect(causalitySpecs[4].lines.some((line) => line.startsWith("+"))).toBe(false);
});

test("unchanged intended policy and unrelated existing flaw do not acquire a changed cause", () => {
  const member = { workspace: "selected", admin: false };
  const outsider = { workspace: "other", admin: false };
  for (const side of ["before", "after"] as const) {
    expect(moduleAt(0, side, "allowed")(member, "selected")).toBe(true);
    expect(moduleAt(0, side, "allowed")(outsider, "selected")).toBe(false);
    expect(moduleAt(1, side, "allowed")(outsider, "selected")).toBe(true);
  }
});

test("new authorization bypass remains harmful despite contradictory intent prose", () => {
  const member = { workspace: "selected", admin: false };
  expect(moduleAt(2, "before", "allowed")(member, "selected")).toBe(false);
  expect(moduleAt(2, "after", "allowed")(member, "selected")).toBe(true);
});

test("changed input causes injection at an unchanged rendering sink", () => {
  const input = "<script>alert(1)</script>";
  expect(moduleAt(3, "before", "greet")(input)).not.toContain("<script>");
  expect(moduleAt(3, "after", "greet")(input)).toContain("<script>");
});

test("deleting a guard changes access even without an added source line", () => {
  const records = ["private audit record"];
  expect(() => moduleAt(4, "before", "readAudit")({ admin: false }, records)).toThrow("Forbidden");
  expect(moduleAt(4, "after", "readAudit")({ admin: false }, records)).toEqual(records);
});

test("actual binary defers scope exclusion to scoring under the unchanged live contract", async () => {
  const binary = resolve(process.env.POSTIL_BIN ?? join(process.env.CARGO_TARGET_DIR ?? resolve(import.meta.dir, "../..", "target"), "release/postil"));
  const profilePath = resolve(import.meta.dir, "../../provisional-models.json");
  const profile = JSON.parse(await readFile(profilePath, "utf8"));
  const model = profile.generatorChain[0];
  const root = await mkdtemp(join(tmpdir(), "postil-scope-scoring-"));
  const names = ["OPENROUTER_API_KEY", "POSTIL_API_KEY", "MODEL_API_KEY", "LLM_API_KEY", "OPENAI_API_KEY", "POSTIL_API_BASE", "POSTIL_API_FORMAT", "POSTIL_LLM_REQUEST_TIMEOUT_SECS", "POSTIL_LLM_TOTAL_TIMEOUT_SECS"];
  const saved = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  const nativeFetch = globalThis.fetch;
  const evidence = [];
  try {
    for (const name of names) delete process.env[name];
    process.env.OPENROUTER_API_KEY = randomUUID();
    process.env.POSTIL_API_BASE = profile.apiBase;
    process.env.POSTIL_API_FORMAT = profile.apiFormat;
    for (const mode of ["low", "high", "missing", "failed", "unaccounted", "added", "changed-input", "removed"] as const) {
      const index = mode === "added" ? 2 : mode === "changed-input" ? 3 : mode === "removed" ? 4 : 1;
      const input = causalityScreenCases[index];
      const preExisting = index === 1;
      const phases: string[] = [];
      globalThis.fetch = (async (url, init) => {
        expect(String(url)).toBe(new URL(`${profile.apiBase}/chat/completions`).href);
        expect(init?.method).toBe("POST");
        expect(init?.body).toBeInstanceOf(ArrayBuffer);
        const request = JSON.parse(new TextDecoder().decode(init!.body as ArrayBuffer));
        const system = request.messages.find((message: { role: string }) => message.role === "system").content;
        let content;
        if (system.startsWith("You are Postil's single finding adjudicator.")) {
          phases.push("adjudicator");
          const payload = JSON.parse(request.messages.at(-1).content);
          content = payload.candidates.map((candidate: Record<string, unknown>) => ({
            candidateId: candidate.candidateId, status: "confirmed", revisedTitle: candidate.title,
            revisedBody: candidate.body, evidence: candidate.citedEvidence, duplicateOf: null,
            ...(preExisting ? { scope: { disposition: "preExisting", cause: null, reason: "The authorization defect predates the unrelated notification timeout edit." } }
              : index === 3 ? { scope: { disposition: "introducedOrWorsened", cause: { path: "src/greeting.js", side: "added", line: 5, byteOffset: 0, evidence: "  const value = name;" }, reason: "The changed input reaches the unchanged HTML renderer without escaping." } }
                : index === 4 ? { scope: { disposition: "introducedOrWorsened", cause: { path: "src/audit.js", side: "removed", line: 3, byteOffset: 0, evidence: "  if (!actor.admin) throw new Error('Forbidden');" }, reason: "The deleted guard exposes the unchanged return to unauthorized callers." } } : {}),
          }));
        } else if (system.startsWith("You are Postil's independent second-model scorer.")) {
          phases.push("scorer");
          const text = request.messages.at(-1).content;
          const findings = JSON.parse(text.slice(text.indexOf("[")));
          expect(findings).toHaveLength(1);
          if (preExisting) {
            expect(findings[0].scopeEvidence.disposition).toBe("preExisting");
            expect(findings[0].scopeEvidence.anchorRole).toBe("context");
            expect(findings[0].scopeEvidence.cause).toBeNull();
          }
          if (mode === "failed") return Response.json({ error: { code: 400, message: "Scoring is unavailable." } }, { status: 400 });
          content = { scores: mode === "missing" ? [] : [{ confidence: preExisting && mode !== "high" ? 0.1 : 0.99, kind: "risk", reason: preExisting ? "The authorization defect predates the unrelated timeout edit." : "The change introduces the stated security defect." }] };
        } else {
          expect(system).toContain("Postil");
          phases.push("generator");
          content = preExisting ? { summary: "", findings: [{ path: "src/access.js", line: 2, severity: "error", kind: "risk", confidence: 0.99, title: "Enforce the workspace boundary", body: "The enabled flag grants outsiders access to audit records. Restrict access to the selected workspace.", evidence: "const ALLOW_ALL_USERS = true;" }] } : input.modelOutput;
        }
        const id = `gen-${randomUUID()}`;
        return Response.json({ id, model, provider: profile.upstreamProviderIdentity, choices: [{ finish_reason: "stop", message: { role: "assistant", content: JSON.stringify(content) } }],
          ...(mode === "unaccounted" && phases.at(-1) === "scorer" ? {} : { usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15, cost: 0.000001 } }),
        }, { headers: { "x-generation-id": id } });
      }) as typeof fetch;
      const report = await runLive([input], { binary, model, scorerModel: model, screenProfilePath: profilePath, rootDir: root, runId: mode, concurrency: 1, retries: 0, timeoutMs: 15000, bounded: false, selectedCaseIds: [input.id] });
      await writeFile(join(root, `${mode}.json`), JSON.stringify({ phases, report }, null, 2), { mode: 0o600 });
      evidence.push({ mode, phases, result: report.results[0] });
      expect(phases).toContain("adjudicator");
      expect(phases).toContain("scorer");
      if (["high", "missing", "failed", "unaccounted"].includes(mode)) {
        expect(report.results[0].error).toBe(`operational envelope: scorer/${mode === "failed" ? "providerError" : "invalidOutput"}`);
        expect(report.results[0].scored).toBe(false);
      } else {
        expect(phases).toEqual(["generator", "adjudicator", "scorer"]);
        expect(report.results[0].error).toBeUndefined();
        expect(report.results[0].scored).toBe(true);
        expect(report.results[0].costAccountingComplete).toBe(true);
        if (preExisting) expect(report.results[0].falsePositives).toBe(0);
        else expect(report.results[0].detected).toBe(true);
      }
    }
  } finally {
    globalThis.fetch = nativeFetch;
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    await writeFile(join(root, "result.json"), JSON.stringify({ binary, providerCalls: 0, transport: "in-memory responses", evidence }, null, 2), { mode: 0o600 });
  }
}, 150000);
