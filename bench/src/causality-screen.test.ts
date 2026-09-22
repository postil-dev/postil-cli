import { expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { cases } from "../fixtures/cases";
import { causalityScreenCases, causalitySource, causalitySpecs } from "../fixtures/causality-screen";
import { benchmarkCase, parseUnifiedDiffFiles } from "./harness";

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
