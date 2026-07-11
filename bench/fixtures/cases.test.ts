import { describe, expect, test } from "bun:test";
import { makeDiff } from "./cases";

describe("makeDiff", () => {
  test("uses one-line hunk counts for one-line fixtures", () => {
    const diff = makeDiff("src/example.ts", [{ line: 10, before: "return old;", after: "return next;" }]);
    expect(diff).toContain("@@ -10,1 +10,1 @@");
  });

  test("uses real hunk line counts for multiline fixtures", () => {
    const diff = makeDiff("src/example.ts", [
      { line: 10, before: "const a = 1;\nreturn a;", after: "const a = 1;\nconst b = 2;\nreturn a + b;" },
    ]);
    expect(diff).toContain("@@ -10,2 +10,3 @@");
    expect(diff).toContain("- const a = 1;\n- return a;\n+ const a = 1;\n+ const b = 2;\n+ return a + b;");
  });
});
