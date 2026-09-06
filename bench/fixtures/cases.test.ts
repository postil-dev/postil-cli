import { describe, expect, test } from "bun:test";
import { cases, makeDiff } from "./cases";
import { supplementalCleanCases, supplementalCleanSpecs } from "./clean-screen";
import { benchmarkCase, parseUnifiedDiffFiles } from "../src/harness";

test("supplemental modules supply complete evidence and unique clean targets", () => {
  const ids = [...cases, ...supplementalCleanCases].map((input) => input.id);
  expect(new Set(ids).size).toBe(ids.length);
  expect(supplementalCleanCases).toHaveLength(12);
  for (const input of supplementalCleanCases) {
    const parsed = benchmarkCase.parse(input);
    expect(parsed.groundTruth.findings).toEqual([]);
    expect(parsed.modelOutput.findings).toEqual([]);
    const file = parseUnifiedDiffFiles(parsed.diff).find((file) => file.path === parsed.allowedContext.files[0].path)!;
    expect(file.after.replace(/^ /gm, "").trim()).toBe(parsed.allowedContext.files[0].content.trim());
    expect(parsed.diff).toContain(parsed.allowedContext.docs[0].content);
  }
});

for (const version of ["before", "after"] as const) {
  const program = (id: string): any => {
    const spec = supplementalCleanSpecs.find((entry) => entry.id === `clean-${id}`)!;
    return new Function(`${spec[version].replace("export ", "")}; return run;`)();
  };
  describe(`supplemental clean behavior: ${version}`, () => {
    test("tenant checks allow the owner and reject a different tenant", () => {
      const run = program("tenant-guard-extraction");
      expect(run({ tenantId: "a" }, { tenantId: "a", name: "report" })).toBe("report");
      expect(() => run({ tenantId: "b" }, { tenantId: "a", name: "report" })).toThrow("Forbidden");
    });
    test("expiry includes the boundary and preserves falsy cached values", () => {
      const run = program("cache-expiry-boundary");
      expect(run(null, 10)).toBeNull();
      expect(run({ expiresAt: 10, value: false }, 9)).toBe(false);
      expect(run({ expiresAt: 10, value: "stale" }, 10)).toBeNull();
      expect(run({ expiresAt: 10, value: "stale" }, 11)).toBeNull();
    });
    test("concurrent reads preserve order and propagate rejection", async () => {
      const run = program("concurrent-result-order");
      const pending = new Map<number, (value: string) => void>();
      const result = run([1, 2], (id: number) => new Promise<string>((resolve) => pending.set(id, resolve)));
      expect([...pending.keys()]).toEqual([1, 2]);
      pending.get(2)!("second"); pending.get(1)!("first");
      expect(await result).toEqual(["first", "second"]);
      expect(await run([], () => { throw new Error("unexpected read"); })).toEqual([]);
      await expect(run([1], async () => { throw new Error("read failed"); })).rejects.toThrow("read failed");
    });
    test("cancellation reaches the request with the original signal", async () => {
      const run = program("abort-signal-forwarding");
      const controller = new AbortController();
      const result = run((_url: string, options: RequestInit) => {
        expect(options.method).toBe("GET");
        expect(options.signal).toBe(controller.signal);
        return new Promise((_resolve, reject) => options.signal!.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
      }, "https://example.test/items", controller.signal);
      controller.abort();
      await expect(result).rejects.toThrow("aborted");
    });
    test("retry budget stops at the boundary and propagates failures", async () => {
      const run = program("retry-limit-extraction");
      let calls = 0;
      const retry = async () => { calls++; return "retried"; };
      expect(await run(2, retry, 3)).toBe("retried");
      expect(await run(3, retry, 3)).toBe("exhausted");
      expect(await run(4, retry, 3)).toBe("exhausted");
      expect(calls).toBe(1);
      await expect(run(0, async () => { throw new Error("retry failed"); }, 3)).rejects.toThrow("retry failed");
    });
    test("pagination excludes the cursor without gaps or repeats", () => {
      const run = program("pagination-exclusive-cursor");
      const rows = [1, 3, 5, 8].map((id) => ({ id }));
      expect(run(rows, 1, 2)).toEqual([{ id: 3 }, { id: 5 }]);
      expect(run(rows, 5, 2)).toEqual([{ id: 8 }]);
      expect(run(rows, 8, 2)).toEqual([]);
      expect(run([], 0, 2)).toEqual([]);
    });
    test("serialization retains exact integer digits", () => {
      const run = program("bigint-json-serialization");
      for (const value of [0n, 9007199254740993n, -9007199254740993n]) {
        expect(JSON.parse(run(value))).toEqual({ totalMicros: String(value) });
      }
    });
    test("configuration distinguishes zero from missing values", () => {
      const run = program("config-preserves-zero");
      expect(run({})).toBe(3); expect(run({ retries: null })).toBe(3);
      expect(run({ retries: 0 })).toBe(0); expect(run({ retries: 5 })).toBe(5);
    });
    test("lock stays held until the write settles on success and failure", async () => {
      const run = program("lock-finally-release");
      for (const fails of [false, true]) {
        const events: string[] = [];
        let finish!: () => void;
        const result = run(async () => { events.push("lock"); return () => events.push("release"); }, async () => {
          events.push("write");
          await new Promise<void>((resolve) => { finish = resolve; });
          events.push("settled");
          if (fails) throw new Error("write failed");
          return 42;
        });
        await Promise.resolve();
        expect(events).toEqual(["lock", "write"]);
        finish();
        if (fails) await expect(result).rejects.toThrow("write failed");
        else expect(await result).toBe(42);
        expect(events).toEqual(["lock", "write", "settled", "release"]);
      }
    });
    test("untrusted query input remains a separate bound parameter", async () => {
      const run = program("parameterized-query-extraction");
      const input = "' OR 1=1 --";
      const result = await run({ query: async (sql: string, params: unknown[]) => {
        expect(sql).toBe("SELECT id FROM people WHERE name = $1");
        expect(params).toEqual([input]);
        return [{ id: 7 }];
      } }, input);
      expect(result).toEqual([{ id: 7 }]);
    });
    test("sorting preserves caller ownership and descending numeric order", () => {
      const run = program("input-array-copy-sort");
      const input = Object.freeze([2, -1, 10, 2]);
      expect(run(input)).toEqual([10, 2, 2, -1]);
      expect(input).toEqual([2, -1, 10, 2]);
      expect(run([])).toEqual([]);
    });
    test("partial updates distinguish absence, null, and inherited properties", () => {
      const run = program("optional-field-presence");
      const current = Object.freeze({ displayName: "Name", id: 1 });
      expect(run(current, {})).toEqual(current);
      expect(run(current, { displayName: null })).toEqual({ displayName: null, id: 1 });
      expect(run(current, { displayName: "" })).toEqual({ displayName: "", id: 1 });
      expect(run(current, Object.create({ displayName: "inherited" }))).toEqual(current);
    });
  });
}

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
