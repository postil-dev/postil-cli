import { describe, expect, test } from "bun:test";
import { validateGeneratorPreflight } from "./cost-guard";

describe("generator qualification preflight", () => {
  test("bounds candidate count and the operator-configurable cost cap", () => {
    expect(() => validateGeneratorPreflight(["a/model"], 15)).not.toThrow();
    expect(() => validateGeneratorPreflight([], 15)).toThrow("no models");
    expect(() => validateGeneratorPreflight(["a", "b", "c", "d", "e", "f", "g"], 15)).toThrow(
      "at most 6 candidates",
    );
    expect(() => validateGeneratorPreflight(["a/model"], 26)).toThrow("at most $25");
  });
});
