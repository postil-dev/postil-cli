import { describe, expect, test } from "bun:test";
import { forwardApiKey, resolveApiKeyName } from "./api-key";

describe("resolveApiKeyName", () => {
  test("preserves specific-key precedence", () => {
    expect(
      resolveApiKeyName({
        OPENROUTER_API_KEY: "openrouter-key",
        MODEL_API_KEY: "model-key",
        LLM_API_KEY: "llm-key",
      }),
    ).toBe("OPENROUTER_API_KEY");
    expect(
      resolveApiKeyName({
        POSTIL_API_KEY: "postil-key",
        OPENROUTER_API_KEY: "openrouter-key",
        MODEL_API_KEY: "model-key",
      }),
    ).toBe("POSTIL_API_KEY");
  });

  test("empty values do not shadow later aliases", () => {
    expect(
      resolveApiKeyName({
        POSTIL_API_KEY: "",
        OPENROUTER_API_KEY: " ",
        MODEL_API_KEY: "",
        LLM_API_KEY: "llm-key",
      }),
    ).toBe("LLM_API_KEY");
  });
});

describe("forwardApiKey", () => {
  test("mirrors neutral aliases into POSTIL_API_KEY for older binaries", () => {
    const env: NodeJS.ProcessEnv = {};
    const selected = forwardApiKey(env, { MODEL_API_KEY: "model-key" });
    expect(selected).toBe("MODEL_API_KEY");
    expect(env.MODEL_API_KEY).toBe("model-key");
    expect(env.POSTIL_API_KEY).toBe("model-key");
  });

  test("does not duplicate provider-specific aliases", () => {
    const env: NodeJS.ProcessEnv = {};
    const selected = forwardApiKey(env, { OPENROUTER_API_KEY: "openrouter-key" });
    expect(selected).toBe("OPENROUTER_API_KEY");
    expect(env.OPENROUTER_API_KEY).toBe("openrouter-key");
    expect(env.POSTIL_API_KEY).toBeUndefined();
  });
});
