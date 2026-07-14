import { describe, expect, test } from "bun:test";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { cases as fixtureInputs } from "../fixtures/cases";
import { benchmarkCase } from "./harness";
import {
  admissionManifestCandidate,
  assertExactQualificationFixtures,
  endpointAuthFromEnvironment,
  EVALUATOR_CONTRACT_SOURCE_PATHS,
  fetchPricing,
  formatLiveModelsReport,
  hashNamedSources,
  liveEnv,
  liveModelsQualificationExitCode,
  modelPriceBoundsFor,
  normalizeApiBase,
  normalizeQualificationPairs,
  parseQualificationPairs,
  qualificationProfileDigest,
  runLiveModels,
  type LiveModelsReport,
} from "./livemodels";
import type { QualificationPair } from "./livemodels-score";

const pair: QualificationPair = { generatorModel: "test/generator", scorerModel: "test/scorer" };

async function listen(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ origin: string; server: Server }> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address() as AddressInfo;
  return { origin: `http://127.0.0.1:${address.port}`, server };
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

describe("pair qualification configuration", () => {
  test("requires and normalizes exact generator/scorer pairs", () => {
    expect(parseQualificationPairs(" a/generator::b/scorer ")).toEqual([
      {
        generatorModel: "a/generator",
        generatorCascade: [],
        consensus: 1,
        scorerModel: "b/scorer",
        scorerCascade: [],
      },
    ]);
    expect(parseQualificationPairs("a/one+b/two+c/three::s/scorer")).toEqual([{
      generatorModel: "a/one",
      generatorCascade: ["b/two", "c/three"],
      consensus: 3,
      scorerModel: "s/scorer",
      scorerCascade: [],
    }]);
    expect(parseQualificationPairs("a/one+b/two::1::s/one+s/two")).toEqual([{
      generatorModel: "a/one",
      generatorCascade: ["b/two"],
      consensus: 1,
      scorerModel: "s/one",
      scorerCascade: ["s/two"],
    }]);
    expect(() => parseQualificationPairs("a/generator")).toThrow(
      "generators::scorer+fallback or generators::consensus::scorer+fallback",
    );
    expect(() => parseQualificationPairs("a/generator::1::s/scorer::ignored")).toThrow(
      "generators::scorer+fallback or generators::consensus::scorer+fallback",
    );
    expect(normalizeQualificationPairs([pair, { ...pair }])).toEqual([{
      ...pair,
      generatorCascade: [],
      consensus: 1,
      scorerCascade: [],
    }]);
    expect(() => normalizeQualificationPairs([])).toThrow("at least one generator+scorer pair");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      scorerModel: "s/one",
      scorerCascade: ["s/two", "s/three"],
    }])).toThrow("exactly one ordered fallback");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      generatorCascade: ["a/generator"],
      scorerModel: "s/scorer",
    }])).toThrow("generator chain must not repeat");

    for (const malformed of [
      "a/generator::s/scorer,",
      ",a/generator::s/scorer",
      "a/generator::s/scorer,,b/generator::s/scorer",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("empty pair component");
    }
    for (const malformed of [
      "+a/generator::s/scorer",
      "a/generator+::s/scorer",
      "a/generator++b/fallback::s/scorer",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("generator chain contains an empty model component");
    }
    for (const malformed of [
      "a/generator::+s/scorer",
      "a/generator::s/scorer+",
      "a/generator::s/scorer++s/fallback",
    ]) {
      expect(() => parseQualificationPairs(malformed)).toThrow("scorer chain contains an empty model component");
    }
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      generatorCascade: [" "],
      scorerModel: "s/scorer",
    }])).toThrow("generator chain contains an empty model component");
    expect(() => normalizeQualificationPairs([{
      generatorModel: "a/generator",
      scorerModel: "s/scorer",
      scorerCascade: [""],
    }])).toThrow("scorer chain contains an empty model component");
  });

  test("forces the exact pair and no fallback model", () => {
    const env = liveEnv(
      "/tmp/home",
      "/tmp/tmp",
      "http://github.test",
      pair,
      "https://openrouter.ai/api/v1",
    );
    expect(env).toMatchObject({
      REVIEW_MODEL: pair.generatorModel,
      REVIEW_MODEL_CASCADE: pair.generatorModel,
      REVIEW_MODEL_CONSENSUS: "1",
      REVIEW_SCORER_MODEL: pair.scorerModel,
      POSTIL_API_FORMAT: "openai-compatible",
    });
    expect(env.POSTIL_DISABLE_SCORER).toBeUndefined();
  });

  test("forwards validated endpoint authentication without exposing managed headers", () => {
    const inheritedHeader = process.env.POSTIL_ENDPOINT_AUTH_HEADER;
    const inheritedValue = process.env.POSTIL_ENDPOINT_AUTH_VALUE;
    try {
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Private-Auth";
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "opaque credential";
      expect(endpointAuthFromEnvironment("openai-compatible")).toEqual({
        header: "X-Private-Auth",
        value: "opaque credential",
      });
      expect(liveEnv("/tmp/home", "/tmp/tmp", "http://github.test", pair, "https://models.test/v1"))
        .toMatchObject({
          POSTIL_ENDPOINT_AUTH_HEADER: "X-Private-Auth",
          POSTIL_ENDPOINT_AUTH_VALUE: "opaque credential",
        });
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "Authorization";
      expect(() => endpointAuthFromEnvironment("openai-compatible")).toThrow("provider-managed");
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "Bad Header";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("valid HTTP header name");
      process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Private-Auth";
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "bad\r\nvalue";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("valid HTTP header value");
      delete process.env.POSTIL_ENDPOINT_AUTH_HEADER;
      process.env.POSTIL_ENDPOINT_AUTH_VALUE = "value-only";
      expect(() => endpointAuthFromEnvironment("anthropic")).toThrow("HEADER must be set");
    } finally {
      if (inheritedHeader === undefined) delete process.env.POSTIL_ENDPOINT_AUTH_HEADER;
      else process.env.POSTIL_ENDPOINT_AUTH_HEADER = inheritedHeader;
      if (inheritedValue === undefined) delete process.env.POSTIL_ENDPOINT_AUTH_VALUE;
      else process.env.POSTIL_ENDPOINT_AUTH_VALUE = inheritedValue;
    }
  });

  test("canonicalizes the provider endpoint exactly like the runtime", () => {
    expect(normalizeApiBase("HTTPS://OpenRouter.AI/api/v1/")).toBe(
      "https://openrouter.ai:443/api/v1",
    );
    expect(() => normalizeApiBase("https://example.test/v1?route=x")).toThrow(
      "must not contain a query or fragment",
    );
  });

  test("enforces cost and candidate bounds before execution", async () => {
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs: [pair],
      pricing: new Map(),
      costCapUsd: 26,
    })).rejects.toThrow("cost cap must be greater than zero and at most $25");

    const pairs = Array.from({ length: 7 }, (_, index) => ({
      generatorModel: `generator/${index}`,
      scorerModel: `scorer/${index}`,
    }));
    await expect(runLiveModels([], {
      binary: "/missing/postil",
      pairs,
      pricing: new Map(),
    })).rejects.toThrow("at most 6 candidates");

    const inheritedKey = process.env.POSTIL_API_KEY;
    process.env.POSTIL_API_KEY = "test-only-key";
    try {
      await expect(runLiveModels(fixtureInputs, {
        binary: "/missing/postil",
        pairs: [{ generatorModel: "costly/model", scorerModel: "cheap/scorer" }],
        pricing: new Map([
          ["costly/model", {
            promptUsdPerToken: 0.001, completionUsdPerToken: 0.001,
            inputMicrosPerMillionTokens: 1_000_000_000, outputMicrosPerMillionTokens: 1_000_000_000,
          }],
          ["cheap/scorer", {
            promptUsdPerToken: 0.000001, completionUsdPerToken: 0.000001,
            inputMicrosPerMillionTokens: 1_000_000, outputMicrosPerMillionTokens: 1_000_000,
          }],
        ]),
        costCapUsd: 1,
      })).rejects.toThrow("projected pair qualification spend");
    } finally {
      if (inheritedKey === undefined) delete process.env.POSTIL_API_KEY;
      else process.env.POSTIL_API_KEY = inheritedKey;
    }
  });
});

describe("pricing transport isolation", () => {
  test("rejects redirects without forwarding provider or endpoint credentials", async () => {
    const keyNames = ["MODEL_API_KEY", "LLM_API_KEY", "OPENROUTER_API_KEY", "POSTIL_API_KEY"] as const;
    const authNames = ["POSTIL_ENDPOINT_AUTH_HEADER", "POSTIL_ENDPOINT_AUTH_VALUE"] as const;
    const inherited = new Map([...keyNames, ...authNames].map((name) => [name, process.env[name]]));
    for (const name of [...keyNames, ...authNames]) delete process.env[name];

    const targetRequests: IncomingMessage[] = [];
    const target = await listen((request, response) => {
      targetRequests.push(request);
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"data":[]}');
    });
    try {
      for (const scenario of [
        { format: "openai-compatible" as const, status: 301, providerHeader: "authorization" },
        { format: "anthropic" as const, status: 302, providerHeader: "x-api-key" },
        { format: "openai-compatible" as const, status: 303, providerHeader: "authorization" },
        { format: "anthropic" as const, status: 307, providerHeader: "x-api-key" },
        { format: "openai-compatible" as const, status: 308, providerHeader: "authorization" },
      ]) {
        process.env.MODEL_API_KEY = "test-provider-credential";
        process.env.POSTIL_ENDPOINT_AUTH_HEADER = "X-Endpoint-Auth";
        process.env.POSTIL_ENDPOINT_AUTH_VALUE = "test-endpoint-credential";
        let sourceHeaders: IncomingMessage["headers"] | undefined;
        const source = await listen((request, response) => {
          sourceHeaders = request.headers;
          response.writeHead(scenario.status, { location: `${target.origin}/captured` });
          response.end();
        });
        try {
          await expect(fetchPricing(`${source.origin}/v1`, scenario.format, ["provider/model"]))
            .rejects.toThrow("pricing redirects are not allowed");
          expect(sourceHeaders?.[scenario.providerHeader]).toBe(
            scenario.format === "openai-compatible"
              ? "Bearer test-provider-credential"
              : "test-provider-credential",
          );
          expect(sourceHeaders?.["x-endpoint-auth"]).toBe("test-endpoint-credential");
          expect(targetRequests).toHaveLength(0);
        } finally {
          await close(source.server);
        }
      }
    } finally {
      await close(target.server);
      for (const [name, value] of inherited) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });
});

describe("managed admission workflow", () => {
  test("pins OpenRouter and isolates candidate output from the checkout", async () => {
    const workflow = await Bun.file(
      resolve(import.meta.dir, "..", "..", ".github", "workflows", "bench-live.yml"),
    ).text();
    expect(workflow).toContain("POSTIL_API_BASE: https://openrouter.ai/api/v1");
    expect(workflow).toContain("POSTIL_API_FORMAT: openai-compatible");
    expect(workflow).toContain("POSTIL_BENCH_REPEATS: \"3\"");
    expect(workflow).toContain("POSTIL_BENCH_PAIRS: ${{ inputs.pairs }}");
    expect(workflow).toContain("${{ runner.temp }}/postil-qualified-models-${{ github.run_id }}-${{ github.run_attempt }}.json");
    expect(workflow).toContain('rm -f "$POSTIL_REPORT_OUT" "$POSTIL_MANIFEST_OUT"');
    expect(workflow).toContain('--manifest-out "$POSTIL_MANIFEST_OUT"');
    expect(workflow).toMatch(/name: Upload admission report\n\s+if: always\(\)/u);
    expect(workflow).toMatch(/name: Upload admitted candidate\n\s+if: success\(\)/u);
    expect(workflow).not.toContain("$GITHUB_WORKSPACE/qualified-models.json");
    expect(workflow).not.toContain("inputs.api_base");
    expect(workflow).not.toContain("inputs.api_format");
    expect(workflow).not.toContain("POSTIL_BENCH_MODELS");
    const actionReferences = [...workflow.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)(?:\s+#\s*(\S+))?$/gmu)];
    expect(actionReferences.length).toBeGreaterThan(0);
    expect(actionReferences.every((match) => /@[0-9a-f]{40}$/u.test(match[1] ?? ""))).toBe(true);
    expect(actionReferences.every((match) => (match[2] ?? "").length > 0)).toBe(true);
  });
});

describe("qualification report", () => {
  test("binds the exact fixture matrix and evaluator toolchain sources", () => {
    const exact = fixtureInputs.map((input) => benchmarkCase.parse(input));
    expect(() => assertExactQualificationFixtures(exact)).not.toThrow();
    const changed = exact.map((candidate, index) => index === 0
      ? { ...candidate, name: `${candidate.name} substituted` }
      : candidate);
    expect(() => assertExactQualificationFixtures(changed)).toThrow("exact embedded fixture matrix");
    expect(EVALUATOR_CONTRACT_SOURCE_PATHS).toContain("bench/package.json");
    expect(EVALUATOR_CONTRACT_SOURCE_PATHS).toContain("bench/bun.lock");
  });
  test("matches the runtime named-source framing vector", () => {
    expect(hashNamedSources([
      ["a.txt", Buffer.from("alpha")],
      ["b/β.txt", Buffer.from("line\n")],
    ])).toBe("1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba");
  });

  test("emits the exact runtime admission manifest profile", () => {
    const profileMaterial = {
      modelDefaultsSha256: "c".repeat(64),
      reportSha256: "e".repeat(64),
      apiBase: "https://openrouter.ai:443/api/v1",
      apiFormat: "openai-compatible" as const,
      benchmarkProviderIdentity: "openrouter:test-route",
      generatorModels: ["provider/one", "provider/two"],
      consensus: 2,
      scorerModels: ["provider/scorer"],
      modelPriceBounds: [
        {
          model: "provider/one",
          inputMicrosPerMillionTokens: 1_000_000,
          outputMicrosPerMillionTokens: 2_000_000,
        },
        {
          model: "provider/scorer",
          inputMicrosPerMillionTokens: 3_000_000,
          outputMicrosPerMillionTokens: 4_000_000,
        },
        {
          model: "provider/two",
          inputMicrosPerMillionTokens: 5_000_000,
          outputMicrosPerMillionTokens: 6_000_000,
        },
      ],
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      evaluatorContractHash: "f".repeat(64),
      evaluatorRuntimeIdentity: "bun@1.3.14",
      configHash: "c".repeat(64),
      cliBinaryHash: "d".repeat(64),
      repeats: 3,
    };
    const profile = { id: qualificationProfileDigest(profileMaterial), ...profileMaterial };
    expect(profile.id).toBe("91a2206079adb57e9e25b869cdc8f01955f45cdc814b128c21e2a3f48614382b");
    expect(admissionManifestCandidate("c".repeat(64), [profile])).toEqual({
      version: 1,
      modelDefaultsSha256: "c".repeat(64),
      profiles: [{
        id: profile.id,
        modelDefaultsSha256: "c".repeat(64),
        apiBase: "https://openrouter.ai:443/api/v1",
        benchmarkProviderIdentity: "openrouter:test-route",
        generatorChain: ["provider/one", "provider/two"],
        consensus: 2,
        scorerChain: ["provider/scorer"],
        modelPriceBounds: [
          {
            model: "provider/one",
            inputMicrosPerMillionTokens: 1_000_000,
            outputMicrosPerMillionTokens: 2_000_000,
          },
          {
            model: "provider/scorer",
            inputMicrosPerMillionTokens: 3_000_000,
            outputMicrosPerMillionTokens: 4_000_000,
          },
          {
            model: "provider/two",
            inputMicrosPerMillionTokens: 5_000_000,
            outputMicrosPerMillionTokens: 6_000_000,
          },
        ],
        apiFormat: "openai-compatible",
        reviewContractSha256: "b".repeat(64),
        fixtureSetSha256: "a".repeat(64),
        evaluatorContractSha256: "f".repeat(64),
        evaluatorRuntimeIdentity: "bun@1.3.14",
        reportSha256: "e".repeat(64),
        repeatedRuns: 3,
      }],
    });
  });

  test("prints attributable metrics, hashes, provider, and bounded costs", () => {
    const cost = 0.123456;
    const report: LiveModelsReport = {
      generatedAt: "2026-07-11T00:00:00.000Z",
      cliVersion: "postil 0.6.1",
      apiBase: "https://example.test/v1",
      apiFormat: "openai-compatible",
      providerEndpointIdentity: "https://example.test:443/v1",
      upstreamProviderPinned: false,
      upstreamProviderIdentity: null,
      fixtureHash: "a".repeat(64),
      reviewContractHash: "b".repeat(64),
      evaluatorContractHash: "f".repeat(64),
      evaluatorRuntimeIdentity: "bun@1.3.14",
      configHash: "d".repeat(64),
      cliBinaryHash: "c".repeat(64),
      evidenceHash: "e".repeat(64),
      hostedOperationCostCapMicros: 1_000_000,
      repeats: 3,
      profiles: [],
      manifestCandidate: { version: 1, modelDefaultsSha256: "d".repeat(64), profiles: [] },
      passed: false,
      models: [],
      modelAggregates: [{
        id: "test/generator + test/scorer",
        generatorModel: "test/generator",
        generatorModels: ["test/generator"],
        scorerModel: "test/scorer",
        repeats: 3,
        mustBlockRecall: 1,
        mustBlockFinalBlockingRate: 1,
        advisoryDetectionRate: 0.95,
        advisoryOverblockRate: 0,
        cleanFalseBlocks: 0,
        cleanFindingFalsePositiveRate: 0,
        unrelatedFindings: 0,
        casesRun: 183,
        meanCostUsdPerReview: cost,
        meanDurationMs: 1200,
        p95DurationMs: 1200,
        maxDurationMs: 1200,
        totalCostUsd: cost,
        mustBlockCases: 102,
        mustBlockDetected: 102,
        mustBlockFinalBlocking: 102,
        advisoryCases: 45,
        advisoryDetected: 43,
        advisoryOverblocked: 0,
        cleanCases: 36,
        errors: 0,
        pricingKnown: true,
        fidelityFailures: 0,
        structuredOutputFailures: 0,
        usageFailures: 0,
        providerExactCases: 183,
        catalogEstimateCases: 0,
        admissionFailures: ["mean cost exceeds admission limit"],
        passed: false,
      }],
      totalRunCostUsd: cost,
      cases: [],
    };

    const output = formatLiveModelsReport(report);
    expect(output).toContain("block");
    expect(output).toContain("adv");
    expect(output).toContain("Fixture aaaa");
    expect(output).toContain("Provider endpoint https://example.test:443/v1; 3 complete repeats");
    expect(output).toContain("$0.1235");
    expect(output).not.toContain("$0.123456");
    expect(output).toContain("FAIL: mean cost exceeds admission limit");
    expect(liveModelsQualificationExitCode(report)).toBe(1);
  });

  test("derives exact sorted price bounds for the generator and scorer union", () => {
    const shared = { generatorModel: "provider/shared", scorerModel: "provider/shared" };
    expect(modelPriceBoundsFor(shared, new Map([["provider/shared", {
      promptUsdPerToken: 0.000001,
      completionUsdPerToken: 0.000002,
      inputMicrosPerMillionTokens: 1_000_000,
      outputMicrosPerMillionTokens: 2_000_000,
    }]]))).toEqual([{
      model: "provider/shared",
      inputMicrosPerMillionTokens: 1_000_000,
      outputMicrosPerMillionTokens: 2_000_000,
    }]);

    expect(() => modelPriceBoundsFor(pair, new Map())).toThrow(
      "qualification price bound missing for test/generator",
    );
    expect(() => modelPriceBoundsFor(pair, new Map([
      [pair.generatorModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 0,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
      [pair.scorerModel, {
        promptUsdPerToken: 0.000001,
        completionUsdPerToken: 0.000002,
        inputMicrosPerMillionTokens: 1_000_000,
        outputMicrosPerMillionTokens: 2_000_000,
      }],
    ]))).toThrow("must be a positive safe integer");
  });
});
