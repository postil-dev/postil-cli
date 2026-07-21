import { afterEach, describe, expect, test } from "bun:test";
import {
  MANAGED_RETRY_AFTER_CAP_MS,
  ManagedRequestWindowGovernor,
  parseRetryAfterMillis,
  startManagedRequestWindowProxy,
  type ManagedRequestWindowProxy,
} from "./request-window";

const proxies: ManagedRequestWindowProxy[] = [];
const servers: Bun.Server<unknown>[] = [];

afterEach(() => {
  for (const proxy of proxies.splice(0)) proxy.stop();
  for (const server of servers.splice(0)) server.stop(true);
});

describe("managed request-window governor", () => {
  test("shares one bounded start window and one Retry-After pause", async () => {
    let now = 1_000;
    const sleeps: number[] = [];
    const governor = new ManagedRequestWindowGovernor({
      maxStarts: 2,
      windowMs: 100,
      now: () => now,
      sleep: async (milliseconds) => {
        sleeps.push(milliseconds);
        now += milliseconds;
      },
    });
    await governor.acquire();
    await governor.acquire();
    await governor.acquire();
    expect(sleeps).toEqual([100]);

    await governor.observeRetryAfter("999999999999999999999");
    await governor.acquire();
    expect(sleeps.at(-1)).toBe(MANAGED_RETRY_AFTER_CAP_MS);
  });

  test("parses delta seconds and HTTP dates without exceeding the fixed cap", () => {
    const now = Date.parse("2026-07-21T00:00:00.000Z");
    expect(parseRetryAfterMillis("12", now)).toBe(12_000);
    expect(parseRetryAfterMillis("999", now)).toBe(MANAGED_RETRY_AFTER_CAP_MS);
    expect(parseRetryAfterMillis("Tue, 21 Jul 2026 00:00:05 GMT", now)).toBe(5_000);
    expect(parseRetryAfterMillis("Mon, 20 Jul 2026 23:59:59 GMT", now)).toBe(0);
    expect(parseRetryAfterMillis("invalid", now)).toBeNull();
  });

  test("starts a numeric Retry-After window only after entering the governor mutex", async () => {
    let now = 100;
    const sleeps: number[] = [];
    const governor = new ManagedRequestWindowGovernor({
      maxStarts: 10,
      windowMs: 1,
      now: () => now,
      sleep: async (milliseconds) => {
        sleeps.push(milliseconds);
        now += milliseconds;
      },
    });

    const observation = governor.observeRetryAfter("1");
    now = 500;
    await observation;
    await governor.acquire();

    expect(sleeps).toEqual([1_000]);
  });

  test("proxies approved requests through one real shared window", async () => {
    const starts: number[] = [];
    const authorizations: Array<string | null> = [];
    const upstream = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        starts.push(performance.now());
        authorizations.push(request.headers.get("authorization"));
        return Response.json({ accepted: await request.json() }, {
          headers: { "x-request-id": "request-1" },
        });
      },
    });
    servers.push(upstream);
    const proxy = startManagedRequestWindowProxy(`${new URL(upstream.url).origin}/api/v1`, {
      maxStarts: 1,
      windowMs: 40,
    });
    proxies.push(proxy);

    const send = () => fetch(`${proxy.apiBase}/chat/completions`, {
      method: "POST",
      headers: { Authorization: "Bearer fixture", "Content-Type": "application/json" },
      body: JSON.stringify({ model: "fixture/model" }),
    });
    const [first, second] = await Promise.all([send(), send()]);
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(await first.json()).toEqual({ accepted: { model: "fixture/model" } });
    expect(await second.json()).toEqual({ accepted: { model: "fixture/model" } });
    expect(authorizations).toEqual(["Bearer fixture", "Bearer fixture"]);
    expect(starts).toHaveLength(2);
    expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(30);

    const rejected = await fetch(`${proxy.apiBase}/not-approved`, { method: "POST" });
    expect(rejected.status).toBe(404);
    expect(starts).toHaveLength(2);
  });

  test("applies one provider Retry-After response to later proxy traffic", async () => {
    const starts: number[] = [];
    const upstream = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        starts.push(performance.now());
        return starts.length === 1
          ? Response.json({ error: "rate limited" }, {
              status: 429,
              headers: { "Retry-After": "1" },
            })
          : Response.json({ accepted: true });
      },
    });
    servers.push(upstream);
    const proxy = startManagedRequestWindowProxy(`${new URL(upstream.url).origin}/api/v1`, {
      maxStarts: 10,
      windowMs: 1,
      retryAfterCapMs: 50,
    });
    proxies.push(proxy);
    const send = () => fetch(`${proxy.apiBase}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });

    const limited = await send();
    expect(limited.status).toBe(429);
    expect(limited.headers.get("retry-after")).toBe("1");
    const accepted = await send();
    expect(accepted.status).toBe(200);
    expect(starts[1]! - starts[0]!).toBeGreaterThanOrEqual(40);
  });
});
