export const MANAGED_REQUEST_WINDOW_MAX_STARTS = 4;
export const MANAGED_REQUEST_WINDOW_MS = 1_000;
export const MANAGED_RETRY_AFTER_CAP_MS = 30_000;
const MAX_PROXY_REQUEST_BYTES = 256 * 1024;

type Clock = () => number;
type Sleep = (milliseconds: number) => Promise<void>;

export interface RequestWindowOptions {
  maxStarts?: number;
  windowMs?: number;
  retryAfterCapMs?: number;
  now?: Clock;
  sleep?: Sleep;
}

/**
 * One admission-run governor shared by every generator, scorer, repair, and
 * attribution request. The proxy owns the single instance, so separately
 * spawned CLI processes cannot create independent rate-limit windows.
 */
export class ManagedRequestWindowGovernor {
  readonly maxStarts: number;
  readonly windowMs: number;
  readonly retryAfterCapMs: number;
  readonly #now: Clock;
  readonly #sleep: Sleep;
  #starts: number[] = [];
  #blockedUntil = 0;
  #tail: Promise<void> = Promise.resolve();

  constructor(options: RequestWindowOptions = {}) {
    this.maxStarts = options.maxStarts ?? MANAGED_REQUEST_WINDOW_MAX_STARTS;
    this.windowMs = options.windowMs ?? MANAGED_REQUEST_WINDOW_MS;
    this.retryAfterCapMs = options.retryAfterCapMs ?? MANAGED_RETRY_AFTER_CAP_MS;
    if (!Number.isSafeInteger(this.maxStarts) || this.maxStarts < 1) {
      throw new Error("managed request-window maximum must be a positive integer");
    }
    if (!Number.isSafeInteger(this.windowMs) || this.windowMs < 1) {
      throw new Error("managed request-window duration must be a positive integer");
    }
    if (!Number.isSafeInteger(this.retryAfterCapMs) || this.retryAfterCapMs < 0) {
      throw new Error("managed Retry-After cap must be a nonnegative integer");
    }
    this.#now = options.now ?? Date.now;
    this.#sleep = options.sleep ?? ((milliseconds) => Bun.sleep(milliseconds));
  }

  async acquire(): Promise<void> {
    for (;;) {
      const waitMs = await this.#exclusive(() => {
        const now = this.#now();
        const windowStart = now - this.windowMs;
        this.#starts = this.#starts.filter((startedAt) => startedAt > windowStart);
        const windowWait = this.#starts.length < this.maxStarts
          ? 0
          : Math.max(0, this.#starts[0]! + this.windowMs - now);
        const retryAfterWait = Math.max(0, this.#blockedUntil - now);
        const wait = Math.max(windowWait, retryAfterWait);
        if (wait === 0) this.#starts.push(now);
        return wait;
      });
      if (waitMs === 0) return;
      await this.#sleep(waitMs);
    }
  }

  async observeRetryAfter(value: string | null): Promise<void> {
    await this.#exclusive(() => {
      const now = this.#now();
      const delay = parseRetryAfterMillis(value, now, this.retryAfterCapMs);
      if (delay === null) return;
      this.#blockedUntil = Math.max(this.#blockedUntil, now + delay);
    });
  }

  async #exclusive<T>(work: () => T): Promise<T> {
    const prior = this.#tail;
    let release: () => void = () => {};
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prior;
    try {
      return work();
    } finally {
      release();
    }
  }
}

export function parseRetryAfterMillis(
  value: string | null,
  now = Date.now(),
  capMs = MANAGED_RETRY_AFTER_CAP_MS,
): number | null {
  const normalized = value?.trim();
  if (!normalized) return null;
  let delay: number;
  if (/^\d+$/u.test(normalized)) {
    const seconds = BigInt(normalized);
    const cap = BigInt(capMs);
    return Number(seconds * 1_000n > cap ? cap : seconds * 1_000n);
  }
  const date = Date.parse(normalized);
  if (!Number.isFinite(date)) return null;
  delay = Math.max(0, date - now);
  return Math.min(delay, capMs);
}

export interface ManagedRequestWindowProxy {
  apiBase: string;
  stop(): void;
}

export function startManagedRequestWindowProxy(
  upstreamApiBase: string,
  options: RequestWindowOptions & { fetchImpl?: typeof fetch } = {},
): ManagedRequestWindowProxy {
  const upstreamBase = new URL(upstreamApiBase);
  const fetchImpl = options.fetchImpl ?? fetch;
  const governor = new ManagedRequestWindowGovernor(options);
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const incoming = new URL(request.url);
      if (request.method !== "POST" || incoming.pathname !== "/chat/completions") {
        return Response.json({ error: "unsupported managed request" }, { status: 404 });
      }
      const declaredLength = Number(request.headers.get("content-length") ?? "0");
      if (!Number.isSafeInteger(declaredLength) || declaredLength < 0 ||
          declaredLength > MAX_PROXY_REQUEST_BYTES) {
        return Response.json({ error: "managed request exceeds the byte limit" }, { status: 413 });
      }
      const body = await request.arrayBuffer();
      if (body.byteLength > MAX_PROXY_REQUEST_BYTES) {
        return Response.json({ error: "managed request exceeds the byte limit" }, { status: 413 });
      }
      await governor.acquire();
      const upstreamUrl = new URL(upstreamBase);
      upstreamUrl.pathname = `${upstreamUrl.pathname.replace(/\/$/u, "")}${incoming.pathname}`;
      upstreamUrl.search = incoming.search;
      const headers = selectedHeaders(request.headers, [
        "authorization",
        "content-type",
        "http-referer",
        "x-title",
        "x-openrouter-experimental-metadata",
      ]);
      let response: Response;
      try {
        response = await fetchImpl(upstreamUrl, {
          method: "POST",
          headers,
          body,
          redirect: "error",
          signal: request.signal,
        });
      } catch {
        return Response.json({ error: "managed provider request failed" }, { status: 502 });
      }
      await governor.observeRetryAfter(response.headers.get("retry-after"));
      return new Response(response.body, {
        status: response.status,
        headers: selectedHeaders(response.headers, [
          "content-type",
          "retry-after",
          "x-request-id",
          "x-openrouter-request-id",
        ]),
      });
    },
  });
  return {
    apiBase: new URL(server.url).origin,
    stop() {
      server.stop(true);
    },
  };
}

export async function withManagedRequestWindowProxy<T>(
  upstreamApiBase: string,
  work: (proxy: ManagedRequestWindowProxy) => Promise<T>,
): Promise<T> {
  const proxy = startManagedRequestWindowProxy(upstreamApiBase);
  try {
    return await work(proxy);
  } finally {
    proxy.stop();
  }
}

function selectedHeaders(source: Headers, names: readonly string[]): Headers {
  const selected = new Headers();
  for (const name of names) {
    const value = source.get(name);
    if (value !== null) selected.set(name, value);
  }
  return selected;
}
