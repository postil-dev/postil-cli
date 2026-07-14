# Model providers

Postil speaks either an OpenAI-compatible chat-completions interface or the native Anthropic Messages API. Provider requests do not follow redirects, credentials are never written to logs, and private-network endpoints require an explicit opt-in.

## Model admission

The CLI has no implicit model or fallback chain. Set `REVIEW_MODEL` to a model that passes the repository benchmark for the intended review profile. Set `REVIEW_MODEL_CASCADE` only to other qualified models. Scoring is disabled unless `REVIEW_SCORER_MODEL` names a qualified scorer. `REVIEW_SCORER_MODEL_CASCADE` accepts one qualified scorer fallback.

Hosted deployments admit only complete profiles listed in the embedded `qualified-models.json` qualification manifest. A profile binds the canonical API base, provider API format, ordered generator chain, consensus width, ordered scorer chain, exact Bun evaluator runtime, at least three complete runs, and SHA-256 digests for the review contract, evaluator contract, fixture set, and benchmark report. The manifest also binds the exact `config.toml` digest. Hosted configuration must match one profile exactly; an empty, degraded, or mismatched profile rejects inference.

`benchmarkProviderIdentity` can preserve the upstream route reported by the benchmark as evidence. It does not pin runtime upstream routing; admission pins the API endpoint and model profile that Postil controls.

The review-contract digest covers `Cargo.toml`, `Cargo.lock`, and every Rust source file. The evaluator digest covers the fixtures, live qualification code, `bench/package.json`, and `bench/bun.lock`. The package manifest pins the exact Bun evaluator runtime. Each input is framed as its repository path, a NUL byte, file contents, and a trailing NUL byte. The binary exposes these embedded digests and its matched `admittedProfile` to the benchmark. `admittedProfile` is null unless the embedded defaults exactly match a manifest profile. Changing the runtime, dependencies, defaults, fixtures, or evaluator invalidates existing evidence.

Cross-language framing vector: paths and contents `[("a.txt", "alpha"), ("b/β.txt", "line\n")]` serialize as `a.txt\0alpha\0b/β.txt\0line\n\0` in UTF-8 and hash to `1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba`.

## OpenAI-compatible

OpenRouter is the default endpoint. Hosted OpenRouter requests deny data-collecting routes and require ZDR-capable routes through [OpenRouter's per-request provider controls](https://openrouter.ai/docs/guides/routing/provider-selection). OpenRouter can select upstream providers dynamically, so an endpoint identity does not claim a pinned upstream route. Ollama, vLLM, SGLang, LiteLLM, and private gateways can use the same contract. BYOK operators control their provider routing and retention settings.

```sh
export MODEL_API_KEY=...
export POSTIL_API_BASE=https://openrouter.ai/api/v1
export REVIEW_MODEL=provider/qualified-model
postil doctor
```

These requests authenticate with `Authorization: Bearer`.

## Anthropic Messages API

```sh
export MODEL_API_KEY=...
export POSTIL_API_BASE=https://api.anthropic.com/v1
export POSTIL_API_FORMAT=anthropic
export REVIEW_MODEL=provider-qualified-anthropic-model
postil doctor
```

Native Anthropic requests use `x-api-key` and `anthropic-version`. Set `REVIEW_SCORER_MODEL` to a model available through the same endpoint when scoring is required.

## Local endpoints

Private and loopback addresses are denied unless the operator permits them:

```sh
ollama pull your-qualified-local-model

POSTIL_API_BASE=http://localhost:11434/v1 \
POSTIL_ALLOW_PRIVATE_API_BASE=1 \
MODEL_API_KEY=local \
REVIEW_MODEL=your-qualified-local-model \
postil review --staged
```

The API hostname is resolved before the request and the client is pinned to accepted addresses while retaining hostname-based TLS checks. Model clients bypass system proxies so proxy-side DNS cannot evade this validation.

## Additional gateway authentication

Private gateways can require one additional header:

```sh
POSTIL_ENDPOINT_AUTH_HEADER=X-Gateway-Token \
POSTIL_ENDPOINT_AUTH_VALUE=... \
postil doctor
```

Reserved provider headers cannot be replaced. Pass secrets through environment variables or a secret manager, not command-line arguments.
