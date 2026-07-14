# Model providers

Postil speaks either an OpenAI-compatible chat-completions interface or the native Anthropic Messages API. Provider requests do not follow redirects, credentials are never written to logs, and private-network endpoints require an explicit opt-in.

## Model admission

The CLI has no implicit model or fallback chain. Set `REVIEW_MODEL` to a model that passes the repository benchmark for the intended review profile. Set `REVIEW_MODEL_CASCADE` only to other qualified models. Scoring is disabled unless `REVIEW_SCORER_MODEL` names a qualified scorer. `REVIEW_SCORER_MODEL_CASCADE` accepts one qualified scorer fallback.

Hosted deployments admit only complete profiles listed in the embedded `qualified-models.json` qualification manifest. A profile binds the canonical API base, provider API format, ordered generator chain, consensus width, ordered scorer chain, exact Bun evaluator runtime, qualification source commit, a 30-day authority window, at least three complete runs, and SHA-256 digests for the review contract, evaluator contract, fixture set, and benchmark report. The manifest also binds the exact `config.toml` digest. Hosted configuration must match one unexpired profile exactly; the expiry second is excluded. An empty, degraded, stale, or mismatched profile rejects inference.

Every nonempty manifest has a committed `qualified-models.attestation.json` bundle. CI and release validation use [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify) to require SLSA provenance from the exact `postil-dev/postil-cli` admission workflow, `refs/heads/main` source ref, source and signer commit, issued by GitHub OIDC through public Sigstore on a GitHub-hosted runner. The source commit must be an ancestor of the candidate commit, and only the manifest and bundle may differ. A verified Sigstore timestamp must match the signed issue time and remain within the authority window. The bundle authenticates the exact manifest bytes. Checksums inside the report and manifest provide integrity evidence, not producer authentication. The binary metadata exposes the manifest issue time, exclusive expiry time, and maximum age as top-level values. An empty manifest exposes null authority metadata, needs no bundle, and admits no model.

Managed profiles bind `benchmarkProviderIdentity` to `openrouter:managed-routing`. The value identifies Postil's managed routing contract, not an upstream provider route. Custom and local evidence keeps its own endpoint identity but cannot produce a hosted admission manifest.

The review-contract digest covers `Cargo.toml`, `Cargo.lock`, and every Rust source file. One checked-in source manifest defines the identical Rust and TypeScript evaluator source list, including the fixtures, live qualification code, attestation verifier, `bench/package.json`, and `bench/bun.lock`. The package manifest pins the exact Bun evaluator runtime. Each input is framed as its repository path, a NUL byte, file contents, and a trailing NUL byte. The binary exposes these embedded digests and its matched `admittedProfile` to the benchmark. `admittedProfile` is null unless the embedded defaults exactly match an unexpired manifest profile. Changing the runtime, dependencies, defaults, fixtures, evaluator, or authority window invalidates existing evidence.

Cross-language framing vector: paths and contents `[("a.txt", "alpha"), ("b/β.txt", "line\n")]` serialize as `a.txt\0alpha\0b/β.txt\0line\n\0` in UTF-8 and hash to `1969c5b03a79915d62106b91c742a28127afae455317dcb3a4670e50829eb9ba`.

## Hosted resource admission

Hosted reviews preflight the complete planner, review, scorer, repair, retry, fallback, and consensus path before contacting a provider. Admission measures each JSON request after serialization, including escaped quotes, backslashes, and control characters. The envelope records the conservative attempt, input, output, and cost exposure reserved by that plan. Large diffs use deterministic boundary, risk, and global-synthesis evidence plus a bounded planner selection. If every planner call fails or returns invalid output, Postil retains the planner usage records and reviews the deterministic mandatory selection. The envelope and compact output record exhaustive or bounded mode, selected and total source-batch counts, and whether planner fallback ran. Provider errors stay out of pull request output. Acquired sources, reconstructed diffs, normalized windows, and model batches share one 512 MiB file-backed operation quota.

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
