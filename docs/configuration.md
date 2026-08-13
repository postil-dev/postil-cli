# Configuration

Postil resolves settings in this order:

1. Command-line flags
2. Environment variables
3. `.postil.yaml`, `.postil.yml`, or `.postil.json`
4. Translated `.coderabbit.yaml` settings
5. Built-in defaults

Unknown keys fail validation so a misspelling cannot silently weaken a review.

## Repository policy

```yaml
ignore:
  - "**/dist/**"
severityThreshold: info       # info, warn, or error
minConfidence: 0.6
maxFindings: 20              # 1..20; bounds scorer and publication work
reviewer:
  tone: "direct, specific, no praise, no filler"
  focus: [security, concurrency]
review:
  onClean: skip
  findingPresentation: reviewComments # reviewComments or checkAnnotations (GitHub only)
  uncertaintyResolution: true # resolve uncertainty findings from referenced repository files
  conciseFindings: true       # compress over-long finding bodies before rendering
gate:
  failOn: error               # info, warn, error, or never
  onError: block              # block or advisory for provider outages
contentPolicy:
  enabled: true
model:
  name: provider/qualified-model
  cascade: []                    # qualified fallbacks only
  # scorer: provider/qualified-scorer
  consensus: 1
```

Place organization-specific merge rules in `.postil/guardrails.md`. Place additions to the built-in prose policy in `.postil/content-policy.md`. Repository policy extends the built-in content policy unless `contentPolicy.enabled` is false.

Ignore patterns remove matching paths before grounding, batching, and large-review coverage planning. A rename is removed only when both its old and new paths match. Generated-looking source remains reviewable unless an ignore pattern matches it.

## Environment

| Variable | Purpose |
| --- | --- |
| `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`, `LLM_API_KEY` | Model provider credential, checked in that order |
| `POSTIL_LOGIN_SERVER` | Postil web app used by `postil login`/`postil logout`; defaults to `https://postil.dev` |
| `POSTIL_API_BASE` | Model endpoint selected by the operator |
| `POSTIL_API_FORMAT` | `openai-compatible` or `anthropic` |
| `POSTIL_ENDPOINT_AUTH_HEADER`, `POSTIL_ENDPOINT_AUTH_VALUE` | Additional private-gateway authentication |
| `POSTIL_ALLOW_PRIVATE_API_BASE` | Explicitly permit a local or private-network endpoint |
| `POSTIL_ALLOW_CONFIG_API_BASE` | Honor a repository-controlled `model.apiBase` |
| `POSTIL_IGNORE_REPOSITORY_MODEL_CONFIG` | Keep trusted local/hosted model selection independent of repository model fields |
| `REVIEW_MODEL` | Primary model override |
| `REVIEW_MODEL_CASCADE` | Comma-separated fallback models |
| `REVIEW_MODEL_CONSENSUS` | Number of models from the generator chain to run concurrently; agreeing findings are retained |
| `REVIEW_SCORER_MODEL` | Scorer model override |
| `REVIEW_SCORER_MODEL_CASCADE` | One scorer fallback model |
| `POSTIL_UNCERTAINTY_RESOLUTION` | Override uncertainty resolution with `true`/`false` or `1`/`0` |
| `POSTIL_CONCISE_FINDINGS` | Override concise findings with `true`/`false` or `1`/`0` |
| `POSTIL_LLM_REQUEST_TIMEOUT_SECS` | Per-attempt model request timeout; defaults to 480 seconds |
| `POSTIL_LLM_TOTAL_TIMEOUT_SECS` | Optional total local-review model deadline |
| `POSTIL_DETAILS_URL` | HTTP(S) details link for forge check runs |

Forge credentials and base URLs are listed in [Code forges](forges.md). Provider-specific behavior is in [Model providers](model-providers.md).

## Login

```sh
postil login
postil logout
```

`postil login` authenticates against postil.dev over a device-authorization flow (open the printed URL, enter the code) and stores a credential at `${XDG_CONFIG_HOME:-~/.config}/postil/credentials.json`, mode `0600` in a `0700` directory. That credential is a fallback: it is used only when none of `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`, or `LLM_API_KEY` is set. When it is used, its `apiBase` and model select the request unless `POSTIL_API_BASE`/`REVIEW_MODEL` are set, which still win. `postil logout` revokes the credential server-side and removes the local file even if that call fails. An expired credential produces one instruction to run `postil login` again rather than a provider authentication error.

## Inspect and initialize

```sh
postil init
postil config
postil doctor
```

`postil config` prints the resolved non-secret configuration and its sources. `postil doctor` validates endpoint reachability, credential acceptance, and repository setup without printing credential values, and reports whether a login credential is present and when it expires.
