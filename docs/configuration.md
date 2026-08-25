# Configuration

Postil resolves model settings in this order:

1. Command-line flags
2. Environment variables
3. `.postil.yaml`, `.postil.yml`, or `.postil.json`
4. Stored `postil login` routing
5. Built-in defaults

Translated `.coderabbit.yaml` settings can supply review policy but do not select a model.

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
  reasoningEffort: low           # max, xhigh, high, medium, low, minimal, or none
  cascade: []                    # qualified fallbacks only
  # scorer: provider/qualified-scorer
  scorerReasoningEffort: none
  consensus: 1
```

Place organization-specific merge rules in `.postil/guardrails.md`. Place additions to the built-in prose policy in `.postil/content-policy.md`. Repository policy extends the built-in content policy unless `contentPolicy.enabled` is false.

Ignore patterns remove matching paths before grounding, batching, and large-review coverage planning. A rename is removed only when both its old and new paths match. Generated-looking source remains reviewable unless an ignore pattern matches it.

## Environment

| Variable | Purpose |
| --- | --- |
| `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`, `LLM_API_KEY` | Model provider credential, checked in that order |
| `POSTIL_LOGIN_SERVER` | Postil web app used by `postil login`, refresh, and `postil logout`; defaults to `https://postil.dev` |
| `POSTIL_API_BASE` | Model endpoint selected by the operator |
| `POSTIL_API_FORMAT` | `openai-compatible` or `anthropic` |
| `POSTIL_ENDPOINT_AUTH_HEADER`, `POSTIL_ENDPOINT_AUTH_VALUE` | Additional private-gateway authentication |
| `POSTIL_ALLOW_PRIVATE_API_BASE` | Explicitly permit a local or private-network endpoint |
| `POSTIL_ALLOW_CONFIG_API_BASE` | Honor a repository-controlled `model.apiBase` |
| `POSTIL_IGNORE_REPOSITORY_MODEL_CONFIG` | Keep trusted local/hosted model selection independent of repository model fields |
| `REVIEW_MODEL` | Primary model override |
| `REVIEW_REASONING_EFFORT` | Reviewer reasoning effort: `max`, `xhigh`, `high`, `medium`, `low`, `minimal`, or `none` |
| `REVIEW_MODEL_CASCADE` | Comma-separated fallback models |
| `REVIEW_MODEL_CONSENSUS` | Number of models from the generator chain to run concurrently; agreeing findings are retained |
| `REVIEW_SCORER_MODEL` | Scorer model override |
| `REVIEW_SCORER_REASONING_EFFORT` | Scorer and adjudication reasoning effort: `max`, `xhigh`, `high`, `medium`, `low`, `minimal`, or `none` |
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

`postil login` authenticates against postil.dev over a device-authorization flow (open the printed URL, enter the code) and stores a renewable credential at `${XDG_CONFIG_HOME:-~/.config}/postil/credentials.json`, mode `0600` in a `0700` directory. That credential is a fallback: it is used only when none of `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`, or `LLM_API_KEY` is set. Its `apiBase` and model provide a baseline below trusted project configuration and environment overrides. When the stored login is used, Postil rotates the access credential before it expires and persists the replacement; explicit API keys never trigger a refresh. `postil logout` revokes the stored refresh credential server-side and removes the local file even if that call fails. A legacy access-only login, an expired refresh inactivity window, or a rejected refresh produces one instruction to run `postil login` again rather than a provider authentication error. Temporary refresh failures retain the stored credential and ask the user to try again.

## Inspect and initialize

```sh
postil init
postil config
postil doctor
```

`postil config` prints the resolved non-secret configuration and separate provenance for the model, reviewer reasoning effort, and scorer reasoning effort. `postil doctor` validates endpoint reachability, credential acceptance, and repository setup without printing credential values. Both commands identify renewable logins, access expiry, refresh inactivity expiry, and legacy access-only logins.

Use `--reasoning-effort` and `--scorer-reasoning-effort` for one review. These flags override the matching environment variables, which override `model.reasoningEffort` and `model.scorerReasoningEffort`. The built-in reviewer and scorer defaults are `low` and `none`, respectively. Every request carries the resolved value, including retries and repair calls.
