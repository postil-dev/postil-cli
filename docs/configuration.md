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
maxFindings: 20
reviewer:
  tone: "direct, specific, no praise, no filler"
  focus: [security, concurrency]
review:
  onClean: skip
gate:
  failOn: error               # info, warn, error, or never
  onError: block              # block or advisory for provider outages
contentPolicy:
  enabled: true
model:
  name: mistralai/mistral-small-3.2-24b-instruct
  cascade:
    - google/gemma-3-27b-it
    - qwen/qwen3-32b
  # scorer: provider/model       # explicit opt-in
  consensus: 1
```

Place organization-specific merge rules in `.postil/guardrails.md`. Place additions to the built-in prose policy in `.postil/content-policy.md`. Repository policy extends the built-in content policy unless `contentPolicy.enabled` is false.

## Environment

| Variable | Purpose |
| --- | --- |
| `POSTIL_API_KEY`, `OPENROUTER_API_KEY`, `MODEL_API_KEY`, `LLM_API_KEY` | Model provider credential, checked in that order |
| `POSTIL_API_BASE` | Model endpoint selected by the operator |
| `POSTIL_API_FORMAT` | `openai-compatible` or `anthropic` |
| `POSTIL_ENDPOINT_AUTH_HEADER`, `POSTIL_ENDPOINT_AUTH_VALUE` | Additional private-gateway authentication |
| `POSTIL_ALLOW_PRIVATE_API_BASE` | Explicitly permit a local or private-network endpoint |
| `POSTIL_ALLOW_CONFIG_API_BASE` | Honor a repository-controlled `model.apiBase` |
| `REVIEW_MODEL` | Primary model override |
| `REVIEW_MODEL_CASCADE` | Comma-separated fallback models |
| `REVIEW_SCORER_MODEL` | Scorer model override |
| `POSTIL_LLM_TOTAL_TIMEOUT_SECS` | Optional total local-review model deadline |
| `POSTIL_DETAILS_URL` | HTTP(S) details link for forge check runs |

Forge credentials and base URLs are listed in [Code forges](forges.md). Provider-specific behavior is in [Model providers](model-providers.md).

## Inspect and initialize

```sh
postil init
postil config
postil doctor
```

`postil config` prints the resolved non-secret configuration and its sources. `postil doctor` validates endpoint reachability, credential acceptance, and repository setup without printing credential values.
