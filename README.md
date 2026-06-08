# Postil CLI

`postil` is the low-noise review gate binary for Postil. Hosted Postil workers,
the GitHub Action, and local review commands all run this CLI; the website does
not contain review logic.

## Install

The practical install paths live in [INSTALL.md](./INSTALL.md). The short
version:

```bash
cargo install --git https://github.com/postil-dev/postil-cli --locked --force
```

## Usage

Review a pull request:

```bash
postil review --repo owner/repo --pr 123 --sha HEAD_SHA
```

Local diff review does not require GitHub configuration:

```bash
postil review --diff-file .cache/change.diff
postil review --staged
postil review --base origin/main
```

By default, the command also reads GitHub Actions context:

- `GITHUB_REPOSITORY`
- `GITHUB_EVENT_PATH`
- `GITHUB_TOKEN`
- `OPENROUTER_API_KEY`

Review models are configured with `REVIEW_MODEL` or `REVIEW_MODEL_CASCADE`.
The default model is `deepseek/deepseek-v4-pro`.

## Review modes

Runtime configuration is env-first, with full CLI and file parity. Precedence is:

1. CLI flags
2. Environment variables
3. `--config` file
4. Built-in defaults

Example runtime config:

```yaml
repo: owner/repo
pr: 123
sha: abc123
reviewModel: xiaomi/mimo-v2.5-pro
failOn: error
noInline: false
review:
  enabled: true
  ignore:
    - "dist/**"
  severityThreshold: info
  maxFindings: 25
  review:
    enabled: true
    onClean: skip
```

Clean reviews are silent by default: Postil completes the check-run or local
command without posting a PR approval comment. Set `review.review.onClean:
approve` only when a repository explicitly wants clean PR approval reviews.

`reviewer.focus` is passed into the review prompt as repository-specific
evidence. Use it for enforced areas such as security-sensitive code, migrations,
public API contracts, or user-visible behavior.

The CLI also loads per-repository review config from the pull request head SHA,
using this order:

1. `.postil.yaml`, `.postil.yml`, `.postil.json`
2. `.coderabbit.yaml`, `.coderabbit.yml`
3. `.kodo.yaml`, `.kodo.yml`
4. Built-in defaults

For compatibility, `requiredChecks` and `autoMergeTimeoutMs` are accepted both
top-level and under `review`.

## JSON Output

Hosted callers can request the structured review envelope:

```bash
postil review --output-json .cache/postil-review.json
```

The JSON includes `summary`, `findings`, `usage`, and `modelUsed`. Findings
include `path`, `line`, `severity`, `body`, and optional `kind`
(`risk`, `humanEscalation`, `guardrail`, or `uncertainty`).

Hosted workers that already created an in-progress check-run should pass
`--check-run-id`; CI/self-hosted runs omit it and the CLI creates the check-run.

If a model response is not valid Postil JSON, the CLI fails closed by converting
that response into an `error` finding at `.postil/model-output:1`.

## GitHub Action

The Action in [postil-dev/postil-action](https://github.com/postil-dev/postil-action)
installs the `postil` binary from this repository, then runs `postil review`.

```yaml
name: Postil review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: postil-dev/postil-action@main
        with:
          api-key: ${{ secrets.OPENROUTER_API_KEY }}
```

## Testing

```bash
cargo test --quiet
```

Live OpenRouter smoke test:

```bash
infisical run --env=prod -- env REVIEW_MODEL=deepseek/deepseek-v4-pro cargo test --quiet live_openrouter_smoke -- --ignored
```
