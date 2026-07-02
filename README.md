# postil

Low-noise AI review gate. Silent on clean changes, hard gate on real risk.

Postil reviews diffs for merge-relevant findings only: bugs, security issues, breaking
changes, concurrency hazards, and decisions that need an accountable human. It does not
comment on style, naming, formatting, or anything a linter would catch. On a clean PR it
posts nothing at all — the check-run completes and that is the whole interaction.

One binary runs everywhere: locally before you push, in CI, and behind the hosted
platform at [postil.dev](https://postil.dev).

## Doctrine

- Review by default, trust by evidence. Every finding must cite a line in the diff;
  uncited findings are discarded as ungrounded.
- Silence is a feature. Comment only when the comment can affect the merge decision.
- Fail closed. If the model's output cannot be validated, that is an `error` finding at
  `.postil/model-output:1`, not a pass.
- Block on what matters, advise on the rest. Two separate checks: `postil/review`
  (advisory, never blocks) and `postil/gate` (fails at/above `gate.failOn`, default
  `error`) — mark only the gate as required in branch protection.
- Bring your own key. Postil talks to any OpenAI-compatible endpoint (OpenRouter by
  default; Ollama, vLLM, SGLang, Azure OpenAI, LiteLLM all work) and never proxies or
  marks up your inference.

## Install

```sh
# Verified prebuilt binary (SHA-256 checksum; Sigstore keyless signature when
# cosign is installed), installs to ~/.local/bin:
curl -fsSL https://postil.dev/install.sh | sh

# Or build from source:
cargo install --git https://github.com/postil-dev/postil-cli --locked
```

## Quick start

```sh
export OPENROUTER_API_KEY=...   # or POSTIL_API_KEY with any OpenAI-compatible endpoint

postil doctor                   # validates endpoint, key, model, and repo setup
postil review --staged          # review what you are about to commit
postil review --base origin/main
```

In GitHub Actions, use [postil-action](https://github.com/postil-dev/postil-action), or
run the binary directly:

```sh
postil review --repo owner/name --pr 123   # posts inline comments + both check-runs
```

Other forges (each covering its self-managed/server variant via a base-URL env var):

```sh
# GitLab (gitlab.com or self-managed)
export GITLAB_TOKEN=... GITLAB_API_URL=https://gitlab.example.com/api/v4
postil review --forge gitlab --repo group/project --pr 42

# Bitbucket (Cloud, or Data Center via BITBUCKET_API_URL)
export BITBUCKET_TOKEN=...            # set BITBUCKET_USER too to use an app password
postil review --forge bitbucket --repo workspace/repo --pr 7

# Azure DevOps Services (or Server via AZURE_DEVOPS_API_URL)
export AZURE_DEVOPS_TOKEN=...         # a PAT
postil review --forge azure --repo organization/project/repository --pr 7
```

## SARIF output

`--sarif <path>` writes SARIF 2.1.0 alongside the review for code-scanning ingestion
(GitHub code scanning, GitLab SAST, any SARIF viewer):

```sh
postil review --repo owner/name --pr 123 --sarif postil.sarif
```

## Interactive bot

Mention `@postil` in a pull-request or issue comment, reply to one of its review
comments, or open an issue that mentions it, and the hosted bot replies. Postil reviews
and answers only — it never opens PRs or pushes commits. The same engine is a CLI
command:

```sh
postil respond --repo owner/name --pr 123 --comment "@postil is this safe?"
postil respond --repo owner/name --issue 45 --comment "@postil what's the likely cause?"
# Automation should pass the text via env instead (argv is visible in `ps`):
POSTIL_COMMENT="@postil is this safe?" postil respond --repo owner/name --pr 123
```

## Repo guardrails

Drop repo-specific merge rules in `.postil/guardrails.md` and Postil injects them into
the prompt; a change that violates one is reported as a `guardrail` finding that quotes
the rule it breaks.

## Content policy

Off by default. Reviews human-readable prose in the diff — Markdown, code comments,
docstrings, user-facing/log strings, and the PR title/description, never code logic or
identifiers — for fabricated or contradicted documentation claims, self-contradictions
the same PR creates, authoring-process narration and AI-authorship residue, leaked
conversation/transcript text, and (lower severity) stale temporal/TODO residue and house
style. Violations are reported as `contentPolicy` findings that name the rule broken.

Turn it on with `contentPolicy.enabled: true` in `.postil.yaml` for the built-in
baseline, or drop repo-specific additions in `.postil/content-policy.md` (which also
turns it on by itself, the same way `.postil/guardrails.md` does); the file's rules are
appended to the baseline, not a replacement for it.

## Configuration

`postil init` writes a starter `.postil.yaml`. Precedence: flags > environment >
`.postil.{yaml,yml,json}` > `.coderabbit.yaml` (translated) > defaults. Unknown keys are
rejected so typos fail loudly.

```yaml
ignore:
  - "**/dist/**"
severityThreshold: info   # suppress below: info | warn | error
minConfidence: 0.6        # suppress findings the model is not confident about
maxFindings: 20
reviewer:
  tone: "direct, specific, no praise, no filler"
  focus: [security, concurrency]
review:
  onClean: skip           # stay silent on clean PRs (default)
gate:
  failOn: error           # info | warn | error | never
  onError: block          # block (fail closed, default) | advisory (fail open on
                          # provider outage only; unusable model output still blocks)
contentPolicy:
  enabled: false          # true reviews prose in the diff for fabricated claims, AI-
                          # authorship residue, and stale/style residue (see above)
model:
  name: deepseek/deepseek-v4-pro
  cascade: [anthropic/claude-sonnet-4.6]
  apiBase: https://openrouter.ai/api/v1
  consensus: 1            # >1: only findings multiple models agree on survive
```

Environment: `POSTIL_API_KEY` (or `OPENROUTER_API_KEY`), `POSTIL_API_BASE`,
`REVIEW_MODEL`, `REVIEW_MODEL_CASCADE`, `GITHUB_TOKEN`/`GITHUB_API_URL`,
`GITLAB_TOKEN`/`GITLAB_API_URL`, `BITBUCKET_TOKEN`/`BITBUCKET_USER`/`BITBUCKET_API_URL`,
`AZURE_DEVOPS_TOKEN`/`AZURE_DEVOPS_API_URL`.

## Models and local inference

The hosted site keeps current recommendations at
[postil.dev/docs/models](https://postil.dev/docs/models). For OpenRouter, start with
`deepseek/deepseek-v4-pro` as the balanced default, `deepseek/deepseek-v4-flash` for
low-cost volume, `qwen/qwen3.7-plus` for fast coding reviews, and
`moonshotai/kimi-k2.7-code` or `z-ai/glm-5.2` for larger engineering diffs.

Local endpoints use the same OpenAI-compatible contract:

```sh
# Ollama
ollama pull qwen3-coder:30b
POSTIL_API_BASE=http://localhost:11434/v1 \
POSTIL_API_KEY=ollama \
REVIEW_MODEL=qwen3-coder:30b \
postil doctor

# vLLM, SGLang, LiteLLM, or another local gateway
POSTIL_API_BASE=http://localhost:8000/v1 \
POSTIL_API_KEY=local \
REVIEW_MODEL=<served-model-name> \
postil review --staged --output-json
```

Use the live benchmark harness before standardizing on a model:

```sh
cargo build --quiet --release
cd bench
AGENT=1 POSTIL_API_KEY=... REVIEW_MODEL=deepseek/deepseek-v4-pro bun run bench:live -- --json
```

## Preview a config change before deploying it

`postil plan` re-applies a candidate config to stored review envelopes and reports what
would change — which findings would be suppressed and which gate outcomes would flip.
Deterministic, no model calls.

```sh
postil review --staged --output-json > .cache/envelopes/r1.json
postil plan --envelopes .cache/envelopes --config .postil.candidate.yaml
```

## Incremental re-review

Pass `--since-sha <last-reviewed-head>` and `--baseline <previous-envelope.json>` and
Postil reviews only the new commits, marks earlier findings whose code was changed as
resolved, and carries still-open findings forward so the gate cannot be cleared by
pushing an unrelated commit.

## The envelope

`--output-json` prints a stable versioned envelope (`summary`, `silent`, `findings`,
`resolved`, `counts`, `confidenceBuckets`, `gate`, `modelUsed`, `usage`, SHAs) consumed
by the hosted platform and `postil plan`. Schema: [postil.dev/docs/envelope](https://postil.dev/docs/envelope).

Exit codes: `0` clean or below gate threshold, `1` gate-failing findings, `2`
operational error.

## License

Apache-2.0.
