# postil-cli

`postil` is the entire Postil review engine, packaged as a single static Rust
binary. Local developers, the GitHub Action, and the hosted worker all run this
binary against the same JSON envelope. The website and backend contain zero
review logic.

Postil is a **low-noise pull-request review gate**. It reads the diff, asks an
OpenRouter model for merge-relevant findings only, and stays silent when there
is nothing to say. Clean PRs complete the `postil/review` check-run with no
comment. The system prompt explicitly bans style nitpicks, summaries, praise,
and filler.

## Install

```bash
cargo install --git https://github.com/postil-dev/postil-cli --locked
```

Pre-built binaries are published on each release for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, and
`aarch64-apple-darwin`.

## Quick start

```bash
# Review a GitHub PR (uses GITHUB_TOKEN and OPENROUTER_API_KEY).
postil review --repo owner/name --pr 123 --sha HEAD_SHA

# Review the local staged diff.
postil review --staged

# Review the working tree against a base branch.
postil review --base origin/main

# Review a unified-diff file directly.
postil review --diff-file change.diff
```

`postil` and `postil review` are equivalent — the no-subcommand form runs the
review.

## Environment variables

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | Required for any review. |
| `GITHUB_TOKEN` | Required when targeting a remote PR. |
| `REVIEW_MODEL` | Primary OpenRouter model. Default `deepseek/deepseek-v4-pro`. |
| `REVIEW_MODEL_CASCADE` | Comma-separated fallback list, tried in order. |
| `POSTIL_FAIL_ON` | `info` / `warn` / `error`. Default `error`. |
| `POSTIL_CHECK_NAME` | Override the check-run name. Default `postil/review`. |
| `POSTIL_GITHUB_API_URL` | GitHub Enterprise base URL. |
| `POSTIL_OPENROUTER_API_URL` | OpenRouter base URL override. |
| `POSTIL_LOG` | `tracing` env-filter, e.g. `postil=debug`. |

## Per-repo policy (`.postil.yaml`)

```yaml
enabled: true
ignore:
  - "dist/**"
  - "vendor/**"
severityThreshold: info
maxFindings: 25
reviewer:
  tone: neutral        # terse | neutral | verbose
  focus: ["security", "migrations"]
review:
  enabled: true
  onClean: skip        # skip | approve  (default skip — silence is a feature)
  autoMerge: false
  requiredChecks: ["postil/review", "Lint", "Typecheck"]
  autoMergeTimeoutMs: 15000
```

`.coderabbit.yaml` and `.kodo.yaml` are honored where they overlap, so
migration is zero-config.

## Review envelope (JSON)

`--output-json <path>` writes the structured envelope the hosted worker reads:

```json
{
  "summary": "<= 240 chars, empty when clean>",
  "findings": [
    {
      "path": "src/auth.ts",
      "line": 142,
      "severity": "error",
      "kind": "risk",
      "body": "Token comparison uses `==` instead of timing-safe comparator."
    }
  ],
  "usage": { "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0 },
  "modelUsed": "deepseek/deepseek-v4-pro",
  "cliVersion": "0.1.0"
}
```

Allowed `kind` values: `risk`, `humanEscalation`, `guardrail`, `uncertainty`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean review, or only findings below `--fail-on`. |
| `1` | At least one finding meets `--fail-on`. |
| `2` | Configuration error (missing token, bad flag, unreadable file). |

## Fail-closed semantics

If the model returns invalid JSON or the provider call fails after every
cascade attempt, Postil synthesises a single `error` finding at
`.postil/model-output:1`. This finding bypasses all filters (`ignore`,
`severityThreshold`, `maxFindings`) so a flaky model can **never silently
approve** a PR.

## License

Apache-2.0.
