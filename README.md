# Postil CLI

Postil is a quiet AI code review gate. It reports merge-relevant bugs, security issues, breaking changes, concurrency hazards, and explicit policy violations. Clean changes produce no review comment.

One binary reviews local changes, pull requests, and merge requests. It supports OpenAI-compatible model endpoints and the native Anthropic Messages API.

## Install

```sh
curl -fsSL https://postil.dev/install.sh | sh
```

The installer verifies the release checksum and, when `cosign` is available, its Sigstore signature. Pass `--require-cosign` to refuse checksum-only installation. You can also build from source:

```sh
cargo install --git https://github.com/postil-dev/postil-cli --locked
```

Release binaries cover Linux x86_64 and ARM64 with glibc or musl, plus macOS on Intel and Apple Silicon.

## Review before pushing

Authenticate once for hosted inference against your organization's entitlement, or bring your own model key:

```sh
postil login                             # zero-config: stores a renewable login for hosted inference
# or: export MODEL_API_KEY=...           # OpenRouter is the default endpoint
#     export REVIEW_MODEL=provider/qualified-model
postil doctor                            # validate the endpoint and repository
postil review --staged                   # review the staged change
postil review --base origin/main         # review the branch
postil review --bounded --base origin/main # cap large reviews at five source batches
postil hook install                      # add a pre-push review
```

`postil review` exits `0` when the gate passes, `1` when it fails, and `2` when it cannot produce a review envelope.

## Review a pull request

```sh
export GITHUB_TOKEN=...
postil review --repo owner/repository --pr 123 --publish
```

`--publish` is required for any forge write. Without it, the CLI fetches the pull request and reports locally. Published runs create separate `postil/review` and `postil/gate` checks. Findings appear in one batched review by default; GitHub repositories can set `review.findingPresentation: checkAnnotations` to put them on the advisory check instead. Mark only `postil/gate` as required in branch protection.

For GitHub Actions, use [`postil-action`](https://github.com/postil-dev/postil-action). Hosted GitHub reviews are available at [postil.dev/install](https://postil.dev/install).

## Configuration

`postil init` writes `.postil.yaml`. Flags override environment variables, which override repository configuration and defaults.

```yaml
ignore:
  - "**/dist/**"
severityThreshold: info
minConfidence: 0.6
maxFindings: 20
reviewer:
  tone: "direct, specific, no praise, no filler"
  focus: [security, concurrency]
gate:
  failOn: error
  onError: block
```

Unknown keys are rejected. Repository configuration cannot redirect a deployment credential to another API host unless the operator explicitly permits that behavior.
The CLI has no implicit model roster. Review and scorer models must be selected explicitly from models qualified by the benchmark.

## Documentation

| Guide | Covers |
| --- | --- |
| [Configuration](docs/configuration.md) | Policy, precedence, model selection, and environment variables |
| [Model providers](docs/model-providers.md) | OpenAI-compatible, Anthropic, and local endpoints |
| [Code forges](docs/forges.md) | GitHub, GitLab, Bitbucket, and Azure DevOps |
| [Automation](docs/automation.md) | SARIF, incremental review, envelopes, planning, and interactive replies |
| [Architecture](ARCHITECTURE.md) | Trust boundaries and review pipeline |
| [Benchmarks](bench/README.md) | Model evaluation harness |

The rendered product documentation is at [postil.dev/docs](https://postil.dev/docs).

## License

Apache-2.0.
