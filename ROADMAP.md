# Roadmap

## Shipped

- Grounded, fail-closed review engine; local + GitHub + GitLab + Bitbucket + Azure
  DevOps (each including its self-managed/server variant via a base-URL override).
- Two-check semantics (postil/review advisory, postil/gate blocking); `gate.onError:
  block|advisory` for fail-open on provider outages.
- Incremental re-review with resolved/carried reconciliation.
- Interactive bot (`postil respond`): replies to @postil mentions on PRs and issues.
  Review-and-answer only — never opens PRs or pushes.
- SARIF 2.1.0 output (`--sarif`) for code-scanning ingestion.
- Repo guardrails file (`.postil/guardrails.md`) injected into the prompt; violations
  surface as `kind: guardrail` findings that quote the rule.
- `postil plan` deterministic config dry-run; `postil doctor`; pre-push hook.
- `.coderabbit.yaml` translation for zero-cost migration.
- Model cascade + concurrent multi-model consensus over any OpenAI-compatible endpoint;
  bounded retry with backoff on transient provider errors.
- Verified `curl | sh` install script with SHA-256 checksum verification; prebuilt
  release binaries for four targets.

## Next

- Sign release artifacts (cosign/minisign) and verify the signature in the installer;
  the current checksum guards against corruption, not a compromised release.
- Bitbucket inline-comment threading and Azure DevOps iteration-aware diffs for very
  large PRs.
- Learning from dismissals: feed comment-resolution outcomes from the hosted platform
  back into per-repo suppression hints.
- `postil respond` parity on GitLab/Bitbucket/Azure (today it is GitHub-only).
- An `/evidence` benchmark: Postil's own silence rate and confirmed-finding rate on
  public OSS PRs, with raw envelopes.
