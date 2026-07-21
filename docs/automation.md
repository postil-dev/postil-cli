# Automation

## Machine-readable output

`postil review --output json` and `--output yaml` emit the complete versioned review envelope. `--output csv` emits a flattened findings table with review and gate fields repeated on each row. `--output-file <path>` keeps structured output separate from human-readable output.

The JSON and YAML envelope contains the summary, findings, resolved findings, policy counts, gate result, model and scorer metadata, token usage, per-model usage, and reviewed SHAs. `usageAccountingComplete` is false when a provider request can have unknown billed usage.

`--sarif <path>` writes SARIF 2.1.0 for code-scanning ingestion.

## Incremental review

```sh
postil review \
  --repo owner/repository \
  --pr 123 \
  --since-sha <last-reviewed-head> \
  --baseline <previous-envelope.json>
```

Postil reviews new commits, carries unresolved findings forward, and marks findings as resolved when the relevant code changes.

## Preview policy changes

`postil plan` replays stored envelopes through a candidate configuration without making a model call:

```sh
postil plan --envelopes .cache/envelopes --config .postil.candidate.yaml
```

The report shows which findings become visible or suppressed and which gate results change.

## Interactive replies

`postil respond` answers a mention on a pull request. GitHub and GitLab also support issue mentions. It does not open pull requests or push commits.
Posting the reply requires `--publish`; without it, the reply is printed locally.
CI detection and environment variables do not authorize a forge write.

```sh
POSTIL_COMMENT='@postil is this safe?' \
postil respond --repo owner/repository --pr 123 --publish
```

Pass comment text through `POSTIL_COMMENT` in automation because command-line arguments are visible to other local processes.

## Usage receipts

Hosted workers can set `POSTIL_USAGE_RECEIPT_PATH` to a worker-owned path. A successful response writes a mode-`0600` version 2 JSON receipt before forge delivery. Every provider attempt includes its role, phase, operation-wide call ordinal, transport attempt, token counts, accounting-completeness flag, cost source, canonical provider-reported decimal cost when present, and rounded micro-dollar display value. The caller owns receipt deletion. Receipt consumers must accept the additional `costProviderDecimal` field before deploying this CLI.

Hosted reviews can set `POSTIL_PUBLICATION_RECEIPT_PATH` to a worker-owned path. Review publication writes a mode-`0600` version 1 JSON receipt atomically. Each entry carries the stable finding ID when present, marks legacy fallback identities, and records its initial publication outcome. GitHub receipts include review and inline-comment identities when available and record rejected inline placement before the summary-only fallback. The GitHub create-review body makes no inline-delivery claim; an idempotent review-summary update adds only the count backed by observed comment IDs, while exhausted update retries leave the claim absent and preserve the receipt. Reconciled retries return the existing review identities without posting a duplicate. The caller owns receipt deletion.
