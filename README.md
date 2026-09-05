# Postil CLI

Postil reviews local changes and pull requests for merge-relevant defects. It reports gate status separately from advisory findings and leaves clean changes without a review comment.

## Quick start

Install a release build:

```sh
curl -fsSL https://postil.dev/install.sh | sh
```

The installer verifies the release checksum. Add `--require-cosign` to require Sigstore verification. To build from source instead:

```sh
cargo install --git https://github.com/postil-dev/postil-cli --locked
```

Authenticate for hosted inference, or provide a key for a supported model endpoint, then review the repository:

```sh
postil login
# Or set MODEL_API_KEY for your model endpoint.
postil doctor
postil review
postil hook install
```

`postil review` selects staged changes first, then branch changes, then tracked working-tree changes. It does not change the working tree, index, or refs. Use `--publish` only when a forge review and checks should be written.

For a pull request, set `GITHUB_TOKEN` through the environment:

```sh
postil review --repo owner/repository --pr 123 --publish
```

`--publish` is required for forge writes. Published reviews create `postil/review` and `postil/gate`; require only `postil/gate` in branch protection.

## Documentation

- [Configuration](docs/configuration.md): policy, model selection, and configuration precedence.
- [Model providers](docs/model-providers.md): OpenAI-compatible and Anthropic endpoints.
- [Code forges](docs/forges.md): GitHub, GitLab, Bitbucket, and Azure DevOps.
- [Automation](docs/automation.md): SARIF, incremental review, envelopes, and receipts.
- [Benchmarks](bench/README.md): offline regression suite and live qualification.
- [Public benchmark results](https://postil.dev/bench): model-screening results and raw report.
- [Architecture](ARCHITECTURE.md): trust boundaries and review pipeline.
- [Product documentation](https://postil.dev/docs): hosted setup and reference material.

Use `postil models` for offline guidance about the embedded model configuration and accepted endpoint model IDs. Use `postil config` to inspect resolved non-secret configuration.

## License

Apache-2.0.
