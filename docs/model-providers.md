# Model providers

Postil speaks either an OpenAI-compatible chat-completions interface or the native Anthropic Messages API. Provider requests do not follow redirects, credentials are never written to logs, and private-network endpoints require an explicit opt-in.

## OpenAI-compatible

OpenRouter is the default endpoint. Ollama, vLLM, SGLang, LiteLLM, and private gateways can use the same contract.

```sh
export MODEL_API_KEY=...
export POSTIL_API_BASE=https://openrouter.ai/api/v1
export REVIEW_MODEL=mistralai/mistral-small-3.2-24b-instruct
postil doctor
```

These requests authenticate with `Authorization: Bearer`.

## Anthropic Messages API

```sh
export MODEL_API_KEY=...
export POSTIL_API_BASE=https://api.anthropic.com/v1
export POSTIL_API_FORMAT=anthropic
export REVIEW_MODEL=claude-sonnet-4-6
postil doctor
```

Native Anthropic requests use `x-api-key` and `anthropic-version`. Set `REVIEW_SCORER_MODEL` to a model available through the same endpoint when scoring is required.

## Local endpoints

Private and loopback addresses are denied unless the operator permits them:

```sh
ollama pull qwen3-coder:30b

POSTIL_API_BASE=http://localhost:11434/v1 \
POSTIL_ALLOW_PRIVATE_API_BASE=1 \
MODEL_API_KEY=local \
REVIEW_MODEL=qwen3-coder:30b \
postil review --staged
```

The API hostname is resolved before the request and the client is pinned to accepted addresses while retaining hostname-based TLS checks.

## Additional gateway authentication

Private gateways can require one additional header:

```sh
POSTIL_ENDPOINT_AUTH_HEADER=X-Gateway-Token \
POSTIL_ENDPOINT_AUTH_VALUE=... \
postil doctor
```

Reserved provider headers cannot be replaced. Pass secrets through environment variables or a secret manager, not command-line arguments.
