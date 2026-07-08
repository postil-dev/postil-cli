export const API_KEY_ENV_NAMES = [
  "POSTIL_API_KEY",
  "OPENROUTER_API_KEY",
  "MODEL_API_KEY",
  "LLM_API_KEY",
] as const;

export type ApiKeyEnvName = (typeof API_KEY_ENV_NAMES)[number];

export const API_KEY_ENV_NAMES_TEXT = API_KEY_ENV_NAMES.join(", ");

export function resolveApiKeyName(env: NodeJS.ProcessEnv = process.env): ApiKeyEnvName | undefined {
  for (const name of API_KEY_ENV_NAMES) {
    const value = env[name];
    if (value !== undefined && value.trim() !== "") return name;
  }
  return undefined;
}

export function forwardApiKey(
  target: NodeJS.ProcessEnv,
  source: NodeJS.ProcessEnv = process.env,
): ApiKeyEnvName | undefined {
  const keyName = resolveApiKeyName(source);
  if (!keyName) return undefined;
  target[keyName] = source[keyName];
  if ((keyName === "MODEL_API_KEY" || keyName === "LLM_API_KEY") && source[keyName]) {
    target.POSTIL_API_KEY = source[keyName];
  }
  return keyName;
}
