/** Client for the Kustodyan runtime APIs: Identity (token) and Engine (transform). */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface RpsConfig {
  identityUrl: string;
  engineUrl: string;
  authPath: string;
  transformPath: string;
}

export interface EngineCredentials { clientId: string; clientSecret: string; }

export interface Evidence { name: string; value: string; }

export interface TransformContext {
  guid: string;
  evidences: Evidence[];
}

export interface TransformInstance {
  className?: string;
  propertyName?: string;
  value?: string;
  error?: { code: string; message: string };
  dependencyContext?: { guid: string; evidences: Evidence[] };
}

export interface TransformRequest {
  guid: string;
  rightsContext: string;
  processingContext: string;
  instances: TransformInstance[];
}

export interface TransformInput {
  // The Engine validates loggingContext.evidences (the docs' `attributes` is wrong).
  loggingContext?: { evidences: Evidence[] };
  rightsContexts: TransformContext[];
  processingContexts: TransformContext[];
  requests: TransformRequest[];
}

export interface TransformResponse {
  request: string;
  rightsContext?: string;
  processingContext?: string;
  instances: TransformInstance[];
}

export interface TransformOutput {
  responses?: TransformResponse[];
  error?: { code: string; message: string };
}

export class RpsError extends Error {
  constructor(message: string, readonly status?: number, readonly body?: unknown) {
    super(message);
    this.name = "RpsError";
  }
}

export const REQUEST_TIMEOUT_MS = 30_000;

function trimSlash(u: string) { return u.replace(/\/+$/, ""); }

export const MCP_ENV_FILE = ".env.kustodyan-mcp";

/** Loads an env file into process.env and returns the file used. */
export function loadDotEnv(filePath?: string): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  const pkg = join(here, ".."); // the package root when running dist/server.js
  const candidates = [
    filePath,
    process.env.KUSTODYAN_ENV_FILE,
    join(process.cwd(), MCP_ENV_FILE),
    join(process.cwd(), ".env"),
    join(pkg, MCP_ENV_FILE),
    join(pkg, ".env"),
  ].filter((p): p is string => Boolean(p));

  const path = candidates.map((p) => resolve(p)).find((p) => existsSync(p));
  if (!path) return undefined;

  for (const [key, value] of Object.entries(parseEnvFile(readFileSync(path, "utf8")))) {
    if (process.env[key] === undefined) process.env[key] = value;
  }
  return path;
}

export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[trimmed.slice(0, eq).trim()] = value;
  }
  return out;
}

export function serviceUrl(
  name: "identity" | "engine" | "coreadmin",
  override: string | undefined,
  env = process.env,
): string {
  if (override) return trimSlash(override);
  const base = env.KUSTODYAN_BASE_URL;
  if (!base) {
    throw new Error(
      `Missing required env KUSTODYAN_BASE_URL (e.g. https://dev.kustodyan.io), ` +
      `or set KUSTODYAN_${name.toUpperCase()}_URL explicitly`);
  }
  if (!/^https?:\/\//.test(base)) {
    throw new Error(`KUSTODYAN_BASE_URL must include the scheme, e.g. https://${base}`);
  }
  return `${trimSlash(base)}/api/${name}`;
}

export function loadConfigFromEnv(env = process.env): RpsConfig {
  return {
    identityUrl: serviceUrl("identity", env.KUSTODYAN_IDENTITY_URL, env),
    engineUrl: serviceUrl("engine", env.KUSTODYAN_ENGINE_URL, env),
    authPath: env.KUSTODYAN_AUTH_PATH || "connect/token",
    transformPath: env.KUSTODYAN_TRANSFORM_PATH || "transform",
  };
}

export class RpsClient {
  private tokens = new Map<string, { token: string; exp: number }>();

  constructor(
    private cfg: RpsConfig,
    private readCredentials: (file: string) => Promise<EngineCredentials>,
  ) {}

  get config() { return this.cfg; }

  async getToken(
    credentialsFile: string,
    force = false,
  ): Promise<{ token: string; scope?: string; expiresIn?: number }> {
    const now = Math.floor(Date.now() / 1000);
    const cached = this.tokens.get(credentialsFile);
    if (!force && cached && now < cached.exp - 30) {
      return { token: cached.token };
    }

    let creds = await this.readCredentials(credentialsFile);
    let { res, text } = await this.requestToken(creds);
    // invalid_client: another process may have rotated the secret into the
    // same file since we read it; re-read once and retry on fresh content.
    if (!res.ok && isInvalidClient(res.status, text)) {
      const reread = await this.readCredentials(credentialsFile);
      if (reread.clientId !== creds.clientId || reread.clientSecret !== creds.clientSecret) {
        creds = reread;
        ({ res, text } = await this.requestToken(creds));
      }
    }
    if (!res.ok) {
      throw new RpsError(
        isInvalidClient(res.status, text)
          ? `Identity rejected the credentials in ${credentialsFile} (invalid_client): ` +
            "run create_client to rotate them"
          : `Token request failed (HTTP ${res.status})`,
        res.status, safeJson(text));
    }
    const data = JSON.parse(text);
    this.tokens.set(credentialsFile, {
      token: data.access_token,
      exp: now + (Number(data.expires_in) || 1800),
    });
    return { token: data.access_token, scope: data.scope, expiresIn: Number(data.expires_in) };
  }

  private async requestToken(creds: EngineCredentials): Promise<{ res: Response; text: string }> {
    const res = await fetch(`${this.cfg.identityUrl}/${this.cfg.authPath}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: creds.clientId,
        client_secret: creds.clientSecret,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return { res, text: await res.text() };
  }

  async transform(
    input: TransformInput,
    credentialsFile: string,
  ): Promise<TransformOutput & { httpStatus: number }> {
    const doCall = async (token: string) => {
      const res = await fetch(`${this.cfg.engineUrl}/${this.cfg.transformPath}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(input),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const text = await res.text();
      return { res, text };
    };

    let { token } = await this.getToken(credentialsFile);
    let { res, text } = await doCall(token);
    if (res.status === 401) {
      ({ token } = await this.getToken(credentialsFile, true));
      ({ res, text } = await doCall(token));
    }
    const parsed = (safeJson(text) ?? {}) as TransformOutput;
    if (res.status >= 400 && !parsed.error) {
      throw new RpsError(`Transform failed (HTTP ${res.status})`, res.status, parsed);
    }
    return { ...parsed, httpStatus: res.status };
  }
}

function safeJson(text: string): unknown {
  if (!text) return undefined;
  try { return JSON.parse(text); } catch { return text; }
}

/** OAuth2 invalid_client: wrong or rotated client secret (RFC 6749 §5.2). */
function isInvalidClient(status: number, body: string): boolean {
  if (status !== 400 && status !== 401) return false;
  const parsed = safeJson(body);
  return typeof parsed === "object" && parsed !== null &&
    (parsed as { error?: string }).error === "invalid_client";
}
