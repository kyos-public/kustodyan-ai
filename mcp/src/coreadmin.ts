/** Client for the Kustodyan CoreAdmin API (RPS Core Configuration Admin Web API). */
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { RpsError, REQUEST_TIMEOUT_MS, serviceUrl } from "./rps.js";

export interface CoreAdminConfig {
  identityUrl: string;
  coreAdminUrl: string;
  clientId: string;
  redirectUri: string;  // must be registered on the client in Identity
  scope: string;
  // The MCP is pinned to one configuration; these scope every request.
  accountId: string;
  targetId: string;
  configurationId: string;
}

export const LOGIN_TIMEOUT_MS = 60_000;

export interface Transformer {
  id?: string;
  name?: string;
  description?: string;
  type?: "Transform" | "Wrap" | "Unwrap" | "InsertProperty" | "ExtractProperty" | "Format" | "Validate";
  applicableDataType?: string;
  isSearchable?: boolean;
}

/** ConfigurationWithCounters in the CoreAdmin API. */
export interface ConfigurationInfo {
  id?: string;
  name?: string;
  locked?: boolean;
  lastUpdate?: string;
  instances?: number;
  transformers?: number;
  clients?: number;
}

/** ConfigurationImportContext in the CoreAdmin API. */
export interface ConfigurationImportResult {
  instances?: number;
  processingContexts?: number;
  secrets?: number;
  transformers?: number;
  rightsContexts?: number;
  evidences?: number;
  transformersDataSets?: number | null;
  errors?: string[] | null;
}

/** Secret in the CoreAdmin API. Values live in secrets managers, never here. */
export interface Secret {
  id?: string;
  name?: string;
  description?: string;
  group?: string;
  type?: "Unknown" | "SingleKey" | "MultipleKeys";
  /** Secrets managers holding a value for this secret; empty = missing value. */
  secretsManagerIds?: string[];
  /** Transformer sequences using this secret. */
  sequences?: { id?: string; name?: string }[];
  lastUpdated?: string;
  createdByUserName?: string;
}

export interface SecretsManager {
  id?: string;
  name?: string;
  type?: string;
}

/** ConfigurationClient in the CoreAdmin API. `id` is the entity id; `clientId` is the OAuth client id. */
export interface ConfigurationClient {
  id?: string;
  name?: string;
  clientId?: string;
  type?: "None" | "Global" | "Scoped";
}

/** Returned by create and regenerate-secret: the only two calls that expose a secret. */
export interface ConfigurationClientWithSecret extends ConfigurationClient {
  rightsContexts?: string[];
  processingContexts?: string[];
  secretsManagers?: string[];
  clientSecret?: string;
}

export const CLIENT_NAME_MAX_LENGTH = 50;

export function loadCoreAdminConfigFromEnv(env = process.env): CoreAdminConfig | undefined {
  const clientId = env.KUSTODYAN_COREADMIN_CLIENT_ID;
  if (!clientId) return undefined;
  const need = (k: string) => {
    const v = env[k];
    if (!v) throw new Error(`Missing required env ${k} (required when CoreAdmin is enabled)`);
    return v;
  };
  return {
    identityUrl: serviceUrl("identity", env.KUSTODYAN_IDENTITY_URL, env),
    coreAdminUrl: serviceUrl("coreadmin", env.KUSTODYAN_COREADMIN_URL, env),
    clientId,
    redirectUri: env.KUSTODYAN_COREADMIN_REDIRECT_URI || "http://localhost:8976/callback",
    // offline_access asks for a refresh token, so the browser login happens
    // once per process instead of at every access-token expiry.
    scope: env.KUSTODYAN_COREADMIN_SCOPE || "rps_config_admin_api offline_access",
    accountId: need("KUSTODYAN_COREADMIN_ACCOUNT_ID"),
    targetId: need("KUSTODYAN_COREADMIN_TARGET_ID"),
    configurationId: need("KUSTODYAN_COREADMIN_CONFIGURATION_ID"),
  };
}

function base64Url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

function openBrowser(url: string): void {
  // win32: rundll32 instead of `cmd /c start` — cmd would mangle the `&`s in the URL.
  const [cmd, ...args] = process.platform === "darwin" ? ["open", url]
    : process.platform === "win32" ? ["rundll32", "url.dll,FileProtocolHandler", url]
    : ["xdg-open", url];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch {
    // Fall through: the URL is also printed to stderr by the caller.
  }
}

interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  exp: number; // epoch seconds
}

export class CoreAdminClient {
  private tokens?: TokenSet;
  private renewInFlight?: Promise<TokenSet>;
  constructor(private cfg: CoreAdminConfig) {}

  get config() { return this.cfg; }

  async getToken(force = false): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (!force && this.tokens && now < this.tokens.exp - 30) return this.tokens.accessToken;

    // Single-flight: parallel tool calls share one refresh (a rotated refresh
    // token is single-use) and one browser prompt.
    if (!this.renewInFlight) {
      this.renewInFlight = this.renew().finally(() => { this.renewInFlight = undefined; });
    }
    this.tokens = await this.renewInFlight;
    return this.tokens.accessToken;
  }

  private async renew(): Promise<TokenSet> {
    const refreshToken = this.tokens?.refreshToken;
    if (refreshToken) {
      try {
        return await this.exchangeToken({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: this.cfg.clientId,
        }, refreshToken);
      } catch (e) {
        process.stderr.write(`[kustodyan-mcp] CoreAdmin token refresh failed, falling back to browser login: ${(e as Error).message}\n`);
      }
    }
    return this.interactiveLogin();
  }

  private async interactiveLogin(): Promise<TokenSet> {
    const verifier = base64Url(randomBytes(32));
    const challenge = base64Url(createHash("sha256").update(verifier).digest());
    const state = base64Url(randomBytes(16));
    const redirect = new URL(this.cfg.redirectUri);

    const authorizeUrl = new URL(`${this.cfg.identityUrl}/connect/authorize`);
    authorizeUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      scope: this.cfg.scope,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();

    const code = await this.waitForCallback(redirect, state, authorizeUrl.toString());

    return this.exchangeToken({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.cfg.redirectUri,
      client_id: this.cfg.clientId,
      code_verifier: verifier,
    });
  }

  private waitForCallback(redirect: URL, expectedState: string, authorizeUrl: string): Promise<string> {
    return new Promise<string>((resolvePromise, rejectPromise) => {
      let server: Server;
      let timer: NodeJS.Timeout;
      const done = (fn: () => void) => { clearTimeout(timer); server.close(); fn(); };

      server = createServer((req, res) => {
        const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
        if (url.pathname !== redirect.pathname) {
          res.writeHead(404).end();
          return;
        }
        const err = url.searchParams.get("error");
        const code = url.searchParams.get("code");
        const state = url.searchParams.get("state");
        const finish = (status: number, message: string) => {
          res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
          res.end(`<html><body style="font-family:sans-serif"><p>${message}</p><p>You can close this tab.</p></body></html>`);
        };
        if (err) {
          finish(400, `Login failed: ${escapeHtml(err)}`);
          done(() => rejectPromise(new RpsError(`Authorization failed: ${err} ${url.searchParams.get("error_description") || ""}`.trim())));
        } else if (!code || state !== expectedState) {
          finish(400, "Invalid callback (missing code or state mismatch).");
          done(() => rejectPromise(new RpsError("Invalid OAuth callback (missing code or state mismatch)")));
        } else {
          finish(200, "Kustodyan CoreAdmin login successful.");
          done(() => resolvePromise(code));
        }
      });

      server.on("error", (e) => { clearTimeout(timer); rejectPromise(new RpsError(`Cannot listen on ${redirect.href}: ${(e as Error).message}`)); });

      server.listen(Number(redirect.port) || 80, redirect.hostname, () => {
        timer = setTimeout(
          () => done(() => rejectPromise(new RpsError(`Login timed out after ${LOGIN_TIMEOUT_MS / 1000}s`))),
          LOGIN_TIMEOUT_MS,
        );
        process.stderr.write(`[kustodyan-mcp] CoreAdmin login required — opening browser:\n${authorizeUrl}\n`);
        openBrowser(authorizeUrl);
      });
    });
  }

  private async exchangeToken(params: Record<string, string>, previousRefreshToken?: string): Promise<TokenSet> {
    const res = await fetch(`${this.cfg.identityUrl}/connect/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    if (!res.ok) throw new RpsError(`Token request failed (HTTP ${res.status})`, res.status, safeJson(text));
    const data = JSON.parse(text);
    return {
      accessToken: data.access_token,
      // Servers without rotation may omit refresh_token on refresh: keep the old one.
      refreshToken: data.refresh_token || previousRefreshToken,
      exp: Math.floor(Date.now() / 1000) + (Number(data.expires_in) || 300),
    };
  }

  private async request(
    method: string,
    path: string,
    init?: { body?: BodyInit; headers?: Record<string, string>; accept?: string },
  ): Promise<Response> {
    const doCall = async (token: string) =>
      fetch(`${this.cfg.coreAdminUrl}/${path.replace(/^\/+/, "")}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: init?.accept || "application/json",
          ...init?.headers,
        },
        body: init?.body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

    let res = await doCall(await this.getToken());
    if (res.status === 401) res = await doCall(await this.getToken(true));
    return res;
  }

  private async requestJson<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.request(method, path, body === undefined ? undefined : {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });
    const text = await res.text();
    if (!res.ok) throw coreAdminError(`${method} /${path}`, res.status, text);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  private get configPath(): string {
    const { accountId, targetId, configurationId } = this.cfg;
    return `accounts/${accountId}/targets/${targetId}/configurations/${configurationId}`;
  }

  async listTransformers(): Promise<Transformer[]> {
    return this.requestJson<Transformer[]>("GET", "transformers");
  }

  async getConfiguration(): Promise<ConfigurationInfo> {
    return this.requestJson<ConfigurationInfo>("GET", this.configPath);
  }

  async listSecrets(): Promise<Secret[]> {
    return this.requestJson<Secret[]>("GET", `${this.configPath}/secrets`);
  }

  /** The value is generated server-side and never passes through this process. */
  async generateSecretValue(secretId: string, opts: { valuesCount?: number; secretsManagerId?: string } = {}): Promise<Secret> {
    const managerId = opts.secretsManagerId ?? await this.soleSecretsManagerId();
    const body = { [managerId]: { generateValueOptions: { valuesCount: opts.valuesCount ?? 1 } } };
    return this.requestJson<Secret>("PUT", `${this.configPath}/secrets/${secretId}/value`, body);
  }

  private async soleSecretsManagerId(): Promise<string> {
    const managers = await this.requestJson<SecretsManager[]>("GET", `${this.configPath}/secrets-managers`);
    if (managers.length !== 1) {
      throw new RpsError(
        `Cannot pick a secrets manager automatically: the configuration has ${managers.length} ` +
        `assigned (${managers.map((m) => `${m.name ?? "?"}=${m.id}`).join(", ") || "none"}). ` +
        "Pass secretsManagerId explicitly.");
    }
    return managers[0].id!;
  }

  async deleteSecret(secretId: string): Promise<void> {
    await this.requestJson<void>("DELETE", `${this.configPath}/secrets/${secretId}`);
  }

  async listClients(): Promise<ConfigurationClient[]> {
    return this.requestJson<ConfigurationClient[]>("GET", `${this.configPath}/clients`);
  }

  async findClientByName(name: string): Promise<ConfigurationClient | undefined> {
    const clients = await this.listClients();
    return clients.find((c) => c.name?.toLowerCase() === name.toLowerCase());
  }

  /** Regenerating an existing client's secret invalidates the one issued before. */
  async ensureClient(name: string): Promise<{ id: string; clientId: string; clientSecret: string; created: boolean }> {
    const existing = await this.findClientByName(name);
    const client = existing?.id
      ? await this.requestJson<ConfigurationClientWithSecret>(
          "PUT", `${this.configPath}/clients/${existing.id}/regenerate-secret`)
      : await this.requestJson<ConfigurationClientWithSecret>("POST", `${this.configPath}/clients`, {
          name,
          type: "Global",
          secretsManagers: [await this.soleSecretsManagerId()],
        });
    if (!client?.clientId || !client.clientSecret) {
      throw new RpsError(`CoreAdmin returned no credentials for client ${name}`);
    }
    return {
      id: client.id ?? existing?.id ?? "",
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      created: !existing,
    };
  }

  async deleteClient(id: string): Promise<void> {
    await this.requestJson<void>("DELETE", `${this.configPath}/clients/${id}`);
  }

  async importConfiguration(filePath: string): Promise<ConfigurationImportResult> {
    const data = await readFile(filePath);
    // The server selects its importer from the part's content type; an
    // untyped part (application/octet-stream) is rejected as INVALID_FORMAT.
    const types: Record<string, string> = {
      json: "application/json",
      zip: "application/zip",
      xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    };
    const ext = filePath.split(".").pop()?.toLowerCase() || "";
    const form = new FormData();
    form.append("file", new Blob([new Uint8Array(data)], { type: types[ext] || "application/json" }), basename(filePath));
    const res = await this.request("POST", `${this.configPath}/import`, { body: form });
    const text = await res.text();
    if (!res.ok) throw coreAdminError("import", res.status, text);
    return (text ? JSON.parse(text) : {}) as ConfigurationImportResult;
  }

  async exportConfiguration(opts: { includeHelperData?: boolean; saveTo?: string } = {}):
    Promise<unknown | { savedTo: string; contentType: string; bytes: number }> {
    const query = opts.includeHelperData === undefined ? "" : `?includeHelperData=${opts.includeHelperData}`;
    const res = await this.request("GET", `${this.configPath}/export${query}`, {
      accept: "application/json, application/zip",
    });
    if (!res.ok) {
      throw coreAdminError("export", res.status, await res.text());
    }
    const contentType = res.headers.get("content-type") || "";
    if (!opts.saveTo && contentType.includes("json")) return JSON.parse(await res.text());
    const buf = Buffer.from(await res.arrayBuffer());
    const ext = contentType.includes("zip") ? "zip" : "json";
    const savedTo = resolve(opts.saveTo || join(tmpdir(), `kustodyan-config-export-${Date.now()}.${ext}`));
    await writeFile(savedTo, buf);
    return { savedTo, contentType, bytes: buf.length };
  }
}

function safeJson(text: string): unknown {
  if (!text) return undefined;
  try { return JSON.parse(text); } catch { return text; }
}

/** Include the response body in the message: MCP clients only surface error.message. */
function coreAdminError(what: string, status: number, body: string): RpsError {
  const detail = body ? `: ${body.slice(0, 1000)}` : "";
  return new RpsError(`CoreAdmin ${what} failed (HTTP ${status})${detail}`, status, safeJson(body));
}
