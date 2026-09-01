#!/usr/bin/env node
/** kustodyan-mcp: tool registration and the stdio entry point. See README.md. */
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  MCP_ENV_FILE, RpsClient, loadConfigFromEnv, loadDotEnv,
  type TransformInput,
} from "./rps.js";
import { CoreAdminClient, loadCoreAdminConfigFromEnv } from "./coreadmin.js";
import { clientNameFromEnv, createClient, readCredentialsFile } from "./credentials.js";
import { descriptions, instructions, params, titles } from "./text.js";

const VERSION = "0.1.0";

function jsonResult(obj: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }], structuredContent: obj as Record<string, unknown> };
}

const evidenceSchema = z.object({
  name: z.string().describe(params.evidence.name),
  value: z.string().describe(params.evidence.value),
});

export function buildServer(
  client: RpsClient,
  coreAdmin: CoreAdminClient,
  clientName: string,
): McpServer {
  const server = new McpServer(
    { name: "kustodyan-mcp", version: VERSION },
    { instructions: instructions(clientName) },
  );

  const t = params.transform;
  server.registerTool("transform", {
    title: titles.transform,
    description: descriptions.transform,
    inputSchema: {
      credentials_file: z.string().describe(t.credentials_file),
      rightsContexts: z.array(z.object({
        guid: z.string().describe(t.rightsContexts.guid),
        evidences: z.array(evidenceSchema).describe(t.rightsContexts.evidences),
      })).min(1).describe(t.rightsContexts.self),
      processingContexts: z.array(z.object({
        guid: z.string().describe(t.processingContexts.guid),
        evidences: z.array(evidenceSchema).describe(t.processingContexts.evidences),
      })).describe(t.processingContexts.self),
      requests: z.array(z.object({
        guid: z.string().describe(t.requests.guid),
        rightsContext: z.string().describe(t.requests.rightsContext),
        processingContext: z.string().describe(t.requests.processingContext),
        instances: z.array(z.object({
          className: z.string().optional().describe(t.requests.instances.className),
          propertyName: z.string().optional().describe(t.requests.instances.propertyName),
          value: z.string().describe(t.requests.instances.value),
        })).describe(t.requests.instances.self),
      })).min(1).describe(t.requests.self),
      loggingContext: z.object({
        evidences: z.array(evidenceSchema).describe(t.loggingContext.evidences),
      }).optional().describe(t.loggingContext.self),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  }, async ({ credentials_file, ...payload }) => {
    const out = await client.transform(payload as unknown as TransformInput, credentials_file);
    return jsonResult(out);
  });

  server.registerTool("create_client", {
    title: titles.create_client,
    description: descriptions.create_client(clientName),
    inputSchema: {
      credentials_file: z.string().describe(params.create_client.credentials_file),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  }, async ({ credentials_file }) =>
    jsonResult(await createClient(coreAdmin, clientName, client.config, credentials_file)));

  const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
  server.registerTool("list_transformers", {
    title: titles.list_transformers,
    description: descriptions.list_transformers,
    inputSchema: {},
    annotations: readOnly,
  }, async () => {
    const transformers = await coreAdmin.listTransformers();
    return jsonResult({ count: transformers.length, transformers });
  });

  server.registerTool("get_configuration", {
    title: titles.get_configuration,
    description: descriptions.get_configuration,
    inputSchema: {},
    annotations: readOnly,
  }, async () => jsonResult(await coreAdmin.getConfiguration()));

  server.registerTool("list_secrets", {
    title: titles.list_secrets,
    description: descriptions.list_secrets,
    inputSchema: {},
    annotations: readOnly,
  }, async () => {
    const secrets = await coreAdmin.listSecrets();
    return jsonResult({ count: secrets.length, secrets });
  });

  server.registerTool("generate_secret_value", {
    title: titles.generate_secret_value,
    description: descriptions.generate_secret_value,
    inputSchema: {
      secret_id: z.string().describe(params.generate_secret_value.secret_id),
      values_count: z.number().int().min(1).optional()
        .describe(params.generate_secret_value.values_count),
      secrets_manager_id: z.string().optional()
        .describe(params.generate_secret_value.secrets_manager_id),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }, async ({ secret_id, values_count, secrets_manager_id }) =>
    jsonResult(await coreAdmin.generateSecretValue(secret_id, {
      valuesCount: values_count, secretsManagerId: secrets_manager_id,
    })));

  server.registerTool("delete_secret", {
    title: titles.delete_secret,
    description: descriptions.delete_secret,
    inputSchema: {
      secret_id: z.string().describe(params.delete_secret.secret_id),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }, async ({ secret_id }) => {
    await coreAdmin.deleteSecret(secret_id);
    return jsonResult({ deleted: secret_id });
  });

  server.registerTool("export_configuration", {
    title: titles.export_configuration,
    description: descriptions.export_configuration,
    inputSchema: {
      includeHelperData: z.boolean().optional()
        .describe(params.export_configuration.includeHelperData),
      save_to: z.string().optional().describe(params.export_configuration.save_to),
    },
    annotations: readOnly,
  }, async ({ includeHelperData, save_to }) =>
    jsonResult(await coreAdmin.exportConfiguration({ includeHelperData, saveTo: save_to })));

  server.registerTool("import_configuration", {
    title: titles.import_configuration,
    description: descriptions.import_configuration,
    inputSchema: { file_path: z.string().describe(params.import_configuration.file_path) },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }, async ({ file_path }) => jsonResult(await coreAdmin.importConfiguration(file_path)));

  server.registerTool("delete_client", {
    title: titles.delete_client,
    description: descriptions.delete_client(clientName),
    inputSchema: {},
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  }, async () => {
    const existing = await coreAdmin.findClientByName(clientName);
    if (existing?.id) await coreAdmin.deleteClient(existing.id);
    return jsonResult({ deleted: Boolean(existing), client: clientName });
  });

  return server;
}

async function main() {
  const envFile = loadDotEnv();
  const coreAdminCfg = loadCoreAdminConfigFromEnv();
  if (!coreAdminCfg) {
    throw new Error(
      `Not configured (${envFile ? `loaded ${envFile}` : `no env file found in ${process.cwd()}, ` +
      `looked for ${MCP_ENV_FILE} and .env`}): set KUSTODYAN_COREADMIN_CLIENT_ID, ` +
      "KUSTODYAN_BASE_URL, and the account, target, and configuration ids");
  }
  const engineCfg = loadConfigFromEnv();
  const coreAdmin = new CoreAdminClient(coreAdminCfg);
  const server = buildServer(
    new RpsClient(engineCfg, readCredentialsFile), coreAdmin, clientNameFromEnv());
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `[kustodyan-mcp] stdio transport ready; configured from ${envFile ?? "the process environment"}\n`);
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  main().catch((e) => { process.stderr.write(`[kustodyan-mcp] fatal: ${(e as Error).stack || e}\n`); process.exit(1); });
}
