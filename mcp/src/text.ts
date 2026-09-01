/** Model-facing text: server instructions, tool titles, descriptions, and field hints. */
import { LOGIN_TIMEOUT_MS } from "./coreadmin.js";

/** Template tag collapsing a multi-line literal into one line. */
function oneLine(strings: TemplateStringsArray, ...values: unknown[]): string {
  return strings
    .reduce((acc, s, i) => acc + s + (i < values.length ? String(values[i]) : ""), "")
    .replace(/\s+/g, " ")
    .trim();
}

export const instructions = (clientName: string) => oneLine`
  Tools for the Kustodyan (RegData RPS) APIs, all working on one server-side
  configuration fixed by the environment.

  The Engine performs a single \`transform\` operation whose behaviour is
  server-configured and selected by the evidence you send: name/value pairs
  defined by the configuration, not a fixed vocabulary (e.g. Role=Admin in a
  rights context, Action=Protect in a processing context). Send a fully-formed
  payload with rightsContexts, processingContexts, and requests. A transform
  that unprotects returns cleartext.

  Engine credentials come from a file: run create_client once, which creates
  the API client named "${clientName}" and writes the credentials to the
  absolute path you give it, conventionally .env.kustodyan-client at the
  project root, git-ignored (the secret is never returned). Pass the same path
  as credentials_file to transform. An app being integrated can load that file
  to authenticate the same way.

  When no CoreAdmin session exists, a call opens a browser window for an
  interactive user login (OAuth code + PKCE) and waits up to
  ${LOGIN_TIMEOUT_MS / 1000}s. If it times out mid-login, ask the user to
  finish logging in and retry: the second attempt reuses their Identity
  session and needs no further interaction.
`;

export const titles = {
  transform: "Transform (Engine)",
  create_client: "Create the MCP's API client (CoreAdmin)",
  list_transformers: "List transformers (CoreAdmin)",
  get_configuration: "Get configuration (CoreAdmin)",
  list_secrets: "List secrets (CoreAdmin)",
  generate_secret_value: "Generate secret value (CoreAdmin)",
  delete_secret: "Delete secret (CoreAdmin)",
  export_configuration: "Export configuration (CoreAdmin)",
  import_configuration: "Import configuration (CoreAdmin)",
  delete_client: "Delete the MCP's API client (CoreAdmin)",
};

export const descriptions = {
  transform: oneLine`
    Send an Engine transform payload (rightsContexts, processingContexts,
    requests). The evidence in the contexts selects the operation: name/value
    pairs defined by the configuration, not a fixed vocabulary (e.g. Role=Admin,
    Action=Protect); the technique per (className, propertyName) is configured
    server-side. A transform that unprotects returns cleartext. Authenticates
    with the credentials file written by create_client, which must have run at
    least once.
  `,

  create_client: (clientName: string) => oneLine`
    Create the API client this MCP owns ("${clientName}") in the pinned
    configuration, or regenerate its secret if it already exists, and write
    the credentials to the given file (0600; inside a git repository the path
    must be git-ignored). The secret is never returned. Run once before the
    first transform; run again to rotate, which invalidates any previously
    written credentials.
  `,

  list_transformers: oneLine`
    List all transformers available in CoreAdmin (id, name, description, type,
    applicable data type, searchability).
  `,

  get_configuration: oneLine`
    Get the configuration this MCP is pinned to: name, locked state, last
    update, and counts of instances, transformers, and clients.
  `,

  list_secrets: oneLine`
    List the secrets of the pinned configuration: id, name, type, group, the
    sequences using each secret, and the secrets managers holding a value for
    it (an empty secretsManagerIds means the secret has no value yet). Returns
    metadata only, never secret values.
  `,

  generate_secret_value: oneLine`
    Generate a value for a secret of the pinned configuration. The value is
    generated and stored server-side in the configuration's secrets manager,
    replacing any existing value; it is never returned.
  `,

  delete_secret: oneLine`
    Delete a secret from the pinned configuration. Configuration imports never
    remove secrets, so this is the only way to drop unused ones.
  `,

  export_configuration: oneLine`
    Export the pinned configuration. Returns the configuration JSON inline
    when the server sends JSON and no save_to path is given; otherwise saves
    the file (e.g. a zip) and returns its location.
  `,

  import_configuration: oneLine`
    Import a configuration file (JSON or zip, as exported by CoreAdmin) into
    the pinned configuration, replacing its contents. Takes a local file path
    and returns counters of imported entities and any errors.
  `,

  delete_client: (clientName: string) => oneLine`
    Delete the API client this MCP owns ("${clientName}") from the pinned
    configuration. Credentials files written by create_client stop working but
    are not removed; create_client makes a new client.
  `,
};

const SECRET_ID = "Id (UUID) of the secret, as returned by list_secrets";

/** Input-schema field hints. `self` describes the containing array or object. */
export const params = {
  evidence: {
    name: "Evidence name defined by the configuration, e.g. Role",
    value: "Evidence value defined by the configuration, e.g. Admin",
  },

  transform: {
    credentials_file: "Absolute path of the credentials file written by create_client",
    rightsContexts: {
      self: "Rights contexts: identity evidence deciding what the caller may do",
      guid: "Caller-chosen UUID, referenced by requests[].rightsContext",
      evidences: "Who is asking, e.g. {name: Role, value: Admin}",
    },
    processingContexts: {
      self: "Processing contexts: action evidence selecting the transformation to apply",
      guid: "Caller-chosen UUID, referenced by requests[].processingContext",
      evidences: "What to do, e.g. {name: Action, value: Protect}",
    },
    requests: {
      self: "Transform requests, each referencing one rights and one processing context",
      guid: "Caller-chosen UUID identifying this request in the response",
      rightsContext: "guid of one of the rightsContexts",
      processingContext: "guid of one of the processingContexts",
      instances: {
        self: "Values to transform, each mapped to a configured (className, propertyName)",
        className: "Configured class name, e.g. person",
        propertyName: "Configured property name, e.g. first_name",
        value: "The value to transform",
      },
    },
    loggingContext: {
      self: "Optional context recorded in the server-side audit log",
      evidences: "Free-form evidence recorded in server logs",
    },
  },

  create_client: {
    credentials_file:
      "Absolute path to write the credentials to, e.g. <project>/.env.kustodyan-client",
  },

  generate_secret_value: {
    secret_id: SECRET_ID,
    values_count: "Number of values to generate (for MultipleKeys secrets; default 1)",
    secrets_manager_id:
      "Secrets manager to store the value in; only needed when the configuration has several",
  },

  delete_secret: {
    secret_id: SECRET_ID,
  },

  export_configuration: {
    includeHelperData: "Also export helper data (server default: false)",
    save_to: "Local file path to save the export to",
  },

  import_configuration: {
    file_path: "Local path of the configuration file to upload",
  },
};
