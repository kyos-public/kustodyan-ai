# Kustodyan MCP Server (Experimental)

A [Model Context Protocol](https://modelcontextprotocol.io) server for the [Kustodyan](https://www.kustodyan.com) data-protection API (powered by the RegData Protection Suite, RPS). It gives AI agents the Engine API (`transform`) and part of the CoreAdmin configuration API, over stdio.

## What it does

The Engine has a single `transform` operation. Behaviour is selected by the evidence you send, plus the `(className, propertyName)` of each data instance. Evidence is a set of name/value pairs defined by the configuration, not a fixed vocabulary; `Role=Admin` in a rights context and `Action=Protect` in a processing context are only a common convention. The technique (encryption, tokenization, anonymization, masking) is configured server-side, never chosen by the caller.

CoreAdmin manages configuration and uses OAuth 2.0 authorization code + PKCE: a client id, no secret, and an interactive browser login. Every tool operates on one configuration, pinned by the account, target, and configuration IDs. Cross-configuration operations (create, destroy, clone, move) are deliberately not exposed.

## Build

```bash
cd mcp
npm install
npm run build # -> dist/
```

Then point an MCP client at `dist/server.js` over stdio, with the variables below in its `env` block.

## Configuration

Put the variables in the `env` block of the MCP client config, one entry per project:

```json
{
  "mcpServers": {
    "kustodyan": {
      "command": "node",
      "args": ["/path/to/kustodyan-mcp/dist/server.js"],
      "env": {
        "KUSTODYAN_BASE_URL": "https://dev.kustodyan.io",
        "KUSTODYAN_COREADMIN_CLIENT_ID": "…",
        "KUSTODYAN_COREADMIN_ACCOUNT_ID": "…",
        "KUSTODYAN_COREADMIN_TARGET_ID": "…",
        "KUSTODYAN_COREADMIN_CONFIGURATION_ID": "…"
      }
    }
  }
}
```

| Variable                                    | Required | Description                                     |
| ------------------------------------------- | -------- | ------------------------------------------------- |
| `KUSTODYAN_BASE_URL`                        | yes      | Each API is `<base>/api/<service>`              |
| `KUSTODYAN_COREADMIN_CLIENT_ID`             | yes      | Interactive client, no secret                   |
| `KUSTODYAN_COREADMIN_ACCOUNT_ID`            | yes      | Account of the pinned configuration             |
| `KUSTODYAN_COREADMIN_TARGET_ID`             | yes      | Target of the pinned configuration              |
| `KUSTODYAN_COREADMIN_CONFIGURATION_ID`      | yes      | The configuration every tool operates on        |
| `KUSTODYAN_COREADMIN_REDIRECT_URI`          | no       | Default `http://localhost:8976/callback`        |
| `KUSTODYAN_COREADMIN_SCOPE`                 | no       | Default `rps_config_admin_api offline_access`   |
| `KUSTODYAN_{IDENTITY,ENGINE,COREADMIN}_URL` | no       | Per-service overrides                           |
| `KUSTODYAN_CLIENT_NAME`                     | no       | Default `kustodyan-mcp`, max 50 characters      |

### Using an env file instead

None of these variables is a secret, but they identify the tenant, and the client config is usually committed. To keep them out of version control, set `KUSTODYAN_ENV_FILE`, or put a `.env.kustodyan-mcp` of `KEY=value` lines in the working directory. The server loads the first it finds: `KUSTODYAN_ENV_FILE`, `.env.kustodyan-mcp` or `.env` in the working directory, then the same two next to the package. The process environment wins over the file, so the two can be mixed.

### CoreAdmin login

On the first call needing a CoreAdmin token (every tool except `transform`, which only talks to Identity and the Engine), the server opens the system browser on the Identity authorize endpoint and listens on the redirect URI for the code (PKCE, S256). If the call times out mid-login, the listener closes and the redirect fails; finish the login anyway and retry, and the second attempt reuses the Identity session without further interaction. Tokens are cached in memory and refreshed while Identity grants a refresh token, so a restart means a new login.

## Engine credentials

There are no Engine credentials to configure. The MCP owns one API client of the pinned configuration, named `kustodyan-mcp`. `create_client` creates it, or regenerates its secret if it already exists, and writes the id and secret to the absolute path you pass it, conventionally `.env.kustodyan-client` at the project root (add it to `.gitignore`). `transform` takes the same path as its `credentials_file` argument, so it must run after `create_client`; nothing is provisioned implicitly. Running `create_client` again rotates the secret, which invalidates any credentials written earlier.

No tool returns the secret, so it stays out of the agent's context and the chat transcript. The file is written `0600` through a temporary file and a rename; writing is refused if the path sits in a git repository that does not ignore it, or if a file the MCP did not generate is already there. An app being integrated can load the file and authenticate exactly as the MCP does, which makes a working `transform` and a working app the same fact.

## Tools

| Tool                    | Purpose                                              |
| ----------------------- | ---------------------------------------------------- |
| `create_client`         | Create the MCP's API client, write its credentials   |
| `transform`             | Run an Engine transform. Unprotect returns cleartext |
| `list_transformers`     | List the available transformers                      |
| `get_configuration`     | Name, locked state, entity counts                    |
| `list_secrets`          | Secret metadata, never values                        |
| `generate_secret_value` | Generate a secret's value server-side                |
| `delete_secret`         | Delete a secret                                      |
| `export_configuration`  | Export as inline JSON or to a file                   |
| `import_configuration`  | Replace the configuration from a file                |
| `delete_client`         | Delete the MCP's API client                          |

Any tool may open a browser window for user login when no session exists.
