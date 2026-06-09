# secure-obsidian-memory-mcp

Secure local MCP gateway for connecting AI assistants to persistent Obsidian-based memory through one stable local endpoint.

Connect all your AI assistants to your personal knowledge through one secure local gateway.

## What It Does

This project runs a local TypeScript MCP server that exposes selected markdown memory files to MCP-capable assistants such as Claude, ChatGPT, Gemini, Codex, and local Ollama agents. It is designed for local-first personal memory: your notes stay on your machine, and the server only reads or writes files under `AI_MEMORY_DIR`.

Default MCP endpoint:

```text
http://127.0.0.1:8787/mcp
```

The server uses Express 5 and MCP Streamable HTTP.

## Local-First Design

- The server binds to `127.0.0.1` by default.
- Memory is stored as markdown files under `AI_MEMORY_DIR`.
- No OpenAI, Anthropic, Google, or other model API key is required by this server.
- The repository must only contain fake demo memory under `examples/sample-vault/`.
- Real Obsidian vaults and private memory directories must stay outside Git.

## Available Tools

- `read_main_context`: read the five main memory files.
- `read_handoff_summary`: read `04_MODEL_HANDOFF.md`.
- `search_memory`: search markdown files under `AI_MEMORY_DIR`.
- `read_note`: read one relative `.md` note under `AI_MEMORY_DIR`.
- `update_handoff_summary`: replace `04_MODEL_HANDOFF.md`.
- `append_session_note`: append a timestamped session note under `Sessions/`.
- `add_decision`: append a dated decision to `02_DECISIONS.md`.
- `add_open_task`: append a dated task to `03_OPEN_TASKS.md`.

There is intentionally no delete tool.

## Security Model

Current protections include:

- Bearer-token authentication for the MCP endpoint.
- Separate read and write tokens.
- Write tools disabled by default through `AI_MEMORY_WRITE_ENABLED=false`.
- Markdown-only note access.
- Relative paths only; absolute paths and `../` traversal are rejected.
- Realpath checks keep resolved files inside `AI_MEMORY_DIR`.
- Symlinked directories and notes are rejected or skipped.
- Writes are limited to controlled memory files and generated session notes.
- Privacy-preserving JSON-line audit logs for startup mode, auth failures, denied tool calls, and successful tool calls.
- Host-header guard for local and explicitly allowed hosts.
- Zod validation on tool inputs.
- Request error logs avoid note content.

Audit logging is designed for security review, not content capture. Do not expose this server to untrusted networks without bearer authentication enabled.

## Privacy Warning

Anything reachable under `AI_MEMORY_DIR` can potentially be read by connected MCP clients through search/read tools. Anything sent to an AI assistant may also be processed by that assistant provider according to its own product settings and policies.

Never commit real notes, private memory, secrets, tokens, tunnel URLs, emails, phone numbers, or private filesystem paths. GitHub demo data must live only under `examples/sample-vault/`.

## Quickstart

Install dependencies:

```bash
npm install
```

Run against the fake sample vault:

```bash
cp .env.example .env
export AI_MEMORY_DIR="$PWD/examples/sample-vault"
export MCP_READ_TOKEN="$(openssl rand -hex 32)"
export MCP_WRITE_TOKEN="$(openssl rand -hex 32)"
npm run build
npm start
```

Connect an MCP client to:

```text
http://127.0.0.1:8787/mcp
```

Run tests:

```bash
npm test
```

## Configuration

Copy `.env.example` to `.env` and adjust local values. Keep `.env` out of Git.

Key variables:

- `PORT`: local server port.
- `HOST`: bind address; keep `127.0.0.1` unless you know why you need more.
- `AI_MEMORY_DIR`: markdown memory directory.
- `ALLOWED_HOSTS`: comma-separated additional Host header values.
- `MCP_AUTH_REQUIRED`: defaults to `true`. Set `false` only for explicit local development on `127.0.0.1`.
- `MCP_READ_TOKEN`: bearer token that can call read-only tools.
- `MCP_WRITE_TOKEN`: bearer token that can call read and write tools.
- `AI_MEMORY_WRITE_ENABLED`: defaults to `false`. Write tools are blocked unless this is `true`.
- `LOG_CONTENT`: defaults to `false`. Reserved for future verbosity; audit logs still never include bearer tokens, note bodies, write bodies, or full search queries.
- `MASK_EMAILS`: defaults to `true`. Masks email-like strings in audited metadata.
- `MASK_PHONE_NUMBERS`: defaults to `true`. Masks phone-like strings in audited metadata.
- `MAX_SNIPPET_CHARS`: maximum audited string length for bounded metadata fields.

When `MCP_AUTH_REQUIRED=true`, both tokens must be present and distinct. Missing tokens fail startup safely. MCP clients must send:

```text
Authorization: Bearer <token>
```

The read token can call `read_main_context`, `read_handoff_summary`, `search_memory`, and `read_note`. The write token can also call `update_handoff_summary`, `append_session_note`, `add_decision`, and `add_open_task`, but only when `AI_MEMORY_WRITE_ENABLED=true`.

## Audit Logs

Audit logs are emitted as one JSON object per line on stdout. They record security-relevant metadata such as timestamp, event type, tool name, allowed/denied result, permission level, reason code, safe client IP/host/origin values when available, relative note path when applicable, request/session identifiers when already available, search query length and result count, and write content length.

Audit logs never include bearer tokens, note bodies, write bodies, full search queries, full private file contents, `.env` values, or private vault paths. Redirect stdout through your process manager or container runtime if you need to send audit logs to a file or log collector; keep those logs out of Git.

For safe local development without auth, keep `HOST=127.0.0.1` and explicitly set:

```bash
export MCP_AUTH_REQUIRED=false
export AI_MEMORY_WRITE_ENABLED=false
```

## Safe Public Tunnel Warning

Public tunnels such as ngrok, Cloudflare Tunnel, Tailscale Funnel, or similar tools can make this local MCP server reachable from the internet. A tunnel URL is effectively a remote access path to your memory server.

For public tunnels, keep `MCP_AUTH_REQUIRED=true`, use long random read/write tokens, keep `AI_MEMORY_WRITE_ENABLED=false` unless a trusted write-capable client needs it, and add the tunnel host to `ALLOWED_HOSTS` if required. A public tunnel without auth is unsafe. Use provider access controls, short-lived tunnels, and least-privilege test data. Stop the tunnel when finished.

Audit events for missing or invalid auth and denied tool calls help reveal unsafe tunnel exposure, repeated probing, or a client using the wrong token. They are not a replacement for authentication.
