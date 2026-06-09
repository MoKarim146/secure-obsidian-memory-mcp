# Security Policy

## Supported Security Model

`secure-obsidian-memory-mcp` is intended to run as a local-first MCP gateway on a trusted user machine. The supported default deployment is:

- Bind to `127.0.0.1`.
- Use a dedicated `AI_MEMORY_DIR`.
- Store only markdown memory files in that directory.
- Connect only trusted MCP clients.
- Keep `MCP_AUTH_REQUIRED=true`.
- Use distinct long random values for `MCP_READ_TOKEN` and `MCP_WRITE_TOKEN`.
- Keep `AI_MEMORY_WRITE_ENABLED=false` unless a trusted write-capable client needs writes.
- Use fake data from `examples/sample-vault/` for public demos and tests.

This project implements bearer-token authentication for MCP requests. Public exposure is supported only with authentication enabled and preferably with a separate authenticated reverse proxy or tunnel access-control layer in front of the server.

## Reporting Security Issues

Do not open a public GitHub issue for suspected vulnerabilities involving private data exposure, authentication bypasses, path traversal, unsafe writes, or secret leakage.

Use a private reporting channel configured in the GitHub repository security settings. If that is not available yet, contact the repository owner through a private channel and include:

- A concise description of the issue.
- Impact and affected configuration.
- Reproduction steps using fake data only.
- Suggested fix, if known.

Do not include real vault contents, secrets, tokens, private tunnel URLs, emails, phone numbers, or private filesystem paths.

## Known Risks

- Public tunnels can expose the MCP endpoint to anyone who can reach the URL unless the tunnel is protected.
- Connected AI assistants may send note content to their provider.
- Search/read tools can expose any markdown file under `AI_MEMORY_DIR`.
- Write tools can persist unwanted content if an untrusted client is connected.
- Host-header checks are helpful but are not authentication.
- Bearer tokens grant access to MCP tools; keep them out of logs, shell history, screenshots, and Git.

## Safe Configuration Checklist

- Keep `HOST=127.0.0.1` for local use.
- Point `AI_MEMORY_DIR` at a dedicated memory directory, not an entire private vault.
- Keep `MCP_AUTH_REQUIRED=true` for normal use.
- Set `MCP_READ_TOKEN` and `MCP_WRITE_TOKEN` to distinct long random values.
- Keep `AI_MEMORY_WRITE_ENABLED=false` by default.
- Enable writes only when a trusted client needs write tools.
- Use `examples/sample-vault/` for demos, screenshots, tests, and GitHub examples.
- Keep `.env` out of Git.
- Do not commit real Obsidian notes or private memory.
- Do not commit tokens, tunnel URLs, logs, or local config files.
- Keep public tunnels disabled unless protected by authentication.
- If tunneling is required, enforce authentication before traffic reaches `/mcp`.
- Stop tunnels immediately after use.

## Public Tunnel Warning

Public tunneling requires `MCP_AUTH_REQUIRED=true` and long random bearer tokens. A random-looking tunnel URL is not a sufficient security boundary. Treat an unauthenticated tunnel as public internet exposure of your local MCP gateway.

For local development only, you may explicitly set `MCP_AUTH_REQUIRED=false` while bound to `127.0.0.1`. Do not combine public tunnels with disabled auth.
