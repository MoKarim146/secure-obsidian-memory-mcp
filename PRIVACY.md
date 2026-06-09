# Privacy Policy

## Data The Server Can Access

The server can access markdown files under the configured `AI_MEMORY_DIR`. Current tools can:

- Read the five main memory files.
- Read a specific relative `.md` file.
- Search markdown files and return matching snippets.
- Replace `04_MODEL_HANDOFF.md`.
- Append session notes under `Sessions/`.
- Append decisions and open tasks to controlled memory files.

The server should not be pointed at an entire private Obsidian vault unless you intentionally want connected MCP clients to access those markdown files.

## Data Logged

The server emits privacy-preserving audit logs as JSON lines on stdout. Audit events include security metadata such as:

- Startup security mode summary.
- Missing or invalid auth attempts.
- Denied read/write tool calls.
- Write attempts blocked because `AI_MEMORY_WRITE_ENABLED=false`.
- Successful tool calls.
- Tool name, permission level, allowed/denied status, and reason code.
- Safe client IP, host, origin, request ID, or session ID when already available.
- Relative note path when applicable.
- Search query length and result count, not the query text.
- Write content length, not the body.

Audit logs and operational error logs should not include note bodies or secrets.

## Data Never Logged

The audit logger must never log:

- Bearer tokens or `Authorization` headers.
- Note bodies, write bodies, or full private file contents.
- Full search queries.
- `.env` values.
- Private vault root paths.

`LOG_CONTENT=false`, `MASK_EMAILS=true`, and `MASK_PHONE_NUMBERS=true` are the privacy-preserving defaults. Even if `LOG_CONTENT=true`, audit logs still do not include bearer tokens, note bodies, write bodies, or full search queries. `MAX_SNIPPET_CHARS` bounds logged metadata strings.

Logs go to stdout by default. Redirect stdout with your shell, process manager, Docker, or hosting environment if you need to collect logs elsewhere. Do not commit collected logs.

## Data That Must Never Be Committed

Never commit:

- Real Obsidian notes or private memory.
- `.env` files.
- Secrets, API keys, bearer tokens, or MCP auth tokens.
- Public tunnel URLs.
- Logs containing user prompts, note content, or operational details.
- Emails, phone numbers, addresses, or other personal identifiers.
- Private filesystem paths.

## GitHub Sample-Vault-Only Policy

Public repository data must use fake demo notes only. The only memory vault content intended for GitHub is under:

```text
examples/sample-vault/
```

All files there must be fictional, non-sensitive, and safe to show in screenshots, tests, documentation, and demos.
