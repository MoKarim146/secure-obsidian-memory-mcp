# Container Hardening

The production image is designed to run compiled JavaScript from `dist/`, not `tsx watch`.

## Defaults

- `NODE_ENV=production`.
- `MCP_AUTH_REQUIRED=true`.
- `AI_MEMORY_WRITE_ENABLED=false`.
- `LOG_CONTENT=false`.
- `MASK_EMAILS=true`.
- `MASK_PHONE_NUMBERS=true`.
- Non-root runtime user `10001:10001`.
- Memory directory mounted at `/memory`.
- Healthcheck calls `/health` every 30 seconds.
- No file watchers, polling loops, background indexing, or startup full-vault scan are added.
- Search runs only when an MCP client calls `search_memory`.

## Compose Hardening

`docker-compose.yml` keeps the container local by publishing the port on `127.0.0.1` only. It also enables:

- `read_only: true`.
- Writable `/tmp` via tmpfs.
- Named writable volume for `/memory`.
- `cap_drop: [ALL]`.
- `no-new-privileges:true`.
- `init: true`.
- CPU limit of `0.50`.
- Memory limit of `512m`.

## Memory Data

Do not bake real vault data into the image. Mount a dedicated memory directory or Docker volume at `/memory`.

For public demos, use fake data only. For production, use a dedicated memory directory rather than an entire private Obsidian vault.

## Authentication

Containers require bearer authentication by default. Set `MCP_READ_TOKEN` and `MCP_WRITE_TOKEN` to distinct long random values at deploy time. Keep `AI_MEMORY_WRITE_ENABLED=false` unless a trusted write-capable client needs write tools.

Do not publish a tunnel or container port without auth. A public tunnel with `MCP_AUTH_REQUIRED=false` is unsafe.

## Audit Logs

Containers emit audit logs as JSON lines on stdout. Container runtimes may collect stdout automatically, so treat collected logs as sensitive operational data even though bearer tokens, note bodies, write bodies, and full search queries are excluded.

Audit events help detect unsafe public tunnel exposure by showing missing or invalid auth attempts, denied tool calls, and write-disabled blocks. Keep collected logs out of images and Git.

## Large Vaults

Search is bounded in application code and runs on demand, but large vaults can still cost CPU when users search broad terms. Keep `AI_MEMORY_DIR` narrow and use bounded search limits before adding background indexing.
