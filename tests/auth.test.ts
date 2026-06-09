import type { Server } from "node:http";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getSecurityConfig, type SecurityConfig } from "../src/auth.js";
import { createHttpApp } from "../src/httpServer.js";
import type { MemoryConfig } from "../src/memory.js";

const READ_TOKEN = "read-token-for-auth-tests-0000000000000001";
const WRITE_TOKEN = "write-token-for-auth-tests-0000000000000001";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(closeServer));
  vi.restoreAllMocks();
});

describe("MCP bearer authentication and tool permissions", () => {
  it("defaults to auth required, write disabled, and fails safely when tokens are missing", () => {
    expect(() => getSecurityConfig({})).toThrow("MCP_READ_TOKEN must be set");
    expect(() =>
      getSecurityConfig({
        MCP_AUTH_REQUIRED: "true",
        MCP_READ_TOKEN: READ_TOKEN,
      }),
    ).toThrow("MCP_WRITE_TOKEN must be set");

    expect(
      getSecurityConfig({
        MCP_AUTH_REQUIRED: "false",
      }),
    ).toMatchObject({
      authRequired: false,
      memoryWriteEnabled: false,
    });
  });

  it("rejects missing auth when auth is required", async () => {
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));

    const response = await postJson(url, undefined, initializeRequest());

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        message: "Unauthorized",
      },
    });
  });

  it("rejects invalid bearer tokens without printing token values", async () => {
    const invalidToken = "invalid-token-that-must-not-appear";
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));

    const response = await postJson(url, `Bearer ${invalidToken}`, initializeRequest());
    const body = await response.text();
    const logged = errorSpy.mock.calls.flat().join("\n");

    expect(response.status).toBe(401);
    expect(body).toContain("Unauthorized");
    expect(body).not.toContain(invalidToken);
    expect(logged).not.toContain(invalidToken);
  });

  it("allows the read token to call read tools", async () => {
    const { url } = await startTestServer(security({ memoryWriteEnabled: false }));
    const client = await connectClient(url, READ_TOKEN);

    try {
      const result = await client.callTool({
        name: "read_handoff_summary",
        arguments: {},
      });

      expect(JSON.stringify(result)).toContain("04_MODEL_HANDOFF.md");
    } finally {
      await client.close();
    }
  });

  it("blocks the read token from write tools", async () => {
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));

    const response = await postJson(url, `Bearer ${READ_TOKEN}`, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "add_open_task",
        arguments: {
          task: "fake task",
          priority: "low",
        },
      },
    });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      error: {
        message: "Forbidden",
      },
    });
  });

  it("allows the write token to call write tools when writes are enabled", async () => {
    const { config, url } = await startTestServer(security({ memoryWriteEnabled: true }));
    const client = await connectClient(url, WRITE_TOKEN);

    try {
      await client.callTool({
        name: "add_open_task",
        arguments: {
          task: "Verify fake auth test task",
          priority: "low",
          project: "tests",
        },
      });
    } finally {
      await client.close();
    }

    await expect(readFile(path.join(config.rootDir, "03_OPEN_TASKS.md"), "utf8")).resolves.toContain(
      "Verify fake auth test task",
    );
  });

  it("blocks write tools when writes are disabled, even with the write token", async () => {
    const { url } = await startTestServer(security({ memoryWriteEnabled: false }));
    const client = await connectClient(url, WRITE_TOKEN);

    try {
      await expect(
        client.callTool({
          name: "add_decision",
          arguments: {
            decision: "Fake disabled write",
            reason: "Write gate should block it.",
          },
        }),
      ).rejects.toThrow(/Write tools are disabled|Forbidden|403/);
    } finally {
      await client.close();
    }
  });
});

function security(overrides: Partial<SecurityConfig> = {}): SecurityConfig {
  return {
    authRequired: true,
    readToken: READ_TOKEN,
    writeToken: WRITE_TOKEN,
    memoryWriteEnabled: false,
    ...overrides,
  };
}

async function startTestServer(securityConfig: SecurityConfig): Promise<{ config: MemoryConfig; url: string }> {
  const config = {
    rootDir: await mkdtemp(path.join(os.tmpdir(), "obsidian-memory-mcp-auth-")),
  };
  const app = createHttpApp({
    config,
    security: securityConfig,
    host: "127.0.0.1",
    port: 0,
  });

  const server = await new Promise<Server>((resolve, reject) => {
    const activeServer = app.listen(0, "127.0.0.1", () => {
      resolve(activeServer);
    });
    activeServer.once("error", reject);
  });
  servers.push(server);

  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Test server did not bind to a TCP port");
  }

  return {
    config,
    url: `http://127.0.0.1:${address.port}/mcp`,
  };
}

async function connectClient(url: string, token: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  });
  const client = new Client({
    name: "auth-test-client",
    version: "0.0.0",
  });

  await client.connect(transport);
  return client;
}

async function postJson(url: string, authorization: string | undefined, body: unknown): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };

  if (authorization) {
    headers.Authorization = authorization;
  }

  return fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function initializeRequest() {
  return {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: {
        name: "auth-test-client",
        version: "0.0.0",
      },
    },
  };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}
