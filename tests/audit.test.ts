import type { Server } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { auditStartup, createConsoleAuditLogger, type AuditEvent, type AuditLogger } from "../src/audit.js";
import type { SecurityConfig } from "../src/auth.js";
import { createHttpApp } from "../src/httpServer.js";
import { ensureMemoryLayout, type MemoryConfig } from "../src/memory.js";

const READ_CREDENTIAL = "read-credential-for-audit-tests";
const WRITE_CREDENTIAL = "write-credential-for-audit-tests";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map(closeServer));
  vi.restoreAllMocks();
});

describe("privacy-preserving audit logging", () => {
  it("logs startup security mode without secrets", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const audit = createConsoleAuditLogger(auditConfig({ logContent: true }));

    auditStartup(audit, security({ memoryWriteEnabled: false }), auditConfig({ logContent: true }));

    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"server_startup"');
    expect(logs).toContain('"authRequired":true');
    expect(logs).toContain('"writesEnabled":false');
    expect(logs).not.toContain(READ_CREDENTIAL);
    expect(logs).not.toContain(WRITE_CREDENTIAL);
  });

  it("logs auth failures without bearer token leakage", async () => {
    const invalidCredential = "invalid-audit-credential-must-not-leak";
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));

    const response = await postJson(url, `Bearer ${invalidCredential}`, initializeRequest());

    expect(response.status).toBe(401);
    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"auth_failure"');
    expect(logs).toContain('"reason":"missing_or_invalid_auth"');
    expect(logs).not.toContain(invalidCredential);
    expect(logs).not.toContain("Bearer");
  });

  it("logs successful reads without note body leakage", async () => {
    const secretNoteBody = "Project note body with private details and sensitive identifiers";
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { config, url } = await startTestServer(security({ memoryWriteEnabled: false }));
    await ensureMemoryLayout(config);
    await writeFile(path.join(config.rootDir, "private.md"), secretNoteBody, "utf8");
    const client = await connectClient(url, READ_CREDENTIAL);

    try {
      await client.callTool({
        name: "read_note",
        arguments: {
          path: "private.md",
        },
      });
    } finally {
      await client.close();
    }

    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"tool_call"');
    expect(logs).toContain('"tool":"read_note"');
    expect(logs).toContain('"relativePath":"private.md"');
    expect(logs).not.toContain("Project note body");
    expect(logs).not.toContain("sensitive identifiers");
  });

  it("logs successful writes with content length only", async () => {
    const writeBody = "Write body with private content and sensitive identifiers";
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));
    const client = await connectClient(url, WRITE_CREDENTIAL);

    try {
      await client.callTool({
        name: "append_session_note",
        arguments: {
          model_name: "Audit Test",
          title: "Safe write audit",
          content: writeBody,
        },
      });
    } finally {
      await client.close();
    }

    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"tool_call"');
    expect(logs).toContain('"tool":"append_session_note"');
    expect(logs).toContain('"contentLength":');
    expect(logs).not.toContain("Write body with private content");
    expect(logs).not.toContain("sensitive identifiers");
  });

  it("logs denied write attempts with a safe reason", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { url } = await startTestServer(security({ memoryWriteEnabled: true }));

    const response = await postJson(url, `Bearer ${READ_CREDENTIAL}`, toolCallRequest("add_open_task", {
      task: "private denied write body",
      priority: "low",
    }));

    expect(response.status).toBe(403);
    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"tool_denied"');
    expect(logs).toContain('"tool":"add_open_task"');
    expect(logs).toContain('"reason":"insufficient_permission"');
    expect(logs).toContain('"permission":"write"');
    expect(logs).not.toContain("private denied write body");
  });

  it("logs write-disabled attempts safely", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { url } = await startTestServer(security({ memoryWriteEnabled: false }));

    const response = await postJson(url, `Bearer ${WRITE_CREDENTIAL}`, toolCallRequest("add_decision", {
      decision: "private disabled decision",
      reason: "private disabled reason",
    }));

    expect(response.status).toBe(403);
    const logs = joinedLogs(logSpy);
    expect(logs).toContain('"event":"tool_denied"');
    expect(logs).toContain('"tool":"add_decision"');
    expect(logs).toContain('"reason":"writes_disabled"');
    expect(logs).toContain('"permission":"disabled"');
    expect(logs).not.toContain("private disabled decision");
    expect(logs).not.toContain("private disabled reason");
  });

  it("logs search query length and result count, not query text", async () => {
    const privateQuery = "secret audit query phrase";
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const { config, url } = await startTestServer(security({ memoryWriteEnabled: false }));
    await ensureMemoryLayout(config);
    await writeFile(path.join(config.rootDir, "search.md"), "secret audit query phrase\n", "utf8");
    const client = await connectClient(url, READ_CREDENTIAL);

    try {
      await client.callTool({
        name: "search_memory",
        arguments: {
          query: privateQuery,
        },
      });
    } finally {
      await client.close();
    }

    const events = auditEvents(logSpy);
    const searchEvent = events.find((event) => event.tool === "search_memory");
    expect(searchEvent).toMatchObject({
      event: "tool_call",
      tool: "search_memory",
      queryLength: Buffer.byteLength(privateQuery, "utf8"),
      resultCount: 1,
    });
    expect(joinedLogs(logSpy)).not.toContain(privateQuery);
  });
});

function security(overrides: Partial<SecurityConfig> = {}): SecurityConfig {
  return {
    authRequired: true,
    readToken: READ_CREDENTIAL,
    writeToken: WRITE_CREDENTIAL,
    memoryWriteEnabled: false,
    ...overrides,
  };
}

function auditConfig(overrides = {}) {
  return {
    logContent: false,
    maskEmails: true,
    maskPhoneNumbers: true,
    maxSnippetChars: 220,
    ...overrides,
  };
}

async function startTestServer(
  securityConfig: SecurityConfig,
  audit: AuditLogger = createConsoleAuditLogger(auditConfig({ logContent: true })),
): Promise<{ config: MemoryConfig; url: string }> {
  const config = {
    rootDir: await mkdtemp(path.join(os.tmpdir(), "obsidian-memory-mcp-audit-")),
  };
  const app = createHttpApp({
    config,
    security: securityConfig,
    audit,
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
    name: "audit-test-client",
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
        name: "audit-test-client",
        version: "0.0.0",
      },
    },
  };
}

function toolCallRequest(name: string, args: Record<string, unknown>) {
  return {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name,
      arguments: args,
    },
  };
}

function joinedLogs(logSpy: ReturnType<typeof vi.spyOn>): string {
  return logSpy.mock.calls.flat().join("\n");
}

function auditEvents(logSpy: ReturnType<typeof vi.spyOn>): AuditEvent[] {
  return logSpy.mock.calls.flat().map((line) => JSON.parse(String(line)) as AuditEvent);
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
