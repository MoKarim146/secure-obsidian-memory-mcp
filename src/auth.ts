import { timingSafeEqual } from "node:crypto";

export type AccessLevel = "read" | "write";
export type ToolPermission = "read" | "write";

export interface SecurityConfig {
  authRequired: boolean;
  readToken?: string;
  writeToken?: string;
  memoryWriteEnabled: boolean;
}

export interface AuthenticatedRequest {
  access: AccessLevel;
}

export interface AuthFailure {
  status: 401 | 403;
  code: number;
  message: string;
}

export const READ_TOOLS = [
  "read_main_context",
  "read_handoff_summary",
  "search_memory",
  "read_note",
] as const;

export const WRITE_TOOLS = [
  "update_handoff_summary",
  "append_session_note",
  "add_decision",
  "add_open_task",
] as const;

const READ_TOOL_SET = new Set<string>(READ_TOOLS);
const WRITE_TOOL_SET = new Set<string>(WRITE_TOOLS);

export function getSecurityConfig(env: NodeJS.ProcessEnv = process.env): SecurityConfig {
  const authRequired = parseBooleanEnv("MCP_AUTH_REQUIRED", env.MCP_AUTH_REQUIRED, true);
  const memoryWriteEnabled = parseBooleanEnv("AI_MEMORY_WRITE_ENABLED", env.AI_MEMORY_WRITE_ENABLED, false);
  const readToken = normalizeToken(env.MCP_READ_TOKEN);
  const writeToken = normalizeToken(env.MCP_WRITE_TOKEN);

  if (authRequired) {
    if (!readToken) {
      throw new Error("MCP_READ_TOKEN must be set when MCP_AUTH_REQUIRED=true");
    }

    if (!writeToken) {
      throw new Error("MCP_WRITE_TOKEN must be set when MCP_AUTH_REQUIRED=true");
    }

    if (readToken === writeToken) {
      throw new Error("MCP_READ_TOKEN and MCP_WRITE_TOKEN must be distinct");
    }
  }

  return {
    authRequired,
    readToken,
    writeToken,
    memoryWriteEnabled,
  };
}

export function authenticateBearerToken(
  authorizationHeader: string | string[] | undefined,
  config: SecurityConfig,
): AuthenticatedRequest | AuthFailure {
  if (!config.authRequired) {
    return { access: "write" };
  }

  const authorization = Array.isArray(authorizationHeader) ? authorizationHeader[0] : authorizationHeader;
  if (!authorization) {
    return unauthorized();
  }

  const token = parseBearerToken(authorization);
  if (!token) {
    return unauthorized();
  }

  if (config.readToken && tokenEquals(token, config.readToken)) {
    return { access: "read" };
  }

  if (config.writeToken && tokenEquals(token, config.writeToken)) {
    return { access: "write" };
  }

  return unauthorized();
}

export function authorizeMcpRequestBody(
  body: unknown,
  auth: AuthenticatedRequest,
  config: SecurityConfig,
): AuthFailure | undefined {
  const messages = Array.isArray(body) ? body : [body];

  for (const message of messages) {
    const toolName = getToolCallName(message);
    if (toolName === undefined) {
      continue;
    }

    const permission = getToolPermission(toolName);
    if (!permission) {
      return forbidden();
    }

    if (permission === "write" && !config.memoryWriteEnabled) {
      return forbidden("Write tools are disabled");
    }

    if (permission === "write" && auth.access !== "write") {
      return forbidden();
    }
  }

  return undefined;
}

export function getToolPermission(toolName: string): ToolPermission | undefined {
  if (READ_TOOL_SET.has(toolName)) {
    return "read";
  }

  if (WRITE_TOOL_SET.has(toolName)) {
    return "write";
  }

  return undefined;
}

export function assertWriteToolsEnabled(config: SecurityConfig): void {
  if (!config.memoryWriteEnabled) {
    throw new Error("Write tools are disabled");
  }
}

function getToolCallName(message: unknown): string | undefined {
  if (!isRecord(message) || message.method !== "tools/call") {
    return undefined;
  }

  const params = message.params;
  if (!isRecord(params) || typeof params.name !== "string") {
    return "";
  }

  return params.name;
}

function parseBearerToken(authorization: string): string | undefined {
  const parts = authorization.trim().split(/\s+/);
  if (parts.length !== 2 || parts[0] !== "Bearer" || parts[1].length === 0) {
    return undefined;
  }

  return parts[1];
}

function tokenEquals(actual: string, expected: string): boolean {
  const actualBytes = Buffer.from(actual, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");

  if (actualBytes.length !== expectedBytes.length) {
    return false;
  }

  return timingSafeEqual(actualBytes, expectedBytes);
}

function normalizeToken(value: string | undefined): string | undefined {
  const token = value?.trim();
  return token ? token : undefined;
}

function parseBooleanEnv(name: string, value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined || value.trim() === "") {
    return defaultValue;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "true") {
    return true;
  }

  if (normalized === "false") {
    return false;
  }

  throw new Error(`${name} must be true or false`);
}

function unauthorized(): AuthFailure {
  return {
    status: 401,
    code: -32001,
    message: "Unauthorized",
  };
}

function forbidden(message = "Forbidden"): AuthFailure {
  return {
    status: 403,
    code: -32003,
    message,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
