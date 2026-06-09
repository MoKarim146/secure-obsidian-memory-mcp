import type { Request } from "express";
import type { AuthenticatedRequest, AuthFailure, SecurityConfig, ToolPermission } from "./auth.js";

export type AuditPermission = ToolPermission | "none" | "disabled";

export interface AuditConfig {
  logContent: boolean;
  maskEmails: boolean;
  maskPhoneNumbers: boolean;
  maxSnippetChars: number;
}

export interface AuditLogger {
  log(event: AuditEvent): void;
}

export interface RequestAuditContext {
  clientIp?: string;
  host?: string;
  origin?: string;
  sessionId?: string;
  requestId?: string | number;
}

export interface ToolAuditDetails {
  tool?: string;
  relativePath?: string;
  contentLength?: number;
  queryLength?: number;
  resultCount?: number;
  requestId?: string | number;
  sessionId?: string;
}

export interface AuditEvent extends RequestAuditContext, ToolAuditDetails {
  timestamp?: string;
  event:
    | "server_startup"
    | "auth_failure"
    | "tool_call"
    | "tool_denied"
    | "session_request_denied";
  allowed: boolean;
  permission: AuditPermission;
  reason: string;
  authRequired?: boolean;
  writesEnabled?: boolean;
  logContent?: boolean;
}

const DEFAULT_MAX_SNIPPET_CHARS = 220;
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const PHONE_PATTERN = /(?<!\w)(?:\+?\d[\d().\-\s]{6,}\d)(?!\w)/g;

export function getAuditConfig(env: NodeJS.ProcessEnv = process.env): AuditConfig {
  return {
    logContent: parseBooleanEnv("LOG_CONTENT", env.LOG_CONTENT, false),
    maskEmails: parseBooleanEnv("MASK_EMAILS", env.MASK_EMAILS, true),
    maskPhoneNumbers: parseBooleanEnv("MASK_PHONE_NUMBERS", env.MASK_PHONE_NUMBERS, true),
    maxSnippetChars: parsePositiveIntegerEnv("MAX_SNIPPET_CHARS", env.MAX_SNIPPET_CHARS, DEFAULT_MAX_SNIPPET_CHARS),
  };
}

export function createConsoleAuditLogger(config: AuditConfig = getAuditConfig()): AuditLogger {
  return {
    log(event) {
      const sanitized = sanitizeAuditEvent(
        {
          timestamp: new Date().toISOString(),
          ...event,
        },
        config,
      );

      console.log(JSON.stringify(sanitized));
    },
  };
}

export function createNoopAuditLogger(): AuditLogger {
  return {
    log() {
      return;
    },
  };
}

export function auditStartup(logger: AuditLogger, security: SecurityConfig, config: AuditConfig): void {
  logger.log({
    event: "server_startup",
    allowed: true,
    permission: security.memoryWriteEnabled ? "write" : "disabled",
    reason: "security_mode",
    authRequired: security.authRequired,
    writesEnabled: security.memoryWriteEnabled,
    logContent: config.logContent,
  });
}

export function getRequestAuditContext(req: Request): RequestAuditContext {
  return {
    clientIp: safeHeaderValue(req.ip || req.socket.remoteAddress),
    host: safeHeaderValue(req.headers.host),
    origin: safeHeaderValue(req.headers.origin),
    sessionId: safeHeaderValue(getHeader(req, "mcp-session-id")),
    requestId: getJsonRpcId(req.body),
  };
}

export function auditAuthFailure(logger: AuditLogger, failure: AuthFailure, context: RequestAuditContext): void {
  logger.log({
    event: "auth_failure",
    allowed: false,
    permission: "none",
    reason: failure.reason,
    ...context,
  });
}

export function auditToolDenied(
  logger: AuditLogger,
  failure: AuthFailure,
  details: ToolAuditDetails,
  context: RequestAuditContext,
): void {
  logger.log({
    event: "tool_denied",
    allowed: false,
    permission: failure.permission ?? "none",
    reason: failure.reason,
    ...details,
    ...context,
  });
}

export function auditSessionRequestDenied(logger: AuditLogger, failure: AuthFailure, context: RequestAuditContext): void {
  logger.log({
    event: "session_request_denied",
    allowed: false,
    permission: "none",
    reason: failure.reason,
    ...context,
  });
}

export function auditToolAllowed(
  logger: AuditLogger,
  auth: AuthenticatedRequest,
  permission: ToolPermission,
  details: ToolAuditDetails,
): void {
  logger.log({
    event: "tool_call",
    allowed: true,
    permission,
    reason: auth.access === "write" ? "authorized_write_token" : "authorized_read_token",
    ...details,
  });
}

export function getToolAuditDetails(body: unknown): ToolAuditDetails {
  const message = Array.isArray(body) ? body[0] : body;
  if (!isRecord(message) || message.method !== "tools/call") {
    return {
      requestId: getJsonRpcId(message),
    };
  }

  const params = isRecord(message.params) ? message.params : undefined;
  const tool = typeof params?.name === "string" ? params.name : undefined;
  const args = isRecord(params?.arguments) ? params.arguments : {};

  return {
    tool,
    relativePath: getRelativePathForTool(tool, args),
    contentLength: getContentLengthForTool(tool, args),
    queryLength: typeof args.query === "string" ? Buffer.byteLength(args.query, "utf8") : undefined,
    requestId: getJsonRpcId(message),
  };
}

export function getRelativePathForTool(tool: string | undefined, args: Record<string, unknown>): string | undefined {
  switch (tool) {
    case "read_note":
      return typeof args.path === "string" ? args.path : undefined;
    case "read_handoff_summary":
    case "update_handoff_summary":
      return "04_MODEL_HANDOFF.md";
    case "add_decision":
      return "02_DECISIONS.md";
    case "add_open_task":
      return "03_OPEN_TASKS.md";
    case "append_session_note":
      return "Sessions/<generated-session-note>";
    default:
      return undefined;
  }
}

export function getContentLengthForTool(tool: string | undefined, args: Record<string, unknown>): number | undefined {
  switch (tool) {
    case "update_handoff_summary":
    case "append_session_note":
      return typeof args.content === "string" ? Buffer.byteLength(args.content, "utf8") : undefined;
    case "add_decision":
      return byteLengthSum(args.decision, args.reason);
    case "add_open_task":
      return byteLengthSum(args.task, args.priority, args.project);
    default:
      return undefined;
  }
}

function sanitizeAuditEvent(event: AuditEvent, config: AuditConfig): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(event)) {
    if (value === undefined) {
      continue;
    }

    if (typeof value === "string") {
      sanitized[key] = sanitizeString(value, config);
      continue;
    }

    sanitized[key] = value;
  }

  return sanitized;
}

function sanitizeString(value: string, config: AuditConfig): string {
  let sanitized = value;

  if (config.maskEmails) {
    sanitized = sanitized.replace(EMAIL_PATTERN, "[email]");
  }

  if (config.maskPhoneNumbers) {
    sanitized = sanitized.replace(PHONE_PATTERN, "[phone]");
  }

  if (sanitized.length > config.maxSnippetChars) {
    return `${sanitized.slice(0, config.maxSnippetChars)}...`;
  }

  return sanitized;
}

function byteLengthSum(...values: unknown[]): number | undefined {
  const strings = values.filter((value): value is string => typeof value === "string");
  if (strings.length === 0) {
    return undefined;
  }

  return strings.reduce((total, value) => total + Buffer.byteLength(value, "utf8"), 0);
}

function getJsonRpcId(body: unknown): string | number | undefined {
  const message = Array.isArray(body) ? body[0] : body;
  if (!isRecord(message)) {
    return undefined;
  }

  return typeof message.id === "string" || typeof message.id === "number" ? message.id : undefined;
}

function getHeader(req: Request, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  return safeHeaderValue(value);
}

function safeHeaderValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
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

function parsePositiveIntegerEnv(name: string, value: string | undefined, defaultValue: number): number {
  if (value === undefined || value.trim() === "") {
    return defaultValue;
  }

  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }

  return parsed;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
