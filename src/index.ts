import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { Request, Response } from "express";
import { z } from "zod";
import chalk from "chalk";
import { classifyLicense, auditDependencies, buildNotices, evaluatePolicy, fetchDep, type DepSpec, type AuditPolicy } from "./tools.js";

// ============================================================================
// Dev Logging Utilities
// ============================================================================

const isDev = process.env.NODE_ENV !== "production";

function timestamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function formatLatency(ms: number): string {
  if (ms < 100) return chalk.green(`${ms}ms`);
  if (ms < 500) return chalk.yellow(`${ms}ms`);
  return chalk.red(`${ms}ms`);
}

function truncate(str: string, maxLen = 60): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}

function logRequest(method: string, params?: unknown): void {
  if (!isDev) return;

  const paramsStr = params ? chalk.gray(` ${truncate(JSON.stringify(params))}`) : "";
  console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.cyan("→")} ${method}${paramsStr}`);
}

function logResponse(method: string, result: unknown, latencyMs: number): void {
  if (!isDev) return;

  const latency = formatLatency(latencyMs);

  // For tool calls, show the result
  if (method === "tools/call" && result) {
    const resultStr = typeof result === "string" ? result : JSON.stringify(result);
    console.log(
      `${chalk.gray(`[${timestamp()}]`)} ${chalk.green("←")} ${truncate(resultStr)} ${chalk.gray(`(${latency})`)}`
    );
  } else {
    console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.green("✓")} ${method} ${chalk.gray(`(${latency})`)}`);
  }
}

function logError(method: string, error: unknown, latencyMs: number): void {
  const latency = formatLatency(latencyMs);

  let errorMsg: string;
  if (error instanceof Error) {
    errorMsg = error.message;
  } else if (typeof error === "object" && error !== null) {
    // JSON-RPC error object has { code, message, data? }
    const rpcError = error as { message?: string; code?: number };
    errorMsg = rpcError.message || `Error ${rpcError.code || "unknown"}`;
  } else {
    errorMsg = String(error);
  }

  console.log(
    `${chalk.gray(`[${timestamp()}]`)} ${chalk.red("✖")} ${method} ${chalk.red(truncate(errorMsg))} ${chalk.gray(`(${latency})`)}`
  );
}

// ============================================================================
// MCP Server Setup
// ============================================================================


// ---------------------------------------------------------------------------
// Tool helpers
// ---------------------------------------------------------------------------

function classify(id: string) {
  // classifyLicense is exported from ./tools.js
  return { ...classifyLicense(id) };
}

function toResult(value: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

function parseDeps(raw: string): DepSpec[] {
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("dependencies must be a JSON array");
  return parsed.map((d: { name?: string; version?: string }) => {
    if (!d?.name || typeof d.name !== "string") throw new Error('each dependency needs a string "name"');
    return { name: d.name, version: d.version };
  });
}

// Build a FRESH MCP server per request.
//
// In stateless streamable-HTTP mode the MCP SDK allows a Server to be connected
// to exactly ONE transport. Reusing a single module-scope instance throws
// "Already connected to a transport" on the second connection — and Cloud Run
// opens several (startup probe + real requests). So always create a new server
// (and a new transport) inside the request handler below.
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "license-audit",
    version: "1.0.0",
  });

  server.registerTool(
    "license_lookup",
    {
      title: "License Lookup",
      description:
        "Look up the license of an npm, pypi, go, maven, cargo or nuget package version: SPDX id, category (permissive / weak / strong copyleft / network copyleft), obligations you must satisfy, known advisories and deprecation status. Powered by the keyless deps.dev API.",
      inputSchema: {
        ecosystem: z.string().describe("npm | pypi | go | maven | cargo | nuget (aliases like python/javascript accepted)"),
        name: z.string().describe("Package name, e.g. lodash or requests"),
        version: z.string().describe("Version, e.g. 4.17.21"),
      },
    },
    async ({ ecosystem, name, version }) => {
      const info = await fetchDep(ecosystem, name, version);
      return toResult({ ...info, classification: info.licenses[0] ? classify(info.licenses[0]) : { category: "unknown", commercial_ok: false, obligations: [] } });
    }
  );

  server.registerTool(
    "audit_dependencies",
    {
      title: "License Audit",
      description:
        "Audit a dependency list: per-package license, category, obligations, known advisories, deprecation, plus risk summary (strong/network copyleft, non-commercial, unknown-license packages). Resolve latest version by omitting it.",
      inputSchema: {
        ecosystem: z.string().describe("npm | pypi | go | maven | cargo | nuget"),
        dependencies: z.string().describe('JSON array of {"name": "...", "version": "..."} objects (version optional)'),
        project: z.string().describe("Your project name, for the report"),
      },
    },
    async ({ ecosystem, dependencies, project }) => {
      const deps = parseDeps(dependencies);
      const report = await auditDependencies(ecosystem, deps);
      return toResult({ project: project || "unnamed project", ...report });
    }
  );

  server.registerTool(
    "check_policy",
    {
      title: "Policy Check",
      description:
        "Check audited dependencies against a compliance policy: deny/allow license lists, block strong/network copyleft, block non-commercial licenses. Returns pass/fail with exact violations.",
      inputSchema: {
        ecosystem: z.string().describe("npm | pypi | go | maven | cargo | nuget"),
        dependencies: z.string().describe('JSON array of {"name": "...", "version": "..."} objects'),
        policy: z.string().describe(
          'JSON policy: {"deny": ["GPL-3.0-only"], "allow": ["MIT","Apache-2.0"], "block_strong_copyleft": true, "block_non_commercial": true}'
        ),
      },
    },
    async ({ ecosystem, dependencies, policy }) => {
      const deps = parseDeps(dependencies);
      const policyObj = JSON.parse(policy) as AuditPolicy;
      const report = await auditDependencies(ecosystem, deps);
      const verdict = evaluatePolicy(report.dependencies, policyObj);
      return toResult({ ecosystem: report.ecosystem, ...verdict, license_by_package: report.dependencies.map((d) => ({ name: d.name, version: d.version, license: d.license, category: d.category })) });
    }
  );

  server.registerTool(
    "generate_notices",
    {
      title: "Generate NOTICE",
      description:
        "Generate a third-party notices / attribution markdown file (grouped by license, ready for THIRDPARTYNOTICES.md or your About screen) from a dependency list.",
      inputSchema: {
        ecosystem: z.string().describe("npm | pypi | go | maven | cargo | nuget"),
        dependencies: z.string().describe('JSON array of {"name": "...", "version": "..."} objects'),
        project: z.string().describe("Your project name, used as the file title"),
      },
    },
    async ({ ecosystem, dependencies, project }) => {
      const deps = parseDeps(dependencies);
      const report = await auditDependencies(ecosystem, deps);
      return toResult({
        ecosystem: report.ecosystem,
        project: project || "this product",
        markdown: buildNotices(report.dependencies, project || "this product"),
      });
    }
  );

  return server;
}

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();
app.use(express.json());

// Health check endpoint (required for Cloud Run)
app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "healthy" });
});

// MCP endpoint with dev logging
app.post("/mcp", async (req: Request, res: Response) => {
  const startTime = Date.now();
  const body = req.body;

  // Extract method and params from JSON-RPC request
  const method = body?.method || "unknown";
  const params = body?.params;

  // Log incoming request
  if (method === "tools/call") {
    const toolName = params?.name || "unknown";
    const toolArgs = params?.arguments;
    logRequest(`tools/call ${chalk.bold(toolName)}`, toolArgs);
  } else if (method !== "notifications/initialized") {
    logRequest(method, params);
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  // Capture response body for logging
  let responseBody = "";
  const originalWrite = res.write.bind(res) as typeof res.write;
  const originalEnd = res.end.bind(res) as typeof res.end;

  res.write = function (chunk: unknown, encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void), callback?: (error: Error | null | undefined) => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }
    return originalWrite(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.end = function (chunk?: unknown, encodingOrCallback?: BufferEncoding | (() => void), callback?: () => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }

    // Log response
    if (method !== "notifications/initialized") {
      const latency = Date.now() - startTime;

      try {
        const rpcResponse = JSON.parse(responseBody) as { result?: unknown; error?: unknown };

        if (rpcResponse?.error) {
          logError(method, rpcResponse.error, latency);
        } else if (method === "tools/call") {
          const content = (rpcResponse?.result as { content?: Array<{ text?: string }> })?.content;
          const resultText = content?.[0]?.text;
          logResponse(method, resultText, latency);
        } else {
          logResponse(method, null, latency);
        }
      } catch {
        logResponse(method, null, latency);
      }
    }

    return originalEnd(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.on("close", () => {
    transport.close();
  });

  // Fresh server instance per request (see createMcpServer above) — required for
  // stateless streamable-HTTP so a second connection never reuses a transport.
  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// JSON error handler (Express defaults to HTML errors)
app.use((_err: unknown, _req: Request, res: Response, _next: Function) => {
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================================
// Start Server
// ============================================================================

const port = parseInt(process.env.PORT || "8080");
const httpServer = app.listen(port, () => {
  console.log();
  console.log(chalk.bold("MCP Server running on"), chalk.cyan(`http://localhost:${port}`));
  console.log(`  ${chalk.gray("Health:")} http://localhost:${port}/health`);
  console.log(`  ${chalk.gray("MCP:")}    http://localhost:${port}/mcp`);

  if (isDev) {
    console.log();
    console.log(chalk.gray("─".repeat(50)));
    console.log();
  }
});

// Graceful shutdown for Cloud Run (SIGTERM before kill)
process.on("SIGTERM", () => {
  console.log("Received SIGTERM, shutting down...");
  httpServer.close(() => {
    process.exit(0);
  });
});
