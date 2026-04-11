#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getLatestDataDate,
} from "./db.js";
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "polish-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "pl_cyber_search_guidance",
    description:
      "Full-text search across CERT Polska / CSIRT NASK guidelines and technical reports. Covers cybersecurity guides, KSC (Ustawa o Krajowym Systemie Cyberbezpieczenstwa) implementation guidance, NIS2 transposition materials, and sector-specific recommendations. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query in Polish or English (e.g., 'cyberbezpieczenstwo', 'KSC wymagania', 'zarzadzanie podatnosciami', 'incident response')",
        },
        type: {
          type: "string",
          enum: ["technical_guideline", "sector_guide", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["CERT-PL", "KSC", "NIS2"],
          description: "Filter by guidance series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "pl_cyber_get_guidance",
    description:
      "Get a specific CERT Polska guidance document by reference (e.g., 'CERT-PL-2023-01', 'KSC-Przewodnik-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CERT Polska document reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "pl_cyber_search_advisories",
    description:
      "Search CERT Polska security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query in Polish or English (e.g., 'krytyczna podatnosc', 'ransomware', 'phishing kampania')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "pl_cyber_get_advisory",
    description: "Get a specific CERT Polska security advisory by reference (e.g., 'CERT-PL-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CERT Polska advisory reference" },
      },
      required: ["reference"],
    },
  },
  {
    name: "pl_cyber_list_frameworks",
    description:
      "List all CERT Polska frameworks and guidance series covered in this MCP, including the KSC national cybersecurity framework and NIS2 implementation materials.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "pl_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "pl_cyber_list_sources",
    description: "List the primary data sources indexed by this MCP server, including CERT Polska, cert.pl, and NASK.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "pl_cyber_check_data_freshness",
    description: "Check the freshness of the indexed data: when it was last updated and whether it is current.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["technical_guideline", "sector_guide", "standard", "recommendation"]).optional(),
  series: z.enum(["CERT-PL", "KSC", "NIS2"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- MCP server factory ------------------------------------------------------

function responseMeta() {
  return {
    disclaimer:
      "This data is provided for informational purposes only. Always verify against official CERT Polska publications at https://cert.pl/.",
    data_age: getLatestDataDate(),
    copyright: "CERT Polska / NASK",
    source_url: "https://cert.pl/",
  };
}

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: pkgVersion },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    function textContent(data: unknown) {
      const payload =
        data !== null && typeof data === "object"
          ? { ...(data as Record<string, unknown>), _meta: responseMeta() }
          : { data, _meta: responseMeta() };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
      };
    }

    function errorContent(
      message: string,
      errorType: "not_found" | "invalid_input" | "internal_error" = "internal_error",
    ) {
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { error: message, _error_type: errorType, _meta: responseMeta() },
              null,
              2,
            ),
          },
        ],
        isError: true as const,
      };
    }

    try {
      switch (name) {
        case "pl_cyber_search_guidance": {
          const parsed = SearchGuidanceArgs.parse(args);
          const results = searchGuidance({
            query: parsed.query,
            type: parsed.type,
            series: parsed.series,
            status: parsed.status,
            limit: parsed.limit,
          });
          const resultsWithCitation = results.map((r) => {
            const item = r as unknown as Record<string, unknown>;
            return {
              ...item,
              _citation: buildCitation(
                String(item.reference ?? ""),
                String(item.title ?? item.reference ?? ""),
                "pl_cyber_get_guidance",
                { reference: String(item.reference ?? "") },
              ),
            };
          });
          return textContent({ results: resultsWithCitation, count: resultsWithCitation.length });
        }

        case "pl_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return errorContent(`Guidance document not found: ${parsed.reference}`, "not_found");
          }
          const d = doc as unknown as Record<string, unknown>;
          return textContent({
            ...d,
            _citation: buildCitation(
              String(d.reference ?? parsed.reference),
              String(d.title ?? d.reference ?? parsed.reference),
              "pl_cyber_get_guidance",
              { reference: parsed.reference },
            ),
          });
        }

        case "pl_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          const resultsWithCitation = results.map((r) => {
            const item = r as unknown as Record<string, unknown>;
            return {
              ...item,
              _citation: buildCitation(
                String(item.reference ?? ""),
                String(item.title ?? item.reference ?? ""),
                "pl_cyber_get_advisory",
                { reference: String(item.reference ?? "") },
              ),
            };
          });
          return textContent({ results: resultsWithCitation, count: resultsWithCitation.length });
        }

        case "pl_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return errorContent(`Advisory not found: ${parsed.reference}`, "not_found");
          }
          const a = advisory as unknown as Record<string, unknown>;
          return textContent({
            ...a,
            _citation: buildCitation(
              String(a.reference ?? parsed.reference),
              String(a.title ?? a.reference ?? parsed.reference),
              "pl_cyber_get_advisory",
              { reference: parsed.reference },
            ),
          });
        }

        case "pl_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({ frameworks, count: frameworks.length });
        }

        case "pl_cyber_about": {
          return textContent({
            name: SERVER_NAME,
            version: pkgVersion,
            description:
              "CERT Polska / CSIRT NASK MCP server. Provides access to Polish national cybersecurity guidelines, KSC (Ustawa o Krajowym Systemie Cyberbezpieczenstwa) implementation materials, NIS2 transposition guidance, and security advisories.",
            data_source: "CERT Polska / NASK (https://cert.pl/)",
            tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
          });
        }

        case "pl_cyber_list_sources": {
          return textContent({
            sources: [
              {
                name: "CERT Polska",
                url: "https://cert.pl/",
                description:
                  "Poland's national CERT, operated by NASK. Publishes cybersecurity advisories, threat reports, and KSC/NIS2 implementation guidance.",
              },
              {
                name: "NASK (Research and Academic Computer Network)",
                url: "https://www.nask.pl/",
                description:
                  "Naukowa i Akademicka Siec Komputerowa — the Polish research institute operating CERT Polska and maintaining national cybersecurity infrastructure.",
              },
              {
                name: "CERT Polska Publications",
                url: "https://cert.pl/publikacje/",
                description:
                  "Official publication archive: technical guides, annual reports, KSC guidance documents, and NIS2 transposition materials.",
              },
            ],
          });
        }

        case "pl_cyber_check_data_freshness": {
          const dataAge = getLatestDataDate();
          const isUnknown = dataAge === "unknown";
          return textContent({
            source: "CERT Polska / NASK (https://cert.pl/)",
            last_checked: new Date().toISOString().slice(0, 10),
            data_age: dataAge,
            status: isUnknown ? "unknown" : "indexed",
            note: isUnknown
              ? "No data has been ingested yet. Run the ingest workflow to populate the database."
              : `Most recent document date in the database: ${dataAge}.`,
          });
        }

        default:
          return errorContent(`Unknown tool: ${name}`, "invalid_input");
      }
    } catch (err) {
      if (err instanceof Error && err.name === "ZodError") {
        return errorContent(`Invalid arguments for ${name}: ${err.message}`, "invalid_input");
      }
      const message = err instanceof Error ? err.message : String(err);
      return errorContent(`Error executing ${name}: ${message}`, "internal_error");
    }
  });

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
