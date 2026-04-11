#!/usr/bin/env node

/**
 * Polish Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying CERT Polska / CSIRT NASK guidelines,
 * technical reports, security advisories, and cybersecurity frameworks.
 * CERT Polska operates under NASK (Research and Academic Computer Network
 * — Naukowa i Akademicka Siec Komputerowa).
 *
 * Tool prefix: pl_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
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

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "polish-cybersecurity-mcp";

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
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
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
        reference: {
          type: "string",
          description: "CERT Polska document reference",
        },
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
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "pl_cyber_get_advisory",
    description:
      "Get a specific CERT Polska security advisory by reference (e.g., 'CERT-PL-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "CERT Polska advisory reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "pl_cyber_list_frameworks",
    description:
      "List all CERT Polska frameworks and guidance series covered in this MCP, including the KSC national cybersecurity framework and NIS2 implementation materials.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "pl_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "pl_cyber_list_sources",
    description: "List the primary data sources indexed by this MCP server, including CERT Polska, cert.pl, and NASK.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "pl_cyber_check_data_freshness",
    description: "Check the freshness of the indexed data: when it was last updated and whether it is current.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

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

// --- Helpers ------------------------------------------------------------------

function responseMeta() {
  return {
    disclaimer:
      "This data is provided for informational purposes only. Always verify against official CERT Polska publications at https://cert.pl/.",
    data_age: getLatestDataDate(),
    copyright: "CERT Polska / NASK",
    source_url: "https://cert.pl/",
  };
}

function textContent(data: unknown) {
  const payload =
    data !== null && typeof data === "object"
      ? { ...(data as Record<string, unknown>), _meta: responseMeta() }
      : { data, _meta: responseMeta() };
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(payload, null, 2) },
    ],
  };
}

function errorContent(message: string, errorType: "not_found" | "invalid_input" | "internal_error" = "internal_error") {
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

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

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
          coverage: {
            guidance: "KSC national cybersecurity framework guidance, NIS2 implementation, sector-specific security recommendations, CSIRT operational guides",
            advisories: "CERT Polska security advisories, vulnerability alerts, and threat intelligence reports",
            frameworks: "KSC framework, Polish national cybersecurity strategy, NIS2 compliance framework",
          },
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

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
