# Tool Reference

This MCP server exposes the following tools under the `pl_cyber_` prefix.

---

## pl_cyber_search_guidance

Full-text search across CERT Polska / CSIRT NASK guidelines and technical reports.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search query in Polish or English (e.g., `"cyberbezpieczenstwo"`, `"KSC wymagania"`, `"incident response"`) |
| `type` | string | No | Filter by document type: `technical_guideline`, `sector_guide`, `standard`, `recommendation` |
| `series` | string | No | Filter by guidance series: `CERT-PL`, `KSC`, `NIS2` |
| `status` | string | No | Filter by document status: `current`, `superseded`, `draft` |
| `limit` | number | No | Maximum results to return (default: 20, max: 100) |

**Example:**
```json
{
  "query": "zarzadzanie podatnosciami",
  "series": "KSC",
  "status": "current"
}
```

---

## pl_cyber_get_guidance

Retrieve a specific CERT Polska guidance document by its reference identifier.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | Yes | CERT Polska document reference (e.g., `"CERT-PL-2023-01"`, `"KSC-Przewodnik-001"`) |

**Example:**
```json
{ "reference": "CERT-PL-2023-01" }
```

**Response includes:** full document text, metadata, and `_citation` for agent verification.

---

## pl_cyber_search_advisories

Search CERT Polska security advisories and threat reports.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search query in Polish or English (e.g., `"ransomware"`, `"krytyczna podatnosc"`) |
| `severity` | string | No | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | No | Maximum results to return (default: 20, max: 100) |

**Example:**
```json
{ "query": "phishing kampania", "severity": "high" }
```

---

## pl_cyber_get_advisory

Retrieve a specific CERT Polska security advisory by reference.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | Yes | Advisory reference (e.g., `"CERT-PL-2024-001"`) |

**Example:**
```json
{ "reference": "CERT-PL-2024-001" }
```

**Response includes:** severity, affected products, CVE references, full text, and `_citation`.

---

## pl_cyber_list_frameworks

List all CERT Polska frameworks and guidance series indexed in this MCP.

**Parameters:** None

**Example response:**
```json
{
  "frameworks": [
    { "id": "KSC", "name": "Krajowy System Cyberbezpieczenstwa", "document_count": 12 }
  ],
  "count": 1
}
```

---

## pl_cyber_about

Return metadata about this MCP server including version, data source, coverage summary, and tool list.

**Parameters:** None

---

## pl_cyber_list_sources

List the primary data sources indexed by this server.

**Parameters:** None

**Example response:**
```json
{
  "sources": [
    {
      "name": "CERT Polska",
      "url": "https://cert.pl/",
      "description": "Poland's national CERT..."
    }
  ]
}
```

---

## pl_cyber_check_data_freshness

Check when the indexed data was last updated.

**Parameters:** None

**Example response:**
```json
{
  "source": "CERT Polska / NASK (https://cert.pl/)",
  "last_checked": "2026-04-11",
  "data_age": "2025-12-01",
  "status": "indexed"
}
```

---

## Common Response Fields

All successful responses include a `_meta` block:

```json
{
  "_meta": {
    "disclaimer": "This data is provided for informational purposes only...",
    "data_age": "2025-12-01",
    "copyright": "CERT Polska / NASK",
    "source_url": "https://cert.pl/"
  }
}
```

All `get_*` tool responses and per-item search results include a `_citation` block for agent-level verification:

```json
{
  "_citation": {
    "canonical_ref": "CERT-PL-2024-001",
    "display_text": "CERT-PL-2024-001",
    "lookup": {
      "tool": "pl_cyber_get_advisory",
      "arguments": { "reference": "CERT-PL-2024-001" }
    }
  }
}
```

Error responses include `_error_type`:

| Value | Meaning |
|-------|---------|
| `not_found` | The requested document or advisory does not exist in the database |
| `invalid_input` | Argument validation failed (ZodError) or unknown tool name |
| `internal_error` | Unexpected server error |
