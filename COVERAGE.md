# Data Coverage

This document describes the scope of CERT Polska / CSIRT NASK publications indexed by this MCP server.

## Source

All data is sourced from [CERT Polska](https://cert.pl/) (operated by NASK — Naukowa i Akademicka Siec Komputerowa), the Polish national Computer Emergency Response Team.

## Guidance Documents

| Category | Series | Coverage |
|----------|--------|----------|
| KSC implementation guidance | `KSC` | Key guidance documents on implementing the Polish National Cybersecurity System (Ustawa o Krajowym Systemie Cyberbezpieczenstwa) |
| NIS2 transposition materials | `NIS2` | Polish transposition of the EU NIS2 Directive; implementation guidance for operators of essential and important services |
| Technical reports and guides | `CERT-PL` | Operational security guides, threat intelligence reports, sector-specific cybersecurity recommendations |

**Estimated coverage:** The database indexes publicly available CERT Polska publications. Coverage percentage depends on the most recent ingest run; check `pl_cyber_check_data_freshness` for the latest data date.

## Security Advisories

CERT Polska security advisories, vulnerability alerts, and threat reports published at [cert.pl/publikacje](https://cert.pl/publikacje/). Includes:
- Critical and high-severity vulnerability advisories
- Ransomware and phishing campaign alerts
- Affected product lists and CVE references where available

## Frameworks

The `pl_cyber_list_frameworks` tool returns all indexed framework entries. Currently covers:
- KSC national cybersecurity framework
- Polish national cybersecurity strategy
- NIS2 compliance framework

## Freshness

Data is ingested via the [ingest workflow](.github/workflows/ingest.yml) and stored as a SQLite database released as a GitHub Release asset (`database.db.gz`). The [check-freshness workflow](.github/workflows/check-freshness.yml) runs weekly to detect new CERT Polska publications.

Use `pl_cyber_check_data_freshness` to query the most recent document date in the current database.
