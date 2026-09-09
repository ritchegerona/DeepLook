# DeepLook

**Advanced Terminal OSINT & Threat Intelligence Framework**

A lightweight, terminal-based Open Source Intelligence (OSINT) toolkit designed for threat intelligence workflows — reconnaissance, indicator triage, attribution, and reporting. Built in Python, run entirely from the command line, with structured output for analysis, automation, and CTIA deliverables.

## Why DeepLook

Named for digging beneath the surface of an indicator — a domain, an IP, a username, or an email — to surface the first layers of context that a threat analyst needs before deciding whether a lead matters.

DeepLook maps to the **CTIA Intelligence Lifecycle**: it automates the *collection* and early *processing* stages, giving you more time for *analysis* and *dissemination*.

## Features

- **7 entity types**: Domain, IP, Email, Username, Phone, Hash, BTC wallet
- **26+ plugins**: WHOIS, DNS, geolocation, tech fingerprinting, username enumeration, breach checks, certificate transparency, and more
- **Graph visualization**: ASCII/Unicode entity relationship graphs in terminal
- **Bulk scanning**: Scan hundreds of targets from a file with parallel execution
- **Deep website profiling**: Tech stack, headers, certificates, emails, subdomains
- **Cross-target correlation**: Auto-detect shared infrastructure, contacts, technology
- **Export**: CSV, Excel (12-sheet formatted workbooks), JSON, STIX 2.1
- **Report templates**: Executive, Technical, IOC, Phishing, Threat Actor, Infrastructure
- **AI integration**: Optional LLM for summarization, pivot suggestions, report generation
- **Workspace management**: SQLite-backed case persistence with notes and timeline
- **OPSEC**: Proxy/Tor support, user-agent rotation, rate limiting
- **Caching**: TTL-based result caching to avoid re-querying

## Installation

```bash
git clone <your-repo>/DeepLook.git
cd DeepLook
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
deeplook --help
```

## Quick Start

```bash
# Single domain investigation
deeplook domain example.com

# Auto-detect entity type
deeplook analyze 8.8.8.8

# Deep website profiling
deeplook website example.com --tech-stack --headers --cert-chain

# Bulk scan from file
deeplook scan -f domains.txt --export xlsx --output reports/

# View entity graph
deeplook graph

# Export to Excel
deeplook export --format xlsx --report technical --output report.xlsx

# Natural language query
deeplook query "find all domains linked to this IP"
```

## Commands

| Command | Description |
|---------|-------------|
| `deeplook analyze <target>` | Auto-detect type, run all relevant plugins |
| `deeplook domain <domain>` | Domain investigation (WHOIS, DNS, subdomains, web) |
| `deeplook ip <ip>` | IP investigation (geolocation, reverse DNS, ports) |
| `deeplook email <email>` | Email analysis (syntax, MX, breach check) |
| `deeplook username <handle>` | Username enumeration across platforms |
| `deeplook phone <number>` | Phone number lookup |
| `deeplook hash <hash>` | File hash lookup (VirusTotal) |
| `deeplook btc <address>` | Bitcoin wallet balance |
| `deeplook website <domain>` | Deep website profiling |
| `deeplook scan -f <file>` | Bulk scan from file |
| `deeplook graph` | ASCII entity relationship graph |
| `deeplook correlate` | Cross-target correlation analysis |
| `deeplook export` | Export to CSV/Excel/JSON/STIX |
| `deeplook workspace` | Case management |
| `deeplook plugins` | Plugin management |
| `deeplook ai` | AI-powered analysis |
| `deeplook query` | Natural language queries |
| `deeplook diff` | Compare two investigation snapshots |

## Export Formats

- **CSV**: Universal, spreadsheet-compatible
- **Excel**: 12-sheet formatted workbook with conditional formatting
- **JSON**: Structured, machine-readable, TIP-compatible
- **STIX 2.1**: Industry-standard threat intelligence format

## CTIA Alignment

DeepLook maps to the EC-Council CTIA / Threat Intelligence Lifecycle:

- **Collection**: All 26+ plugins are passive, open-source collection modules
- **Processing**: `--json` and `--export` normalize indicators into structured records
- **Analysis**: Graph visualization, correlation engine, AI-powered pivot suggestions
- **Dissemination**: Report templates (Executive, Technical, IOC) ready for deliverables

See `docs/CTIA.md` for detailed module mapping.

## Responsible Use

DeepLook only queries publicly available, passive data sources. Always ensure you have proper authorization before investigating any target, and follow your organization's threat-intelligence and legal policies. Intended for authorized threat intelligence, security-research, and defensive use.

## License

MIT
