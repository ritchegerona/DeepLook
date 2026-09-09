# DeepLook

**Advanced Terminal OSINT & Threat Intelligence Framework**

A lightweight, terminal-based Open Source Intelligence (OSINT) toolkit designed for threat intelligence workflows — reconnaissance, indicator triage, attribution, and reporting. Built in Python, run entirely from the command line, with structured output for analysis, automation, and CTIA deliverables.

---

## Why DeepLook

Named for digging beneath the surface of an indicator — a domain, an IP, a username, or an email — to surface the first layers of context that a threat analyst needs before deciding whether a lead matters.

DeepLook maps to the **CTIA Intelligence Lifecycle**: it automates the *collection* and early *processing* stages, giving you more time for *analysis* and *dissemination*.

---

## Features

### Core Capabilities
- **7 entity types**: Domain, IP, Email, Username, Phone, Hash, BTC wallet
- **26+ plugins**: WHOIS, DNS, geolocation, tech fingerprinting, username enumeration, breach checks, certificate transparency, and more
- **Graph visualization**: ASCII/Unicode entity relationship graphs in terminal
- **Bulk scanning**: Scan hundreds of targets from a file with parallel execution
- **Deep website profiling**: Tech stack, headers, certificates, emails, subdomains
- **Cross-target correlation**: Auto-detect shared infrastructure, contacts, technology

### Export & Reporting
- **CSV**: Universal, spreadsheet-compatible
- **Excel**: 12-sheet formatted workbook with conditional formatting
- **JSON**: Structured, machine-readable, TIP-compatible
- **STIX 2.1**: Industry-standard threat intelligence format
- **Report templates**: Executive, Technical, IOC, Phishing, Threat Actor, Infrastructure

### Advanced Features
- **AI integration**: Optional LLM for summarization, pivot suggestions, report generation
- **Workspace management**: SQLite-backed case persistence with notes and timeline
- **OPSEC**: Proxy/Tor support, user-agent rotation, rate limiting
- **Caching**: TTL-based result caching to avoid re-querying
- **Plugin SDK**: Extensible architecture for community contributions

---

## Installation

### From Source

```bash
git clone https://github.com/your-username/DeepLook.git
cd DeepLook
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Verify Installation

```bash
deeplook --help
deeplook version
deeplook plugins
```

---

## Quick Start

### Single Target Investigation

```bash
# Auto-detect entity type
deeplook analyze example.com

# Domain investigation (WHOIS, DNS, subdomains, web)
deeplook domain example.com

# IP investigation (geolocation, reverse DNS, ports)
deeplook ip 8.8.8.8

# Email analysis (syntax, MX records, breach check)
deeplook email user@example.com

# Username enumeration across platforms
deeplook username johndoe

# Deep website profiling
deeplook website example.com
```

### Bulk Scanning

```bash
# Scan from file
deeplook scan -f targets.txt

# Scan with specific plugins
deeplook scan -f targets.txt --plugins domain-whois,domain-dns

# Export results
deeplook scan -f targets.txt --export xlsx --output reports/
```

### Analysis & Visualization

```bash
# View entity relationship graph
deeplook graph

# Ego graph centered on specific entity
deeplook graph --center example.com

# Cross-target correlation
deeplook correlate

# Search workspace
deeplook search "example.com"
```

### Export & Reporting

```bash
# Export to Excel
deeplook export --format xlsx --output report.xlsx

# Export with report template
deeplook export --format xlsx --report executive --output exec.xlsx

# Export to STIX 2.1
deeplook export --format stix --output stix-bundle.json
```

### Workspace Management

```bash
# Create new workspace
deeplook workspace new --name investigation-001

# List workspaces
deeplook workspace list

# Switch workspace
deeplook workspace open --name investigation-001

# Add notes
deeplook note "Suspicious domain - matches known C2 pattern"
deeplook note "Registrant matches threat actor" -e example.com

# View timeline
deeplook timeline
```

---

## Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `deeplook analyze <target>` | Auto-detect type, run all relevant plugins | `deeplook analyze 8.8.8.8` |
| `deeplook domain <domain>` | Domain investigation | `deeplook domain example.com` |
| `deeplook ip <ip>` | IP investigation | `deeplook ip 8.8.8.8` |
| `deeplook email <email>` | Email analysis | `deeplook email user@example.com` |
| `deeplook username <handle>` | Username enumeration | `deeplook username johndoe` |
| `deeplook phone <number>` | Phone number lookup | `deeplook phone +15551234567` |
| `deeplook hash <hash>` | File hash lookup | `deeplook hash d41d8cd98f00b204` |
| `deeplook btc <address>` | Bitcoin wallet check | `deeplook btc 1A1zP1eP5QGefi2DMPTf` |
| `deeplook website <domain>` | Deep website profiling | `deeplook website example.com` |
| `deeplook scan -f <file>` | Bulk scan from file | `deeplook scan -f targets.txt` |
| `deeplook graph` | ASCII entity graph | `deeplook graph --center example.com` |
| `deeplook correlate` | Cross-target correlation | `deeplook correlate` |
| `deeplook export` | Export workspace data | `deeplook export --format xlsx` |
| `deeplook workspace` | Case management | `deeplook workspace new --name case-001` |
| `deeplook plugins` | Plugin management | `deeplook plugins --action list` |
| `deeplook query` | Natural language queries | `deeplook query "find all domains linked to this IP"` |
| `deeplook diff` | Compare snapshots | `deeplook diff scan1.json scan2.json` |
| `deeplook note` | Add investigation note | `deeplook note "suspicious pattern"` |
| `deeplook timeline` | View investigation timeline | `deeplook timeline` |
| `deeplook search` | Search workspace | `deeplook search "example.com"` |

---

## Plugin System

### Built-in Plugins (26)

| Plugin | Entity Type | Source | Key Required |
|--------|-------------|--------|--------------|
| `domain-whois` | Domain | RDAP/WHOIS | No |
| `domain-dns` | Domain | dnspython | No |
| `domain-subdomain` | Domain | crt.sh | No |
| `domain-web` | Domain | HTTP HEAD | No |
| `ip-geoloc` | IP | ip-api.com | No |
| `ip-revdns` | IP | dnspython | No |
| `ip-ports` | IP | Shodan InternetDB | No |
| `ip-whois` | IP | RDAP | No |
| `username-social` | Username | HTTP checks | No |
| `email-syntax` | Email | RFC 5322 | No |
| `email-mx` | Email | dnspython | No |
| `email-breach` | Email | HaveIBeenPwned | Yes |
| `phone-lookup` | Phone | NumVerify | Yes |
| `hash-lookup` | Hash | VirusTotal | Yes |
| `btc-balance` | BTC | Blockchain.com | No |
| `crtsh` | Domain | crt.sh | No |
| `web-tech` | Domain | HTTP fingerprinting | No |
| `web-headers` | Domain | HTTP HEAD/GET | No |
| `web-cert` | Domain | SSL/TLS | No |
| `web-links` | Domain | HTML parsing | No |
| `web-emails` | Domain | HTML/text extraction | No |
| `web-sitemap` | Domain | sitemap.xml | No |
| `web-robots` | Domain | robots.txt | No |
| `web-redirects` | Domain | HTTP redirect chain | No |
| `web-meta` | Domain | HTML meta tags | No |
| `web-dns-extra` | Domain | CAA/DNSSEC | No |

### Custom Plugins

Place Python files in `~/.deeplook/plugins/` or `./plugins/`. See [docs/PLUGINS.md](docs/PLUGINS.md) for the development guide.

---

## Export Formats

### CSV
```bash
deeplook export --format csv --output results.csv
```

### Excel
```bash
deeplook export --format xlsx --report technical --output report.xlsx
```
Produces a 12-sheet workbook: Summary, Entities, Relationships, Domain Details, IP Details, Website Profiles, Username Results, Email Analysis, IOCs, Correlation, Timeline, Notes.

### JSON
```bash
deeplook export --format json --output results.json
```
Structured JSON with metadata, entities, edges, notes, timeline, and plugin results.

### STIX 2.1
```bash
deeplook export --format stix --output stix-bundle.json
```
OASIS STIX 2.1 bundle compatible with MISP, OpenCTI, and other TIPs.

---

## Report Templates

| Template | Description | Sheets |
|----------|-------------|--------|
| `executive` | High-level summary | Summary, IOCs |
| `technical` | Full technical detail | All sheets |
| `ioc` | Flat IOC list | IOCs only |
| `phishing` | Phishing investigation | Domain, Email, Website, IOCs |
| `threat-actor` | Attribution focus | Username, Email, Correlation, Timeline |
| `infrastructure` | Network/infra focus | IP, Domain, Certificates |

---

## AI Integration

Set an API key to enable LLM-powered analysis:

```bash
export OPENAI_API_KEY="sk-..."
# or
export ANTHROPIC_API_KEY="sk-ant-..."
```

Then use:
```bash
deeplook ai summarize    # Summarize findings
deeplook ai pivot        # Suggest next steps
deeplook ai report       # Generate report draft
```

Without an API key, AI features gracefully degrade with a helpful message.

---

## Configuration

DeepLook stores configuration in `~/.deeplook/`:

```
~/.deeplook/
├── config.yaml          # User preferences
├── cache.db             # Result cache
├── plugins/             # User-installed plugins
└── workspaces/          # Investigation databases
    ├── default.db
    └── case-001.db
```

---

## CTIA Alignment

DeepLook maps to the EC-Council CTIA / Threat Intelligence Lifecycle:

- **Collection**: All 26+ plugins are passive, open-source collection modules
- **Processing**: `--json` and `--export` normalize indicators into structured records
- **Analysis**: Graph visualization, correlation engine, AI-powered pivot suggestions
- **Dissemination**: Report templates (Executive, Technical, IOC) ready for deliverables

See [docs/CTIA.md](docs/CTIA.md) for detailed module mapping.

---

## Responsible Use

DeepLook only queries publicly available, passive data sources. Always ensure you have proper authorization before investigating any target, and follow your organization's threat-intelligence and legal policies. Intended for authorized threat intelligence, security-research, and defensive use.

---

## Development

### Setup

```bash
git clone https://github.com/your-username/DeepLook.git
cd DeepLook
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tests

```bash
pytest tests/ -v
ruff check .
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
