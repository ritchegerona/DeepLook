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
- **38+ plugins**: WHOIS, DNS, geolocation, tech fingerprinting, username enumeration, breach checks, certificate transparency, security assessment, and more
- **Graph visualization**: ASCII/Unicode entity relationship graphs in terminal
- **Bulk scanning**: Scan hundreds of targets from a file with parallel execution
- **Deep website profiling**: Tech stack, headers, certificates, emails, subdomains
- **Cross-target correlation**: Auto-detect shared infrastructure, contacts, technology
- **Security assessment**: Vulnerability scanning, breach detection, misconfiguration checks
- **Auto-pivot**: Recursively expand an indicator breadth-first to discover related infrastructure
- **MITRE ATT&CK mapping**: Map plugins and entities to ATT&CK techniques and export coverage
- **IOC ingestion**: Import text/CSV/STIX 2.1/MISP feeds with automatic defang/refang
- **Watchlist monitoring**: Track indicators and diff newly discovered (or vanished) entities over time

### Export & Reporting
- **CSV**: Universal, spreadsheet-compatible
- **Excel**: 14-sheet formatted workbook with conditional formatting
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

# Security vulnerability and breach assessment
deeplook security example.com

# Security scan with specific type
deeplook security example.com -t breach
deeplook security example.com -t vuln
deeplook security example.com -t misconfig
deeplook security example.com -t exposure
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

### Pivoting, ATT&CK & Feeds

```bash
# Recursively pivot from a seed indicator (breadth-first)
deeplook pivot example.com --depth 2 --max-entities 50

# Map workspace findings to MITRE ATT&CK techniques
deeplook attack
deeplook attack --annotate        # persist technique IDs to entities
deeplook attack -f json           # machine-readable output

# Ingest an IOC feed (auto-detects text, CSV, STIX 2.1, MISP)
deeplook ingest -f indicators.txt --tags apt29
deeplook ingest -f bundle.json --format stix

# Watchlist: track indicators and detect changes
deeplook watch add evil[.]com -w case-001 --tags c2
deeplook watch list -w case-001
deeplook watch check -w case-001
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
| `deeplook security <target>` | Security vulnerability assessment | `deeplook security example.com` |
| `deeplook scan -f <file>` | Bulk scan from file | `deeplook scan -f targets.txt` |
| `deeplook graph` | ASCII entity graph | `deeplook graph --center example.com` |
| `deeplook pivot <target>` | Recursive entity expansion | `deeplook pivot example.com --depth 2` |
| `deeplook attack` | MITRE ATT&CK coverage mapping | `deeplook attack --annotate` |
| `deeplook ingest -f <file>` | Ingest IOC feeds (text/CSV/STIX/MISP) | `deeplook ingest -f feed.txt` |
| `deeplook watch <action>` | Watchlist add/list/remove/check | `deeplook watch check -w case-001` |
| `deeplook correlate` | Cross-target correlation | `deeplook correlate` |
| `deeplook pivot <target>` | Recursive entity expansion | `deeplook pivot example.com --depth 2` |
| `deeplook attack` | MITRE ATT&CK coverage mapping | `deeplook attack --annotate` |
| `deeplook ingest -f <file>` | Ingest IOC feeds (text/CSV/STIX/MISP) | `deeplook ingest -f feed.txt` |
| `deeplook watch <action>` | Watchlist add/list/remove/check | `deeplook watch check -w case-001` |
| `deeplook export` | Export workspace data | `deeplook export --format xlsx` |
| `deeplook workspace` | Case management | `deeplook workspace new --name case-001` |
| `deeplook plugins` | Plugin management | `deeplook plugins --action list` |
| `deeplook query` | Natural language queries | `deeplook query "find all domains linked to this IP"` |
| `deeplook diff` | Compare snapshots | `deeplook diff scan1.json scan2.json` |
| `deeplook note` | Add investigation note | `deeplook note "suspicious pattern"` |
| `deeplook timeline` | View investigation timeline | `deeplook timeline` |
| `deeplook search` | Search workspace | `deeplook search "example.com"` |
| `deeplook ai <action>` | AI analysis (summarize/pivot/report/query) | `deeplook ai summarize` |
| `deeplook gui` | Launch the Streamlit dashboard | `deeplook gui` |

---

## Plugin System

### Built-in Plugins (38)

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
| `breach-domain` | Domain | URLhaus/ThreatFox | No |
| `breach-ip` | IP | AbuseIPDB/ThreatFox | No |
| `malware-hash` | Hash | MalwareBazaar | No |
| `cve-check` | Domain/IP | NVD API | No |
| `ssl-vuln` | Domain | SSL/TLS check | No |
| `dns-security` | Domain | DNS analysis | No |
| `header-security` | Domain | HTTP headers | No |
| `email-security` | Domain | DNS records | No |
| `subdomain-takeover` | Domain | CNAME check | No |
| `exposed-services` | Domain/IP | Port/path check | No |
| `sensitive-files` | Domain | Path probing | No |
| `api-exposure` | Domain | Endpoint discovery | No |

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
Produces a 14-sheet workbook: Summary, Entities, Relationships, Domain Details, IP Details, Username Results, Email Analysis, IOCs, Correlation, ATT&CK, Watchlist, Ingestion, Timeline, Notes.

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
| `attack` | ATT&CK coverage only | Summary, ATT&CK |
| `phishing` | Phishing investigation | Domain, Email, Website, IOCs |
| `threat-actor` | Attribution focus | Username, Email, Correlation, Timeline |
| `infrastructure` | Network/infra focus | IP, Domain, Certificates |
| `monitoring` | Watchlist + ingestion monitoring | Summary, Watchlist, Ingestion, IOCs, ATT&CK, Timeline |

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
deeplook ai query -q "which indicators share infrastructure?"
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

- **Collection**: All 38 plugins are passive, open-source collection modules, plus IOC feed ingestion (text/CSV/STIX/MISP)
- **Processing**: `--json` and `--export` normalize indicators into structured records, with automatic defang/refang
- **Analysis**: Graph visualization, correlation engine, recursive auto-pivot, MITRE ATT&CK coverage, watchlist monitoring
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
