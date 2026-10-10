# DeepLook CLI Reference

Complete command reference for the DeepLook OSINT framework.

---

## Global Options

All commands accept these options:

| Option | Description |
|--------|-------------|
| `--help` | Show help message and exit |

---

## Investigation Commands

### `deeplook analyze <target>`

Auto-detect entity type and run all relevant plugins.

```bash
deeplook analyze <target> [OPTIONS]
```

**Arguments:**
- `target` — Target to investigate (auto-detect type)

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--workspace` | `-w` | Workspace name |
| `--format` | `-f` | Output format: `table`, `json` |
| `--export` | | Export format: `csv`, `xlsx`, `json`, `stix` |
| `--output` | | Export file path |
| `--no-cache` | | Skip cache |

**Examples:**
```bash
deeplook analyze example.com
deeplook analyze 8.8.8.8
deeplook analyze user@example.com --export json
```

---

### `deeplook domain <target>`

Investigate a domain (WHOIS, DNS, subdomains, web profiling).

```bash
deeplook domain <target> [OPTIONS]
```

**Plugins run:** `domain-whois`, `domain-dns`, `domain-subdomain`, `domain-web`, `web-tech`, `web-headers`, `web-cert`, `web-links`, `web-emails`, `web-sitemap`, `web-robots`, `web-redirects`, `web-meta`, `web-dns-extra`, `crtsh`

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--workspace` | `-w` | Workspace name |
| `--format` | `-f` | Output format |
| `--export` | | Export format |
| `--output` | | Export file path |
| `--no-cache` | | Skip cache |

**Examples:**
```bash
deeplook domain example.com
deeplook domain example.com --export xlsx
deeplook domain example.com -w investigation-001
```

---

### `deeplook ip <target>`

Investigate an IP address (geolocation, reverse DNS, ports, WHOIS).

```bash
deeplook ip <target> [OPTIONS]
```

**Plugins run:** `ip-geoloc`, `ip-revdns`, `ip-ports`, `ip-whois`

**Examples:**
```bash
deeplook ip 8.8.8.8
deeplook ip 192.168.1.1 --export json
```

---

### `deeplook email <target>`

Investigate an email (syntax, MX records, breach check).

```bash
deeplook email <target> [OPTIONS]
```

**Plugins run:** `email-syntax`, `email-mx`, `email-breach`

**Examples:**
```bash
deeplook email user@example.com
deeplook email user@example.com --no-cache
```

---

### `deeplook username <target>`

Investigate a username across social platforms.

```bash
deeplook username <target> [OPTIONS]
```

**Plugins run:** `username-social`

**Platforms checked:** GitHub, GitLab, Twitter/X, Reddit, Instagram, TikTok, YouTube, Twitch, Pinterest, LinkedIn, Medium, Keybase, HackerNews, DeviantArt, SoundCloud

**Examples:**
```bash
deeplook username johndoe
deeplook username johndoe --export csv
```

---

### `deeplook phone <target>`

Investigate a phone number.

```bash
deeplook phone <target> [OPTIONS]
```

**Plugins run:** `phone-lookup` (requires `NUMVERIFY_API_KEY`)

**Examples:**
```bash
deeplook phone +15551234567
```

---

### `deeplook hash <target>`

Investigate a file hash (MD5/SHA1/SHA256).

```bash
deeplook hash <target> [OPTIONS]
```

**Plugins run:** `hash-lookup` (requires `VT_API_KEY`)

**Examples:**
```bash
deeplook hash d41d8cd98f00b204e9800998ecf8427e
deeplook hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

### `deeplook btc <target>`

Investigate a Bitcoin wallet address.

```bash
deeplook btc <target> [OPTIONS]
```

**Plugins run:** `btc-balance`

**Examples:**
```bash
deeplook btc 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

---

### `deeplook website <target>`

Deep website profiling (tech stack, headers, certs, links, emails).

```bash
deeplook website <target> [OPTIONS]
```

**Plugins run:** `web-tech`, `web-headers`, `web-cert`, `web-links`, `web-emails`, `web-sitemap`, `web-robots`, `web-redirects`, `web-meta`, `web-dns-extra`

**Examples:**
```bash
deeplook website example.com
deeplook website example.com --export xlsx
```

---

### `deeplook security <target>`

Security vulnerability and breach assessment.

```bash
deeplook security <target> [OPTIONS]
```

**Plugins run:** All 12 security plugins (unless filtered by type)

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--type` | `-t` | Security check type: `breach`, `vuln`, `misconfig`, `exposure` | all |
| `--workspace` | `-w` | Workspace name | |
| `--format` | `-f` | Output format: `table`, `json` | `table` |
| `--export` | | Export format: `json`, `xlsx`, `stix` | |
| `--output` | | Export file path | |
| `--no-cache` | | Skip cache | |

**Security Types:**
- `breach` — Breach detection: `breach-domain`, `breach-ip`, `malware-hash`
- `vuln` — Vulnerability scanning: `cve-check`, `subdomain-takeover`, `ssl-vuln`
- `misconfig` — Misconfiguration checks: `dns-security`, `header-security`, `email-security`
- `exposure` — Exposure detection: `exposed-services`, `sensitive-files`, `api-exposure`

**Security Scoring:**
The security command produces a weighted score across 6 categories:
- SSL/TLS Security (20%)
- DNS Security (20%)
- Security Headers (20%)
- Email Security (15%)
- Exposure Risk (15%)
- Breach Status (10%)

**Examples:**
```bash
# Full security assessment
deeplook security example.com

# Breach detection only
deeplook security example.com -t breach

# Vulnerability scan with JSON output
deeplook security example.com -t vuln -f json

# Export security report
deeplook security example.com --export xlsx --output security-report.xlsx
```

---

## Bulk Operations

### `deeplook scan`

Bulk scan targets from a file.

```bash
deeplook scan [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--file` | `-f` | File with targets (one per line) | *required* |
| `--workspace` | `-w` | Workspace name | |
| `--concurrency` | `-c` | Parallel scans | `10` |
| `--export` | | Export format | |
| `--export-dir` | | Export directory | |
| `--plugins` | | Comma-separated plugin names | |

**Input formats:**
- `.txt` — one indicator per line
- `.csv` — with column selection
- `.json` — array of strings

**Examples:**
```bash
deeplook scan -f targets.txt
deeplook scan -f targets.txt --plugins domain-whois,domain-dns
deeplook scan -f targets.txt --export xlsx --export-dir reports/
```

---

## Analysis & Visualization

### `deeplook graph`

Display ASCII entity relationship graph.

```bash
deeplook graph [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--center` | `-c` | Center entity for ego graph | |
| `--depth` | `-d` | Max graph depth | `3` |
| `--workspace` | `-w` | Workspace name | |
| `--geo` | | Show geolocation map | |

**Examples:**
```bash
deeplook graph
deeplook graph --center example.com
deeplook graph --center example.com --depth 5
deeplook graph --geo
```

---

### `deeplook correlate`

Run cross-target correlation analysis.

```bash
deeplook correlate [OPTIONS]
```

**Correlation types:**
- Shared infrastructure (same IP across domains)
- Shared contacts (same email across domains)
- Shared technology (same CMS/framework)
- Certificate overlap (same issuer + expiry)

**Examples:**
```bash
deeplook correlate
deeplook correlate -w investigation-001
```

---

### `deeplook query <question>`

Natural language query against workspace data.

```bash
deeplook query <question> [OPTIONS]
```

**Examples:**
```bash
deeplook query "find all domains linked to this IP"
deeplook query "what emails were found"
deeplook query "show me all breached accounts"
```

---

## Pivoting & ATT&CK

### `deeplook pivot <target>`

Recursively expand an indicator breadth-first, running the relevant plugins on
each newly discovered entity and persisting the resulting graph.

```bash
deeplook pivot <target> [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--depth` | `-d` | Maximum expansion depth | `2` |
| `--max-entities` | | Entity budget before truncating | `50` |
| `--plugins` | | Comma-separated plugin names to restrict expansion | all |
| `--workspace` | `-w` | Workspace name | |

**Examples:**
```bash
deeplook pivot example.com
deeplook pivot example.com --depth 3 --max-entities 100
deeplook pivot 8.8.8.8 --plugins ip-revdns
```

---

### `deeplook attack`

Map workspace findings to MITRE ATT&CK techniques (Reconnaissance and Resource
Development tactics) via plugin provenance, with an entity-type fallback.

```bash
deeplook attack [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--annotate` | | Persist technique IDs into entity metadata | off |
| `--format` | `-f` | Output format: `table`, `json` | `table` |
| `--workspace` | `-w` | Workspace name | |

**Examples:**
```bash
deeplook attack
deeplook attack --annotate
deeplook attack -f json
```

---

## Threat Intelligence Feeds

### `deeplook ingest`

Ingest IOC feeds into a workspace. Supports plain/defanged text (one indicator
per line), CSV, STIX 2.1 bundles, and MISP event JSON. Indicators are refanged,
de-duplicated, tagged, and stored with `ingest:<file>` provenance.

```bash
deeplook ingest -f <file> [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--file` | `-f` | Feed file to ingest | *required* |
| `--format` | | Format: `auto`, `text`, `csv`, `stix`, `misp` | `auto` |
| `--tags` | | Comma-separated tags to apply | |
| `--output-format` | | Output format: `table`, `json` | `table` |
| `--workspace` | `-w` | Workspace name | |

**Examples:**
```bash
deeplook ingest -f indicators.txt --tags apt29
deeplook ingest -f feed.csv --format csv
deeplook ingest -f bundle.json --format stix --output-format json
```

---

### `deeplook watch`

Manage the watchlist and check watched indicators for newly discovered (or
vanished) related entities.

```bash
deeplook watch <action> [value] [OPTIONS]
```

**Actions:**
- `add` — Add an indicator to the watchlist
- `list` — List watched indicators
- `remove` — Remove a watch by id
- `check` — Re-run plugins and diff against the previous check (all, or one id)

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--tags` | | Comma-separated tags (add) |
| `--note` | | Note (add) |
| `--output-format` | | Output format: `table`, `json` |
| `--report` | | Append a JSON-lines run log to this file (check) |
| `--fail-on-change` | | Exit 2 if any changes are detected (check) |
| `--workspace` | `-w` | Workspace name |

**Examples:**
```bash
deeplook watch add evil[.]com -w case-001 --tags c2
deeplook watch list -w case-001
deeplook watch check -w case-001
deeplook watch check 2 -w case-001
deeplook watch remove 2 -w case-001
deeplook watch check -w case-001 --report ~/.deeplook/watch-runs.jsonl
deeplook watch check -w case-001 --fail-on-change
```

See [SCHEDULING.md](SCHEDULING.md) for running checks on a schedule (cron,
launchd, systemd).

---

## Export & Reporting

### `deeplook export`

Export workspace data.

```bash
deeplook export [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-f` | Export format: `csv`, `xlsx`, `json`, `stix` | `json` |
| `--report` | | Report template | `full` |
| `--output` | `-o` | Output file path | |
| `--workspace` | `-w` | Workspace name | |

**Report templates:** `executive`, `technical`, `ioc`, `phishing`, `threat_actor`, `infrastructure`, `attack`, `monitoring`, `custom`

**Examples:**
```bash
deeplook export --format xlsx --output report.xlsx
deeplook export --format xlsx --report executive --output exec.xlsx
deeplook export --format stix --output stix-bundle.json
deeplook export --format csv --output iocs.csv
```

---

## Workspace Management

### `deeplook workspace`

Manage investigation workspaces.

```bash
deeplook workspace <action> [OPTIONS]
```

**Actions:**
- `new` — Create new workspace
- `list` — List all workspaces
- `open` — Switch to workspace

**Options:**
| Option | Description |
|--------|-------------|
| `--name` | Workspace name |

**Examples:**
```bash
deeplook workspace new --name investigation-001
deeplook workspace list
deeplook workspace open --name investigation-001
```

---

### `deeplook note`

Add an investigation note.

```bash
deeplook note <content> [OPTIONS]
```

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--entity` | `-e` | Attach to entity |
| `--workspace` | `-w` | Workspace name |

**Examples:**
```bash
deeplook note "Suspicious domain - matches known C2 pattern"
deeplook note "Registrant matches threat actor" -e example.com
```

---

### `deeplook timeline`

Show investigation timeline.

```bash
deeplook timeline [OPTIONS]
```

**Examples:**
```bash
deeplook timeline
deeplook timeline -w investigation-001
```

---

### `deeplook search <query>`

Search workspace for entities, edges, and notes.

```bash
deeplook search <query> [OPTIONS]
```

**Examples:**
```bash
deeplook search "example.com"
deeplook search "breached"
```

---

### `deeplook diff`

Compare two investigation snapshots.

```bash
deeplook diff <scan1> <scan2>
```

**Arguments:**
- `scan1` — Path to first scan JSON
- `scan2` — Path to second scan JSON

**Examples:**
```bash
deeplook diff scan-2026-09-07.json scan-2026-09-08.json
```

---

## Plugin Management

### `deeplook plugins`

List or get info about plugins.

```bash
deeplook plugins [OPTIONS]
```

**Options:**
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--action` | `-a` | Action: `list`, `info` | `list` |
| `--name` | `-n` | Plugin name for info | |

**Examples:**
```bash
deeplook plugins
deeplook plugins --action info --name domain-whois
```

---

## AI Commands

### `deeplook ai`

AI-powered analysis (requires API key).

```bash
deeplook ai <action> [OPTIONS]
```

**Actions:**
- `summarize` — Summarize current findings
- `pivot` — Suggest next investigation steps
- `report` — Generate investigation report draft
- `query` — Answer a natural-language question (use `-q`)

**Options:**
| Option | Short | Description |
|--------|-------|-------------|
| `--question` | `-q` | Question (for the `query` action) |
| `--output` | `-o` | Write the result to a file |
| `--workspace` | `-w` | Workspace name |

**Environment variables:**
- `OPENAI_API_KEY` — OpenAI API key
- `ANTHROPIC_API_KEY` — Anthropic API key

**Examples:**
```bash
deeplook ai summarize
deeplook ai pivot -w investigation-001
deeplook ai report -o report-draft.md
deeplook ai query -q "which indicators share infrastructure?"
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for AI features |
| `ANTHROPIC_API_KEY` | Anthropic API key for AI features |
| `HIBP_API_KEY` | HaveIBeenPwned API key for breach checks |
| `VT_API_KEY` | VirusTotal API key for hash lookups |
| `NUMVERIFY_API_KEY` | NumVerify API key for phone lookups |
