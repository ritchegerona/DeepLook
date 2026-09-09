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

**Report templates:** `executive`, `technical`, `ioc`, `phishing`, `threat_actor`, `infrastructure`, `custom`

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

**Environment variables:**
- `OPENAI_API_KEY` — OpenAI API key
- `ANTHROPIC_API_KEY` — Anthropic API key

**Examples:**
```bash
deeplook ai summarize
deeplook ai pivot -w investigation-001
deeplook ai report
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
