# DeepLook & CTIA Alignment

How DeepLook maps to the EC-Council Certified Threat Intelligence Analyst (CTIA) curriculum and the Threat Intelligence Lifecycle.

---

## Threat Intelligence Lifecycle Mapping

DeepLook automates the **Collection** and **Processing** stages of the Intelligence Lifecycle, enabling analysts to focus on **Analysis** and **Dissemination**.

| Lifecycle Stage | DeepLook Feature | Commands |
|-----------------|------------------|----------|
| **Planning & Direction** | Workspace management, investigation notes | `workspace new`, `note` |
| **Collection** | 38+ passive OSINT plugins, IOC feed ingestion | `domain`, `ip`, `email`, `username`, `website`, `scan`, `ingest` |
| **Processing** | Entity normalization, defang/refang, graph construction, caching | `analyze`, `ingest`, `graph` |
| **Analysis** | Correlation engine, recursive auto-pivot, ATT&CK mapping, security assessment, watchlist monitoring | `correlate`, `pivot`, `attack`, `watch`, `query`, `security` |
| **Dissemination** | Export to CSV/Excel/JSON/STIX, report templates incl. ATT&CK | `export`, `attack`, `ai report` |
| **Feedback** | Timeline tracking, diff comparison, watchlist change detection | `timeline`, `diff`, `watch check` |

---

## CTIA Module Mapping

### Module 1: Introduction to Threat Intelligence

DeepLook provides hands-on practice with:
- **OSINT collection** via 38+ plugins
- **Indicator types**: Domains, IPs, emails, usernames, hashes, BTC wallets
- **Source validation**: Each result includes provenance tracking
- **Security assessment**: Vulnerability scanning, breach detection, misconfiguration checks

**Commands:** `analyze`, `domain`, `ip`, `email`, `username`, `security`

---

### Module 2: Threat Intelligence Lifecycle

DeepLook implements all six stages:
1. **Planning**: Create workspaces, define investigation scope
2. **Collection**: Run plugins against targets
3. **Processing**: Normalize results into entity/edge graph
4. **Analysis**: Correlate findings, identify patterns
5. **Dissemination**: Export to industry-standard formats
6. **Feedback**: Track timeline, compare snapshots

**Commands:** Full workflow from `workspace new` to `export`

---

### Module 3: Advanced Threat Intelligence and Countermeasures

DeepLook supports:
- **Infrastructure analysis**: WHOIS, DNS, certificate transparency
- **Threat actor profiling**: Username enumeration, email analysis
- **Attack surface mapping**: Subdomain enumeration, tech fingerprinting
- **Indicator enrichment**: Geolocation, port scanning, breach checks

**Commands:** `domain`, `website`, `scan`, `correlate`

---

### Module 4: Threat Intelligence for Cyber Countermeasures

DeepLook enables:
- **Proactive defense**: Identify exposed infrastructure before attackers
- **Incident response**: Quick triage of suspicious indicators
- **Threat hunting**: Bulk scan IOCs from threat reports
- **Attribution support**: Cross-reference indicators across investigations

**Commands:** `scan`, `diff`, `export --format stix`

---

### Module 5: Strategic Threat Intelligence

DeepLook supports executive reporting:
- **Executive summary reports**: High-level findings for leadership
- **Risk assessment**: Confidence scoring for indicators
- **Trend analysis**: Timeline tracking across investigations
- **Shareable formats**: STIX bundles for TIP integration

**Commands:** `export --report executive`, `export --format stix`, `timeline`

---

## CTIA Practical Exercises

### Exercise 1: Domain Investigation

```bash
# Investigate a suspicious domain
deeplook domain suspicious-site.com

# View the entity graph
deeplook graph --center suspicious-site.com

# Export findings
deeplook export --format xlsx --report technical --output domain-report.xlsx
```

**Skills practiced:** WHOIS analysis, DNS enumeration, subdomain discovery, certificate analysis

---

### Exercise 2: IP Attribution

```bash
# Investigate a malicious IP
deeplook ip 185.220.101.45

# Check for related domains
deeplook graph --center 185.220.101.45

# Correlate with other targets
deeplook correlate
```

**Skills practiced:** Geolocation, reverse DNS, port scanning, infrastructure mapping

---

### Exercise 3: Email Analysis

```bash
# Investigate a phishing email
deeplook email attacker@malicious-domain.com

# Check for breach exposure
deeplook email victim@company.com

# Export IOCs for SIEM
deeplook export --format csv --output email-iocs.csv
```

**Skills practiced:** Email validation, MX analysis, breach checking, IOC extraction

---

### Exercise 4: Username Investigation

```bash
# Enumerate social profiles
deeplook username threat_actor_handle

# View all discovered accounts
deeplook graph --center threat_actor_handle

# Generate attribution report
deeplook export --report threat-actor --output attribution.xlsx
```

**Skills practiced:** Social media enumeration, persona mapping, attribution analysis

---

### Exercise 5: Bulk IOC Triage

```bash
# Scan indicators from a threat report
deeplook scan -f threat-report-iocs.txt

# View correlation across all targets
deeplook correlate

# Export for TIP ingestion
deeplook export --format stix --output stix-bundle.json
```

**Skills practiced:** Bulk analysis, cross-target correlation, TIP integration

---

### Exercise 6: Website Profiling

```bash
# Deep profile a target website
deeplook website target-site.com

# Identify technology stack
deeplook website target-site.com --export json

# Track changes over time
deeplook scan -f target-site.txt --export xlsx --export-dir week1/
# ... later ...
deeplook scan -f target-site.txt --export xlsx --export-dir week2/
deeplook diff week1/scan.json week2/scan.json
```

**Skills practiced:** Technology fingerprinting, attack surface mapping, change detection

---

### Exercise 7: Recursive Pivoting & ATT&CK Mapping

```bash
# Expand from a seed indicator, discovering related infrastructure
deeplook pivot example.com --depth 2 --max-entities 50

# Map the resulting findings to MITRE ATT&CK techniques
deeplook attack

# Persist technique IDs and export an ATT&CK coverage report
deeplook attack --annotate
deeplook export --format xlsx --report attack --output attack-coverage.xlsx
```

**Skills practiced:** Infrastructure pivoting, MITRE ATT&CK technique mapping, adversary-tactic coverage

---

### Exercise 8: IOC Feed Ingestion & Watchlist Monitoring

```bash
# Ingest a defanged IOC feed and tag it
deeplook ingest -f threat-feed.txt --tags apt29

# Add key indicators to a watchlist
deeplook watch add evil[.]com -w case-001 --tags c2

# Re-check later and diff for newly observed infrastructure
deeplook watch check -w case-001

# Ingest a STIX bundle from another TIP
deeplook ingest -f external-bundle.json --format stix
```

**Skills practiced:** Feed ingestion, defang/refang handling, STIX/MISP interop, continuous monitoring

---

## MITRE ATT&CK Mapping

DeepLook maps its collection and analysis activity to ATT&CK techniques via
plugin provenance (the plugin that produced a finding), with an entity-type
fallback when provenance is unavailable. Because DeepLook is a passive
collection and reconnaissance tool, its techniques sit primarily in the
**Reconnaissance** and **Resource Development** tactics.

| DeepLook Activity | Example Plugins | ATT&CK Techniques |
|-------------------|-----------------|-------------------|
| DNS enumeration | `domain-dns`, `dns-security`, `web-dns-extra` | T1590.002 (DNS), T1596.001 (DNS/Passive DNS) |
| WHOIS / registration | `domain-whois`, `ip-whois` | T1596.002 (WHOIS) |
| Subdomain discovery | `domain-subdomain`, `crtsh` | T1590.001 (Domain Properties) |
| Active scanning / ports | `ip-ports`, `exposed-services` | T1595 (Active Scanning), T1595.001 (Scanning IP Blocks) |
| Vulnerability checks | `cve-check`, `ssl-vuln`, `subdomain-takeover` | T1595.002 (Vulnerability Scanning) |
| Email/mail infrastructure | `email-mx`, `email-security`, `web-emails` | T1589.002 (Email Addresses) |
| Username / persona | `username-social` | T1589.003 (Employee Names) |
| Host/software fingerprint | `web-tech`, `web-headers`, `web-cert` | T1592.002 (Software) |

Use `deeplook attack` to generate coverage from a workspace, `--annotate` to
persist IDs to entities, and `--report attack` on export for a spreadsheet.

---

## IOC Types and STIX Mapping
DeepLook entities map to STIX 2.1 objects:

| DeepLook Entity | STIX Object | Pattern Type |
|-----------------|-------------|--------------|
| Domain | `indicator` | `[domain-name:value = '...']` |
| IP | `indicator` | `[ipv4-addr:value = '...']` |
| Email | `indicator` | `[email-addr:value = '...']` |
| Hash (MD5) | `indicator` | `[file:hashes.MD5 = '...']` |
| Hash (SHA1) | `indicator` | `[file:hashes.'SHA-1' = '...']` |
| Hash (SHA256) | `indicator` | `[file:hashes.'SHA-256' = '...']` |
| URL | `indicator` | `[url:value = '...']` |

---

## Confidence Scoring

DeepLook assigns confidence scores based on source reliability:

| Source Type | Base Confidence | Rationale |
|-------------|-----------------|-----------|
| WHOIS/RDAP | 90% | Authoritative registry data |
| DNS | 95% | Direct resolution |
| Geolocation | 70% | Third-party approximation |
| Port scan | 80% | Shodan InternetDB |
| Username check | 80% | HTTP status code |
| Breach check | 95% | HIBP authoritative |
| Tech fingerprint | 80% | Pattern matching |

Analyst notes and tags can override confidence scores.

---

## Best Practices for CTIA Candidates

1. **Always document your methodology**: Use `note` and `timeline` to track your investigation process
2. **Validate findings**: Cross-reference results across multiple plugins
3. **Maintain OPSEC**: Use workspaces to isolate investigations
4. **Export for reports**: Use `export --report` templates for deliverables
5. **Track changes**: Use `diff` to compare investigation snapshots over time
6. **Share intelligence**: Use STIX export for TIP integration
7. **Practice responsible use**: Only investigate authorized targets
