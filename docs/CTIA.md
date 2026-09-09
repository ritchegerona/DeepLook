# DeepLook & CTIA Alignment

How DeepLook maps to the EC-Council Certified Threat Intelligence Analyst (CTIA) curriculum and the Threat Intelligence Lifecycle.

---

## Threat Intelligence Lifecycle Mapping

DeepLook automates the **Collection** and **Processing** stages of the Intelligence Lifecycle, enabling analysts to focus on **Analysis** and **Dissemination**.

| Lifecycle Stage | DeepLook Feature | Commands |
|-----------------|------------------|----------|
| **Planning & Direction** | Workspace management, investigation notes | `workspace new`, `note` |
| **Collection** | 26+ passive OSINT plugins | `domain`, `ip`, `email`, `username`, `website`, `scan` |
| **Processing** | Entity normalization, graph construction, caching | `analyze`, `graph` |
| **Analysis** | Correlation engine, AI pivot suggestions | `correlate`, `ai pivot`, `query` |
| **Dissemination** | Export to CSV/Excel/JSON/STIX, report templates | `export`, `ai report` |
| **Feedback** | Timeline tracking, diff comparison | `timeline`, `diff` |

---

## CTIA Module Mapping

### Module 1: Introduction to Threat Intelligence

DeepLook provides hands-on practice with:
- **OSINT collection** via 26+ plugins
- **Indicator types**: Domains, IPs, emails, usernames, hashes, BTC wallets
- **Source validation**: Each result includes provenance tracking

**Commands:** `analyze`, `domain`, `ip`, `email`, `username`

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
