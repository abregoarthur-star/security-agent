# Uber Security Agent

## Overview
Autonomous AI security intelligence agent powered by Claude Opus 4.6. Continuously monitors 7 vulnerability databases and exploit feeds, analyzes the threat landscape, identifies bug bounty opportunities, and delivers actionable security alerts via Telegram.

**Bot:** @UberSecurityBot on Telegram (pending BotFather setup)
**Hosting:** Railway (same Hobby plan as the Brain)
**Model:** Claude Opus 4.6 (best available — this is for making money)
**Feeds:** 7 intelligence sources, all free

## Revenue Model
1. **Bug Bounties** — First-to-find advantage via fast CVE → exploit correlation + Nuclei template generation
2. **SMB Monitoring** — Curated vulnerability alerts for business customers ($49-$349/mo)
3. **Intelligence Feeds** — Premium threat intelligence delivery ($29-$199/mo)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              INTELLIGENCE FEEDS (7, all free)                │
│                                                              │
│  NVD ─────────── 337K+ CVEs, CVSS scores, CWE, CPE         │
│  CISA KEV ────── Actively exploited in the wild              │
│  OSV.dev ─────── npm, PyPI, Go, Rust, Maven, NuGet, Ruby    │
│  GitHub ─────── Security advisories (reviewed, with CVSS)    │
│  Exploit-DB ──── New exploits as they drop (RSS)             │
│  PacketStorm ─── Exploit + advisory feed (RSS)               │
│  The Hacker News  Security news for context (RSS)            │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              SECURITY AGENT (Railway)                        │
│                                                              │
│  index.js ──── Express server + 3 cron jobs                  │
│  intel.js ──── 7-feed polling engine + CVE store + scoring   │
│  analysis.js ── Opus 4.6 threat analysis + bounty strategy   │
│  findings.js ── Finding store                                │
│  telegram.js ── 13 commands + alert formatting               │
└──────────────────────────┬──────────────────────────────────┘
                           │
                      Telegram ──> Arthur's phone
```

## Cron Schedule

| Pattern | Frequency | Purpose |
|---------|-----------|---------|
| `*/5 * * * *` | Every 5 min | Poll ALL 7 feeds — speed is money in bug bounties |
| `*/15 * * * *` | Every 15 min | Opus 4.6 deep analysis — bounty opportunities, exploit watch, threat trends |
| `0 13 * * *` | 8:00 AM ET | Full daily security briefing with all metrics |

## Intelligence Feeds

| Feed | Data | Cost | Why |
|------|------|------|-----|
| **NVD** | 337K+ CVEs, CVSS, CWE, CPE | Free | Core vulnerability database |
| **CISA KEV** | Actively exploited vulns | Free | Highest-priority threats |
| **OSV.dev** | Package vulns (8 ecosystems) | Free | Supply chain attacks |
| **GitHub Advisories** | Reviewed advisories + CVSS | Free | OSS vuln coverage |
| **Exploit-DB** | New exploits RSS | Free | Weaponization tracking |
| **Packet Storm** | Exploit + advisory RSS | Free | Additional exploit coverage |
| **The Hacker News** | Security news | Free | Threat context |

## Opus 4.6 Analysis (Every 15 min)

Claude Opus 4.6 analyzes the full CVE + exploit landscape and produces:

1. **Bounty Opportunities** — CVE ID, target, estimated bounty, difficulty, exploitation strategy
2. **Nuclei Template Priority** — Which CVEs to write templates for first (first-to-scan advantage)
3. **SMB Alerts** — What business customers need to patch NOW
4. **Exploit Watch** — Newly weaponized vulnerabilities
5. **Attack Trends** — What attack vectors are trending
6. **Market Intel** — How the threat landscape affects cybersecurity stocks

### Bounty Relevance Scoring
Every CVE is scored for bounty relevance based on:
- CWE type (XSS, SQLi, SSRF, auth bypass, RCE = high value)
- Web-facing keywords (API, REST, GraphQL, plugin, portal, admin)
- Attack vector (NETWORK = remotely exploitable = bounty target)
- Exploit availability (exploit exists = confirmed vulnerable)

## Telegram Commands (13)

| Command | Description |
|---------|-------------|
| `/start` | Welcome + capabilities |
| `/status` | Full agent status — feeds, model, database, uptime |
| `/stats` | CVE statistics (24h) with bounty metrics |
| `/critical` | Recent critical/high CVEs with exploit + bounty flags |
| `/cve [ID]` | Detailed CVE lookup (local + NVD API) |
| `/threats` | Opus 4.6 threat landscape analysis |
| `/bounty` | Bug bounty opportunities + Nuclei template priorities |
| `/exploits` | Recent public exploits (Exploit-DB + PacketStorm) |
| `/news` | Security news headlines (The Hacker News) |
| `/feeds` | Feed health dashboard with last poll times |
| `/scan [domain]` | Security header check with letter grade |
| `/chatid` | Show chat ID |
| `/help` | All commands |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | From @BotFather |
| `TELEGRAM_CHAT_ID` | Yes | Default alert chat |
| `ANTHROPIC_API_KEY` | Yes | Claude API (Opus 4.6) |
| `BRAIN_API_URL` | No | Brain production URL |
| `BRAIN_API_KEY` | No | Shared API key for Brain intel |
| `NVD_API_KEY` | No | Higher NVD rate limits |
| `GITHUB_TOKEN` | No | Higher GitHub API limits |
| `PORT` | No | Server port (Railway assigns) |

## File Structure

```
security-agent/
├── package.json
├── Dockerfile
├── CLAUDE.md
├── .gitignore
├── .env.example
└── src/
    ├── index.js      # Express + 3 crons + alert formatters
    ├── telegram.js   # 13 commands + quick scan + HTML alerts
    ├── intel.js      # 7-feed polling engine + bounty scoring + RSS parser
    ├── analysis.js   # Opus 4.6 threat analysis + bounty strategy
    └── findings.js   # Finding store (in-memory)
```

## Brain Integration

| Endpoint | Data |
|----------|------|
| `GET /intel/security` | Stats, critical CVEs, analysis, bounty opps, exploits, news |
| `GET /intel/cve?q=` | CVE search (local + NVD fallback) |
| `GET /intel/analysis` | Latest analysis + 24h history |

Auth: `x-api-key` header (same pattern as Trader Agent)

## Future Phases (all on Railway)

1. **Nuclei Scanning** — Docker-based vuln scanning, custom template generation
2. **Recon Pipeline** — subfinder + httpx for asset discovery
3. **HackerOne Integration** — Scope parsing, automated report drafts, submission API
4. **SMB SaaS** — Customer dashboard, Stripe billing, scheduled scans
5. **Brain Tool** — `security_scan` tool for the AI Brain
6. **Trader Agent Cross-Intel** — Feed cybersecurity market insights to the Trader

## Development

```bash
npm install
npm run dev       # Watch mode
npm start         # Production
```

## Key Design Decisions

- **Opus 4.6 for analysis** — This is for making money. The best model produces the best intelligence. We're on the $100 Max plan.
- **7 feeds, all free** — Maximum coverage at zero data cost. Every feed adds signal.
- **5-minute polling** — Speed is money in bug bounties. First to find = first to report.
- **Bounty relevance scoring** — Not all CVEs are equal. Score by CWE, attack vector, and web exposure.
- **HTML parse mode** — More reliable than Markdown for Telegram formatting.
- **Same stack as Brain** — Node.js + Express. Easy to maintain, deploy, and integrate.
