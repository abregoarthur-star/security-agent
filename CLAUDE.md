# Security Agent v2.2

## Overview
Autonomous AI security intelligence agent powered by Claude Opus 4.6. Monitors 15 vulnerability databases and exploit feeds, scores CVEs against 16 bug bounty programs, **validates targets with passive testing**, generates evidence-backed bounty reports, and delivers actionable alerts via Telegram.

**Bot:** @UberSecurityBot on Telegram
**Hosting:** Railway (Hobby plan)
**Model:** Claude Opus 4.6 (analysis + report drafting)
**Feeds:** 15 intelligence sources, all free
**Programs:** 16 bounty programs (Railway, Google, Microsoft, Apple, Immunefi, etc.)

## Revenue Model
1. **Bug Bounties** — Automated CVE-to-program matching + priority scoring + report drafting. First to find = first to report = first to get paid.
2. **SMB Monitoring** — Curated vulnerability alerts for business customers ($49-$349/mo)
3. **Intelligence Feeds** — Premium threat intelligence delivery ($29-$199/mo)

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│              INTELLIGENCE FEEDS (15, all free)                    │
│                                                                   │
│  NVD ──────────── 337K+ CVEs, CVSS scores, CWE, CPE             │
│  CISA KEV ─────── Actively exploited in the wild                  │
│  OSV.dev ──────── npm, PyPI, Go, Rust, Maven, NuGet, Ruby        │
│  GitHub ────────── Security advisories (reviewed, with CVSS)      │
│  Exploit-DB ───── New exploits as they drop (RSS)                 │
│  Sploitus ─────── Exploit aggregator (replaced PacketStorm)       │
│  The Hacker News  Security news for context (RSS)                 │
│  Nuclei Templates Latest detection templates (GitHub API)         │
│  InTheWild ────── Exploited-in-the-wild tracker (API)             │
│  VulDB ─────────── Recent vulnerability database (RSS)            │
│  oss-security ──── Full disclosure mailing list (seclists.org)    │
│  FullDisclosure ── Vulnerability disclosures (seclists.org)       │
│  Bugtraq ──────── Classic vuln mailing list (seclists.org)        │
│  OpenCVE ──────── CVE change notifications (RSS)                  │
│  CERT/CC ──────── US-CERT vulnerability notes (RSS)               │
└────────────────────────────┬─────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────┐
│              SECURITY AGENT v2.2 (Railway)                        │
│                                                                   │
│  index.js ──────── Express server + 3 crons + API routes          │
│  intel.js ──────── 15-feed polling engine + CVE store + scoring   │
│  bounty-manager.js  16 programs, matching engine, submissions     │
│  bounty-pipeline.js PoC research + validation + report + Brain    │
│  bounty-testing.js  Passive validation + Nuclei detection engine  │
│  analysis.js ───── Opus 4.6 threat analysis + bounty strategy     │
│  underground.js ── Alt feeds (InTheWild, VulDB, oss-sec, etc.)    │
│  findings.js ───── Finding store (in-memory)                      │
│  hackerone.js ──── HackerOne API sync                             │
│  telegram.js ───── 20 commands + alert formatting                 │
└────────────────────────────┬─────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         Telegram       Brain API      Submissions
         Alerts        /intel/*        Tracker
```

## Cron Schedule

**STATUS: PARTIALLY PAUSED (March 19, 2026)** — Opus/Sonnet API calls and Telegram alerts disabled to stop API charges while automation pipeline is incomplete. Feed polling and bounty matching still run (free). To re-enable: search `[PAUSED]` comments in `src/index.js` and uncomment.

| Pattern | Frequency | Purpose | Status |
|---------|-----------|---------|--------|
| `*/5 * * * *` | Every 5 min | Poll 15 feeds + bounty matching (free, no API) | **ACTIVE** |
| `0 * * * *` | Every hour | Opus/Sonnet threat + exploit analysis | **PAUSED** |
| `0 13 * * *` | 8:00 AM ET | Daily security briefing (Telegram) | **PAUSED** |
| `0 17 * * *` | 9:00 AM PT | HackerOne program sync (HTTP only) | **ACTIVE** |

### What's paused (to re-enable, search `[PAUSED]` in index.js):
- Telegram alerts for new critical CVEs and PoC exploits
- Opus analysis + bounty pipeline auto-trigger on high-score matches (>= 85)
- Hourly Sonnet threat analysis + Opus exploit deep-dive
- Daily security briefing Telegram message

### What's still running (zero cost):
- 15-feed polling every 5 min (data accumulates silently)
- Bounty matching engine (local scoring, no API)
- HackerOne sync (HTTP only)
- All manual Telegram commands (`/test`, `/pipeline`, `/status`, etc.)

### 5-Minute Cron Flow (current — paused items crossed out)
```
Poll CVE feeds (intel.js) ──► 15 feeds, deduplicated
         │
         ▼
Poll underground feeds (underground.js) ──► InTheWild, VulDB, oss-sec, etc.
         │
         ▼
Match CVEs to programs (bounty-manager.js) ──► local scoring only
         │
         ├── ~~Score >= 70 → Telegram alert~~ [PAUSED]
         ├── ~~Score >= 85 → Opus analysis + bounty pipeline~~ [PAUSED]
         │
         ▼
Cache results in memory (available via /matches, /stats, /critical)
```

## Intelligence Feeds (15)

| Feed | Data | Source | Notes |
|------|------|--------|-------|
| **NVD** | CVEs, CVSS, CWE, CPE | `services.nvd.nist.gov` | 24h lookback on first poll, 2h after |
| **CISA KEV** | Actively exploited vulns | `cisa.gov` | Highest priority |
| **OSV.dev** | Package vulns (8 ecosystems) | `osv.dev` | Supply chain |
| **GitHub Advisories** | Reviewed advisories + CVSS | `api.github.com` | Requires GITHUB_TOKEN |
| **Exploit-DB** | New exploits | `exploit-db.com/rss.xml` | Weaponization tracking |
| **Sploitus** | Exploit aggregator | `sploitus.com/rss` | Replaced PacketStorm |
| **The Hacker News** | Security news | `feeds.feedburner.com` | Threat context |
| **Nuclei Templates** | Detection templates | `api.github.com` | Requires GITHUB_TOKEN |
| **InTheWild** | Exploited-in-the-wild | `inthewild.io/api` | Confirmed exploitation |
| **VulDB** | Recent vulns | `vuldb.com` | RSS feed |
| **oss-security** | Full disclosure | `seclists.org/rss/oss-sec.rss` | Mailing list mirror |
| **FullDisclosure** | Vuln disclosures | `seclists.org` | Mailing list |
| **Bugtraq** | Classic vuln list | `seclists.org` | Mailing list |
| **OpenCVE** | CVE change notifications | `opencve.io` | RSS |
| **CERT/CC** | US-CERT notes | `kb.cert.org` | RSS |

## Bounty Program Manager

### 16 Built-in Programs (3 Tiers)

**Tier 1 — High Payout:**
| Program | Platform | Max Bounty | Key Tech |
|---------|----------|-----------|----------|
| Google VRP | Independent | $150K | Chrome, Android, Cloud, GCP, Go |
| Microsoft MSRC | Independent | $100K | Windows, Azure, Office 365, .NET |
| Apple Security | Independent | $1M | iOS, macOS, WebKit, Safari, iCloud |
| Immunefi | Immunefi | $500K | DeFi, smart contracts, Solidity, bridges |

**Tier 2 — High Volume:**
| Program | Platform | Key Tech |
|---------|----------|----------|
| HackerOne Top 50 | HackerOne | Web apps, APIs, cloud, mobile |
| Bugcrowd Top 30 | Bugcrowd | Web apps, APIs, IoT, cloud |
| GitLab | HackerOne | Ruby, Rails, GraphQL, CI/CD, Docker |
| Shopify | HackerOne | Ruby, Rails, GraphQL, payments, Liquid |

**Tier 3 — Specialized:**
| Program | Platform | Key Tech |
|---------|----------|----------|
| Railway | Independent | Docker, K8s, Node, PostgreSQL, Redis |
| Alibaba | Independent | Cloud, Java, K8s, microservices |
| Veeam | Bugcrowd | Backup, Windows, .NET, VMware |
| Fortinet | Independent | FortiOS, FortiGate, VPN, firewall |
| Cisco | Bugcrowd | IOS, networking, VPN, Webex |
| WordPress | HackerOne | PHP, MySQL, plugins, themes |
| Docker | HackerOne | Docker Engine, containerd, runc |
| Redis | HackerOne | Redis, Lua, in-memory data |

### Priority Scoring (0-100)

| Factor | Weight | Logic |
|--------|--------|-------|
| Tech stack match | 30 | CVE description/CPE keywords vs program techStack |
| CWE relevance | 20 | Is CWE in program's high-value list? |
| CVSS score | 15 | Normalized: cvss / 10 × 15 |
| Exploit available | 15 | Has PoC or in CISA KEV? |
| Freshness | 10 | <24h = 10, <72h = 7, <7d = 4, else 0 |
| Competition level | 10 | Independent = 10, HackerOne/Bugcrowd = 5 |

### Submission Tracker
Status flow: `submitted → acknowledged → accepted → paid → rejected`
- Prevents duplicate reporting
- Tracks payout analytics per program
- Win rate, CWE skill breakdown, time-to-payout

## Bounty Pipeline (LIVE — March 15, 2026; Validation added March 16)

When a match scores >= 80, automatically runs the full pipeline:

1. **Research package** (`buildResearchPackage`) — Parallel fetches: NVD disclosure details, GitHub PoC search, Sploitus exploit search, passive recon (HTTP headers, public repos, tech inference), exploitability assessment (0-100)
2. **Passive validation** (`runPassiveValidation`) — 5 zero-risk tests against target: version fingerprinting, endpoint existence, technology confirmation, Shodan InternetDB lookup, CPE match verification. Returns confidence score (0-100) with label (confirmed/likely/uncertain/unlikely). Evidence captured for every test.
3. **Report draft** (`draftBountyReport`) — Opus 4.6 generates submission-ready report in program's format (email/HackerOne/Bugcrowd/Intigriti). Validation evidence injected into prompt so reports cite real findings. Falls back to structured template if API unavailable.
4. **Brain push** (`pushReportToBrain`) — Pushes full report + test results to Brain's `POST /bounty/reports` for review/edit/approve. Fire-and-forget (Brain failures don't block pipeline).
5. **Telegram delivery** (`formatBountyPackage`) — Ready-to-act package with VALIDATION section (confidence score + per-test results), research summary, and full report. Auto-splits across multiple messages (4096 char limit).

**Manual triggers:**
- `/pipeline CVE-2026-XXXX program_id` — full pipeline (research + validation + report)
- `/test CVE-2026-XXXX program_id` — validation only (fast, no Opus call)
- `/evidence matchId` — view full evidence and audit log for a test

**Human steps remaining:** review report + evidence (on Brain dashboard or Telegram), submit, `/submit CVE program`.

## Passive Validation Engine (LIVE — March 16, 2026)

**File:** `src/bounty-testing.js`

5 passive tests, zero risk, no payloads:

| Test | Points | Method |
|------|--------|--------|
| Version fingerprint | +30 (exact) / +15 (partial) | HTTP headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) + HTML `<meta generator>` vs CVE affected version ranges |
| Endpoint existence | +20 | HEAD requests to paths extracted from CVE description/references |
| Technology confirmation | +15 | Probe tech-specific paths (`/wp-login.php`, `/actuator/health`, `/__graphql`, etc.) |
| Shodan InternetDB | +10 | `https://internetdb.shodan.io/{ip}` — free, no API key, zero scanning |
| CPE match | +10 | NVD CPE entries vs detected tech stack overlap |

**Confidence labels:** 90+ confirmed, 70-89 likely, 50-69 uncertain, <50 unlikely

**Phase 2 (Nuclei detection):** Code ready in `runNucleiDetection()`. Requires Nuclei binary in Docker image (deferred — GitHub download URL needs fixing). Only runs info-severity templates, scope-validated, rate-limited (5 req/s), requires `safeHarbor: true`.

**Future phases:**
- Phase 3: Sandbox reproduction (Docker containers on separate VPS)
- Phase 4: Authorized active testing (human-approved, detection-only payloads)

## Telegram Commands (20)

| Command | Description |
|---------|-------------|
| `/start` | Welcome + capabilities |
| `/status` | Full agent status — feeds, model, programs, uptime |
| `/stats` | CVE statistics (24h) with bounty metrics |
| `/critical` | Recent critical/high CVEs with exploit + bounty flags |
| `/cve [ID]` | Detailed CVE lookup (local + NVD API) |
| `/threats` | Opus 4.6 threat landscape analysis |
| `/bounty` | Bug bounty opportunities + Nuclei template priorities |
| `/exploits` | Recent public exploits (Exploit-DB + Sploitus) |
| `/news` | Security news headlines (The Hacker News) |
| `/feeds` | Feed health dashboard with last poll times |
| `/scan [domain]` | Security header check with letter grade |
| `/programs` | List all 16 bounty programs with tech stacks and scope |
| `/matches [program]` | Top CVE matches scored by priority, optionally filtered |
| `/submit [cve] [program]` | Mark a CVE as submitted, prevents duplicate alerts |
| `/payouts` | Revenue analytics — earned, pending, win rate, skill breakdown |
| `/pipeline [cve] [program]` | Manually trigger bounty pipeline for any CVE × program combo |
| `/test [cve] [program]` | Run passive validation — version, endpoints, tech, Shodan, CPE |
| `/evidence [matchId]` | View full test evidence, per-test details, and audit log |
| `/chatid` | Show chat ID |
| `/help` | All commands |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | From @BotFather |
| `TELEGRAM_CHAT_ID` | Yes | Default alert chat |
| `ANTHROPIC_API_KEY` | Yes | Claude API (Opus 4.6) |
| `GITHUB_TOKEN` | Yes | GitHub Advisories + Nuclei Templates + PoC search |
| `BRAIN_API_URL` | No | Brain production URL |
| `BRAIN_API_KEY` | No | Shared API key for Brain intel |
| `NVD_API_KEY` | No | Higher NVD rate limits |
| `PORT` | No | Server port (Railway assigns) |

## File Structure

```
security-agent/
├── package.json
├── Dockerfile
├── CLAUDE.md          # This file
├── AGENTS.md          # Parallel build coordination
├── ARCHITECTURE.html  # Master architecture doc (unified design system, red accent)
├── .gitignore
├── .env.example
└── src/
    ├── index.js           # Express + 3 crons + API routes + alert formatters
    ├── intel.js           # 15-feed polling engine + CVE store + bounty scoring + RSS parser
    ├── bounty-manager.js  # 16 programs, matching engine, scoring, submissions, analytics
    ├── bounty-pipeline.js # PoC research + validation + Opus report + Brain push + Telegram
    ├── bounty-testing.js  # Passive validation engine (5 tests) + Nuclei detection (Phase 2)
    ├── analysis.js        # Opus 4.6 threat analysis + bounty strategy
    ├── exploit-analysis.js # CVE deep analysis + Nuclei template generation
    ├── underground.js     # Alt feeds: InTheWild, VulDB, oss-sec, FullDisclosure, Bugtraq, OpenCVE, CERT
    ├── findings.js        # Finding store (in-memory)
    ├── hackerone.js       # HackerOne API program sync
    └── telegram.js        # 20 commands + quick scan + HTML alerts
```

## API Routes

All routes behind `BRAIN_API_KEY` auth:

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/architecture` | Serves architecture doc (public, no auth) |
| `GET` | `/intel/security` | Full intel: stats, CVEs, analysis, bounty matches, programs, submissions |
| `GET` | `/intel/cve?q=` | CVE search (local + NVD fallback) |
| `GET` | `/intel/analysis` | Latest analysis + 24h history |
| `GET` | `/bounty/programs` | List all programs |
| `POST` | `/bounty/programs` | Add new program |
| `GET` | `/bounty/matches` | Top matches with scores |
| `GET` | `/bounty/matches/:programId` | Matches for specific program |
| `GET` | `/bounty/submissions` | Submission tracker |
| `GET` | `/bounty/test/results` | All validation test results |
| `GET` | `/bounty/test/:matchId` | Trigger validation for a specific match |

## Brain Integration

**Inbound (Brain pulls from Security Agent):**

The Brain calls `GET /intel/security` which returns:
```javascript
{
  stats, criticalCVEs, recentAnalysis, bountyOpportunities,
  recentExploits, recentNews,
  bountyPrograms,    // all active programs
  bountyMatches,     // top 10 scored matches
  submissions        // recent 10 submissions
}
```

The Brain's `security_intel` tool consumes this — no Brain code changes needed when we add features.

**Outbound (Security Agent pushes to Brain):**

The bounty pipeline pushes reports to `POST {BRAIN_API_URL}/bounty/reports` with `x-api-key` auth. Report payload includes full CVE details, draft report, research summary, and status tracking (`pending → editing → submitted → paid/rejected`). Arthur can review/edit/approve from the Brain dashboard.

## Key Design Decisions

- **Opus 4.6 for analysis + report drafting** — Best model produces best intelligence and professional bounty reports. Worth the cost.
- **15 feeds, all free** — Maximum coverage at zero data cost. Replaced dead feeds (PacketStorm → Sploitus, AttackerKB → VulDB, InTheWild GitHub → API).
- **5-minute polling** — Speed is money in bug bounties. First to find = first to report.
- **24h initial NVD poll** — On redeploy, first poll fetches 24h of CVEs to seed the in-memory store. Subsequent polls use 2h window.
- **6-factor priority scoring** — Not all CVEs are equal. Tech stack match, CWE, CVSS, exploit availability, freshness, and competition level.
- **One CVE, multiple programs** — A single CVE can match multiple programs. Each match is scored independently.
- **HTML parse mode** — More reliable than Markdown for Telegram. Use `esc()` helper for all dynamic text.
- **All in-memory** — Fast, simple, no database. Programs are code-defined, matches and submissions reset on redeploy.
- **Passive validation** — Bounty pipeline validates targets with read-only HTTP requests + public data (Shodan InternetDB). No payloads, no exploitation. Evidence-backed reports get paid.
- **Phased testing approach** — Phase 1 (passive) is live. Phase 2 (Nuclei detection) code-ready. Phase 3-4 (sandbox, active) are future.
- **Same stack as Brain** — Node.js + Express. Easy to maintain, deploy, and integrate.
- **Architecture doc** — Served at `/architecture` route (public, no auth). Also mirrored on GitHub Pages: `https://abregoarthur-star.github.io/agent-portfolio/`

## Development

```bash
npm install
npm run dev       # Watch mode (nodemon)
npm start         # Production
railway up        # Deploy to Railway
railway logs      # View logs
```

## Feed Reliability Notes

Some feeds have died and been replaced over time:
- **PacketStorm** → Replaced with **Sploitus** (domain moved, TOS wall)
- **AttackerKB** → Replaced with **VulDB** (CloudFront WAF blocking)
- **InTheWild** → Switched from GitHub raw JSON to **official API** (repo deleted)
- **oss-security** → Switched from Openwall to **seclists.org mirror** (Openwall removed RSS)

When a feed breaks, check for alternative mirrors/APIs before removing it. The `GITHUB_TOKEN` env var is required for GitHub Advisories and Nuclei Templates feeds.
