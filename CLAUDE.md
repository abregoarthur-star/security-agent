# Uber Security Agent

## Overview
Autonomous AI security intelligence agent that continuously monitors vulnerability databases, analyzes threat landscapes, and delivers actionable security alerts via Telegram. Runs on Railway alongside the DJ Abstract AI Brain.

**Bot:** @UberSecurityBot on Telegram (pending BotFather setup)
**Hosting:** Railway (same Hobby plan as the Brain)
**Cost:** ~$0-3/month (shares Railway, free APIs, Claude Haiku for analysis)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              INTELLIGENCE FEEDS (Free)               │
│                                                      │
│  NVD ─────── 337K+ CVEs, CVSS scores, CPE matching  │
│  CISA KEV ── Actively exploited vulnerabilities      │
│  OSV.dev ─── Open-source package vulnerabilities     │
│  GitHub ──── Security advisories (OSV format)        │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│           SECURITY AGENT (Railway)                    │
│                                                      │
│  index.js ──> intel.js      (CVE feed polling)       │
│           ──> analysis.js   (Claude Haiku triage)    │
│           ──> findings.js   (finding store)          │
│           ──> telegram.js   (bot + alerts)           │
└───────────────────────┬──────────────────────────────┘
                        │
                   Telegram ──> Arthur's phone
```

## Cron Schedule

| Pattern | Frequency | Purpose |
|---------|-----------|---------|
| `*/15 * * * *` | Every 15 min | Poll NVD, CISA KEV, OSV.dev for new CVEs |
| `0 * * * *` | Every hour | Claude Haiku threat landscape analysis |
| `0 13 * * *` | 8:00 AM ET daily | Daily security briefing |

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome + capabilities |
| `/status` | Feed health, CVE count, uptime |
| `/stats` | CVE statistics (24h/7d) |
| `/critical` | Recent critical CVEs |
| `/cve [ID]` | Look up specific CVE |
| `/threats` | Current threat landscape |
| `/scan [domain]` | Basic security header check |
| `/chatid` | Show chat ID |
| `/help` | All commands |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | From @BotFather |
| `TELEGRAM_CHAT_ID` | Default alert chat |
| `ANTHROPIC_API_KEY` | Claude API key |
| `BRAIN_API_URL` | Brain production URL |
| `BRAIN_API_KEY` | Shared API key for Brain intel |
| `NVD_API_KEY` | Optional — higher rate limits |
| `PORT` | Server port (Railway assigns) |

## File Structure

```
security-agent/
├── package.json
├── Dockerfile
├── CLAUDE.md
├── .gitignore
├── .env.example
└── src/
    ├── index.js      # Express server + cron jobs + startup
    ├── telegram.js   # Bot commands + alerts (HTML parse mode)
    ├── intel.js      # CVE feed polling (NVD, CISA KEV, OSV)
    ├── analysis.js   # Claude Haiku threat analysis
    └── findings.js   # Finding store (in-memory, future: disk)
```

## Future Phases (all on Railway)

1. **Nuclei Scanning** — Docker-based vuln scanning against targets
2. **Recon Pipeline** — subfinder + httpx for asset discovery
3. **Bug Bounty** — HackerOne scope parsing + automated report drafts
4. **SMB Monitoring** — Customer domains + scheduled scans
5. **Brain Integration** — /intel/security endpoint for cross-agent intelligence

## Development

```bash
npm install
npm run dev       # Watch mode
npm start         # Production

# Deploy: push to main → Railway auto-deploys
```
