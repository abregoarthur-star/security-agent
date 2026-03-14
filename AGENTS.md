# Security Agent — Parallel Build Coordination

## Active Build: Bounty Pipeline (`src/bounty-pipeline.js`)

### Status: COMPLETE

### Architect: Claude instance in `/Users/arthur/trader-agent` (Arthur's main session)
### Builder: Claude instance in `/Users/arthur/security-agent` (this terminal)

---

## Communication Protocol

**Builder** writes questions/blockers here under `## Questions for Architect`.
**Architect** checks this file periodically and answers under `## Architect Answers`.

When build is complete, Builder sets Status to `COMPLETE` and lists what was built.

---

## Build Spec: Bounty Pipeline Module

### New File: `src/bounty-pipeline.js`

**Purpose:** When a high-scoring bounty match is detected (score >= 70), automatically:
1. Build a research package (passive recon + PoC gathering)
2. Draft a submission-ready bug bounty report
3. Deliver both to Telegram as a ready-to-act package

### Architecture

```
High-score match (>=70) from bounty-manager.js
        │
        ▼
  buildResearchPackage(env, match, program)
        │
        ├── Pull full CVE disclosure details (NVD API)
        ├── Search for PoCs (GitHub search, Sploitus, CVE references)
        ├── Extract: affected versions, prerequisites, exploit conditions
        ├── Passive recon on target:
        │     ├── Check program's public GitHub repos (if any)
        │     ├── HTTP headers / tech fingerprinting (if URL in scope)
        │     ├── Public docs / blog posts for tech stack clues
        │     └── Job postings for tech stack signals (nice-to-have)
        ├── Output: researchPackage object
        │
        ▼
  draftBountyReport(env, match, program, researchPackage)
        │
        ├── Call Opus 4.6 with all context
        ├── Generate structured report following program's platform format:
        │     ├── email (Railway, independent programs)
        │     ├── hackerone (HackerOne template)
        │     ├── bugcrowd (Bugcrowd template)
        │     └── intigriti (Intigriti template)
        ├── Include: title, severity, CVSS justification, description,
        │            reproduction steps, impact, remediation, references
        ├── Output: draftReport object
        │
        ▼
  formatBountyPackage(match, program, researchPackage, draftReport)
        │
        └── Telegram-formatted ready-to-act message
```

### Functions to Export

```javascript
// Main entry point — called from index.js when match score >= 70
export async function runBountyPipeline(env, match, program)
// Returns: { researchPackage, draftReport, telegramMessage }

// Sub-functions (exported for testing/direct use)
export async function buildResearchPackage(env, match, program)
export async function draftBountyReport(env, match, program, researchPackage)
export function formatBountyPackage(match, program, researchPackage, draftReport)
```

### Research Package Schema
```javascript
{
  cveId: 'CVE-2026-XXXX',
  programId: 'railway',

  // Disclosure details
  disclosure: {
    description: 'Full NVD description',
    affectedVersions: ['1.0-2.3'],
    affectedProducts: ['product CPE strings'],
    prerequisites: ['AppArmor enabled', 'kernel 5.15+'],
    exploitConditions: 'Requires local container access',
    references: [{ url, source, type }],
  },

  // PoC intelligence
  pocs: [
    { source: 'github', url: '...', language: 'python', description: '...' },
    { source: 'sploitus', url: '...', description: '...' },
  ],

  // Passive recon on target
  targetRecon: {
    confirmedTech: ['docker', 'kubernetes'],     // from public sources
    inferredTech: ['apparmor'],                   // educated guess
    publicRepos: ['github.com/railwayapp/cli'],   // OSS repos found
    techClues: ['Blog post mentions K8s migration', 'Job posting: Senior K8s Engineer'],
    versionHints: [],                              // any version info found
    exposedEndpoints: [],                          // public URLs checked
  },

  // Assessment
  exploitability: {
    score: 0-100,
    rationale: 'Why this is/isn't exploitable against this target',
    applicablePoCs: 1,                            // how many PoCs could work
    targetLikelyVulnerable: true/false,
    confidence: 'high' | 'medium' | 'low',
  },

  generatedAt: ISO timestamp,
}
```

### Report Draft Schema
```javascript
{
  format: 'email' | 'hackerone' | 'bugcrowd' | 'intigriti',

  // Report content
  title: 'Container Isolation Bypass via AppArmor Profile Escape',
  severity: 'Critical',
  cvssScore: 9.0,
  cvssVector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',

  summary: '2-3 sentence executive summary',
  description: 'Detailed technical description',
  reproductionSteps: ['Step 1...', 'Step 2...'],
  impact: 'What an attacker could achieve',
  remediation: 'Recommended fix',
  references: [{ title, url }],

  // Platform-specific
  emailBody: 'Full formatted email text (for independent programs)',
  hackeroneMarkdown: 'HackerOne-formatted report (if applicable)',

  // Meta
  estimatedBounty: '$5,000 - $15,000',
  duplicateRisk: 'low' | 'medium' | 'high',
  duplicateRationale: 'Why this may/may not already be reported',

  generatedAt: ISO timestamp,
}
```

### Integration Points

**In `src/index.js`** — after existing Opus analysis in the cron:
```javascript
// After matchCVEsToPrograms() and analyzeMatch()...
// For high-scoring matches, run the full pipeline
if (match.score >= 70) {
  const pipeline = await runBountyPipeline(env, match, program);
  if (pipeline.telegramMessage) {
    await sendMessage(CHAT_ID, pipeline.telegramMessage);
  }
}
```

**In `src/telegram.js`** — new command `/pipeline [cveId] [programId]`:
- Manually trigger the pipeline for any CVE × program combo
- Useful when you want to run it on a match that scored below 70

### Opus Prompt for Report Drafting

Use the existing `callOpus()` pattern from `bounty-manager.js`. The prompt should include:
- Full CVE details + research package
- Program scope, tech stack, submission requirements
- Platform-specific format instructions
- Emphasis on: clear reproduction steps, accurate CVSS, realistic impact, professional tone

### Telegram Output Format

```
🔴 BOUNTY PIPELINE — {CVE-ID} x {Program Name}

📊 Match Score: {score}/100 | Severity: {severity}
💰 Est. Payout: {estimatedBounty}
⚡ Duplicate Risk: {duplicateRisk}

🔬 RESEARCH PACKAGE
Tech Match: {confirmedTech}
Target Likely Vulnerable: {yes/no} ({confidence})
PoCs Found: {count} ({sources})
Key Prerequisites: {prerequisites}

📝 DRAFT REPORT
Title: {title}
CVSS: {cvssScore} ({cvssVector})
Format: {platform} ({email/hackerone/etc})

[Full report below ⬇️]
---
{emailBody or hackeroneMarkdown}
---

⏳ YOUR TODO:
1. Reproduce locally
2. Review & tweak the report above
3. Submit to {submitTo}
4. /submit {cveId} {programId}
```

The full report may need to be split across multiple Telegram messages (4096 char limit).

### Important Notes

- **No active exploitation.** All recon is passive — public sources only.
- **Respect rate limits.** NVD: 5 req/30s without API key. GitHub search: 10 req/min unauthenticated, 30/min with token.
- **Opus calls are expensive.** Only one Opus call per pipeline run (the report draft). Research package is assembled from free APIs.
- **Use `env.GITHUB_TOKEN`** for GitHub search API (already set on Railway).
- **HTML escape** all dynamic text in Telegram messages using the `esc()` helper from `index.js` (or define your own).
- **Split long messages** — Telegram has a 4096 char limit. Split the report into chunks if needed.
- **Follow existing code patterns** — Look at `bounty-manager.js` and `intel.js` for the codebase style (JSDoc, async/await, error handling).

### Files to Read First
1. `src/bounty-manager.js` — program schema, matching, `callOpus()` pattern, `analyzeMatch()`
2. `src/index.js` — cron flow, route pattern, `esc()` helper, `sendMessage()` usage
3. `src/intel.js` — feed polling patterns, NVD API usage
4. `src/telegram.js` — command handler pattern, message formatting
5. `CLAUDE.md` — full project context

---

## Questions for Builder
(Architect posts questions here)

## Builder Answers
(Builder responds here)

## Questions for Architect
(Builder posts questions/blockers here)

## Architect Answers
(Architect responds here)

## Build Log

### Build Complete — March 14, 2026

**What was built:**

1. **`src/bounty-pipeline.js`** (783 lines) — Full bounty pipeline module
   - `runBountyPipeline(env, match, program)` — Main entry point, orchestrates research + report + formatting
   - `buildResearchPackage(env, match, program)` — Parallel research: NVD disclosure details, GitHub PoC search, Sploitus search, passive recon (HTTP headers, public repos, tech inference), exploitability assessment (0-100 score)
   - `draftBountyReport(env, match, program, researchPackage)` — Opus 4.6 report drafting with platform-specific formats (email/hackerone/bugcrowd/intigriti), fallback report when API unavailable
   - `formatBountyPackage(match, program, researchPackage, draftReport)` — Telegram-formatted output with header, research summary, draft report body, TODO footer. Splits long reports across multiple messages (4096 char limit)
   - Helper functions: `fetchDisclosureDetails`, `searchGitHubPoCs`, `searchSploitus`, `runPassiveRecon`, `checkHttpHeaders`, `assessExploitability`, `extractPrerequisites`, `extractExploitConditions`, `inferTechFromContext`, `splitMessage`, `esc`

2. **`src/index.js` integration** (lines 254-271) — Already integrated
   - After `analyzeMatch()` for score >= 70, runs `runBountyPipeline()`
   - Handles array of Telegram messages (multi-message split)
   - Error handling with console logging

3. **`src/telegram.js` — `/pipeline` command handler** (added `handlePipeline` function)
   - Usage: `/pipeline CVE-2026-XXXX program_id`
   - Validates program exists, looks up existing match or creates minimal one from NVD
   - Shows recent top matches as suggestions when called without args
   - Sends progress message, then delivers full pipeline output
   - Error handling with user-facing error messages

**All syntax checks passed.** No new dependencies required.
