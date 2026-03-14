# Security Agent — Parallel Build Coordination

## Active Build: Bounty Report Push to Brain

### Status: COMPLETE

### Architect: Claude instance in `/Users/arthur/trader-agent` (Arthur's main session)
### Builder: Claude instance in `/Users/arthur/security-agent` (this terminal)

---

## Build Spec: Push Bounty Reports to Brain

### What to Build

When the bounty pipeline (`bounty-pipeline.js`) generates a report, push it to the Brain's new endpoint so Arthur can review/edit/approve from the Brain dashboard.

### Changes Required

#### 1. New function in `src/bounty-pipeline.js`

Add `pushReportToBrain(env, match, program, researchPackage, draftReport)`:

```javascript
async function pushReportToBrain(env, match, program, researchPackage, draftReport) {
  const brainUrl = process.env.BRAIN_API_URL;
  const brainKey = process.env.BRAIN_API_KEY;
  if (!brainUrl || !brainKey) {
    console.log('[PIPELINE] No Brain URL/key — skipping report push');
    return null;
  }

  const report = {
    id: `br_${Date.now()}`,
    cveId: match.cveId,
    programId: program.id,
    programName: program.name,
    platform: program.platform,
    submitTo: program.submitTo || program.url,
    score: match.score,
    severity: draftReport.severity,
    cvssScore: draftReport.cvssScore,
    cvssVector: draftReport.cvssVector,
    title: draftReport.title,
    summary: draftReport.summary,
    description: draftReport.description,
    reproductionSteps: draftReport.reproductionSteps,
    impact: draftReport.impact,
    remediation: draftReport.remediation,
    references: draftReport.references,
    emailBody: draftReport.emailBody,
    hackeroneMarkdown: draftReport.hackeroneMarkdown,
    estimatedBounty: draftReport.estimatedBounty,
    duplicateRisk: draftReport.duplicateRisk,
    duplicateRationale: draftReport.duplicateRationale,
    format: draftReport.format,
    // Research context
    researchSummary: {
      pocsFound: researchPackage.pocs.length,
      pocSources: researchPackage.pocs.map(p => p.source),
      confirmedTech: researchPackage.targetRecon.confirmedTech,
      exploitabilityScore: researchPackage.exploitability.score,
      exploitabilityConfidence: researchPackage.exploitability.confidence,
      targetLikelyVulnerable: researchPackage.exploitability.targetLikelyVulnerable,
    },
    status: 'pending',  // pending | editing | submitted | acknowledged | accepted | paid | rejected
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    submittedAt: null,
  };

  try {
    const res = await fetch(`${brainUrl}/bounty/reports`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': brainKey,
      },
      body: JSON.stringify(report),
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      console.error(`[PIPELINE] Brain push failed: ${res.status}`);
      return null;
    }

    console.log(`[PIPELINE] Report pushed to Brain: ${report.id}`);
    return report;
  } catch (err) {
    console.error(`[PIPELINE] Brain push error:`, err.message);
    return null;
  }
}
```

#### 2. Call it from `runBountyPipeline()`

In the `runBountyPipeline` function, after building the research package and draft report, add:

```javascript
// Push to Brain for review/edit/approve
await pushReportToBrain(env, match, program, researchPackage, draftReport);
```

Add it right before the `formatBountyPackage` call (or after, doesn't matter — it's non-blocking to the Telegram flow).

#### 3. Also call it from `handlePipeline()` in telegram.js

When the user manually triggers `/pipeline`, the report should also be pushed to Brain. After the pipeline runs successfully in `handlePipeline()`, add:

```javascript
// Note: pushReportToBrain is internal to bounty-pipeline.js,
// so this is already handled if you add the call inside runBountyPipeline()
```

Actually — since the push happens inside `runBountyPipeline()`, the Telegram handler doesn't need changes. It just works.

### Brain Endpoint

The Brain will accept reports at:
```
POST /bounty/reports  — Create new report (from Security Agent)
```

Auth: `x-api-key` header (same BRAIN_API_KEY pattern)

### Testing

After building, verify:
1. `node --check src/bounty-pipeline.js` passes
2. `node --check src/index.js` passes
3. The push is non-blocking — if Brain is down, pipeline still sends Telegram alerts

### Important Notes

- Don't break existing Telegram delivery — the push to Brain is IN ADDITION to Telegram
- The push should be fire-and-forget — don't let Brain failures block the pipeline
- Use `process.env.BRAIN_API_URL` and `process.env.BRAIN_API_KEY` (already set on Railway)
- Follow existing code patterns (JSDoc, error handling, console logging with [PIPELINE] prefix)

### Files to Read First
1. `src/bounty-pipeline.js` — current pipeline, where to add the push
2. `src/brain-intel.js` (if it exists) or check how other modules call the Brain API

---

## Questions for Architect
(Builder posts questions here)

## Architect Answers
(Architect responds here)

## Build Log

### Build Complete — March 14, 2026

**Changes made to `src/bounty-pipeline.js`:**

1. Added `pushReportToBrain()` function — pushes full report payload (CVE details, draft report, research summary) to `POST /bounty/reports` on the Brain. Fire-and-forget with 10s timeout. Logs success/failure with `[PIPELINE]` prefix.

2. Called `pushReportToBrain()` from `runBountyPipeline()` — inserted between `draftBountyReport()` and `formatBountyPackage()`. Brain push happens before Telegram formatting. Brain failures don't block Telegram delivery.

**No changes needed to `telegram.js`** — `/pipeline` command calls `runBountyPipeline()` which now includes the Brain push automatically.

**Verified:** `node --check` passes on both `bounty-pipeline.js` and `index.js`.
