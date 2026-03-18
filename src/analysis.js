/**
 * AI-Powered Threat Analysis — Opus 4.6
 *
 * This is for making money. We use the best model available
 * to produce institutional-grade threat intelligence.
 *
 * Opus 4.6 analyzes:
 * - CVE landscape for bug bounty opportunities
 * - Exploit availability and weaponization risk
 * - Attack surface trends across industries
 * - Which vulns to write Nuclei templates for
 * - SMB monitoring priorities
 */

import { readJSON, createDebouncedWriter } from './store.js';

const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';

const savedAnalysis = readJSON('analysis.json', null);
let latestAnalysis = savedAnalysis?.latest || null;
let analysisHistory = savedAnalysis?.history || [];
const scheduleSaveAnalysis = createDebouncedWriter('analysis.json', 5000);

if (latestAnalysis) {
  console.log(`[ANALYSIS] Loaded ${analysisHistory.length} analysis entries from disk`);
}

/**
 * Run Opus 4.6 threat landscape analysis.
 */
export async function runAnalysis() {
  const { getCVEStats, getRecentCritical, getBountyRelevantCVEs, getRecentExploits, getSecurityNews } = await import('./intel.js');

  const stats = getCVEStats();
  const critical = getRecentCritical();
  const bountyRelevant = getBountyRelevantCVEs();
  const exploits = getRecentExploits();
  const news = getSecurityNews();

  if (stats.totalTracked === 0) {
    console.log('No CVE data yet, skipping analysis');
    return null;
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.log('No ANTHROPIC_API_KEY, skipping analysis');
    return null;
  }

  // Build comprehensive context
  const cveContext = critical.slice(0, 20).map(c =>
    `${c.id} (CVSS: ${c.cvss || '?'}, ${c.severity || '?'}) — ${c.description?.slice(0, 250) || 'No description'}` +
    `${c.cisaKEV ? ' [ACTIVELY EXPLOITED - CISA KEV]' : ''}` +
    `${c.exploitAvailable ? ' [EXPLOIT AVAILABLE]' : ''}` +
    `${c.bountyRelevant ? ' [BOUNTY RELEVANT]' : ''}` +
    `${c.attackVector ? ` [${c.attackVector}]` : ''}` +
    `${c.weaknesses?.length ? ` [${c.weaknesses.join(', ')}]` : ''}`
  ).join('\n\n');

  const bountyContext = bountyRelevant.slice(0, 10).map(c =>
    `${c.id} (CVSS: ${c.cvss}) — ${c.description?.slice(0, 150)}` +
    `${c.weaknesses?.length ? ` | Weaknesses: ${c.weaknesses.join(', ')}` : ''}`
  ).join('\n');

  const exploitContext = exploits.slice(0, 10).map(e =>
    `${e.title}${e.cveId ? ` (${e.cveId})` : ''} — ${e.source}`
  ).join('\n');

  const newsContext = news.slice(0, 10).map(n =>
    `${n.title} — ${n.source}`
  ).join('\n');

  const res = await fetch(ANTHROPIC_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2048,
      system: `You are an elite cybersecurity threat analyst and bug bounty strategist running an autonomous security intelligence operation. Your analysis directly drives revenue through:

1. BUG BOUNTY HUNTING — Identify which new CVEs can be turned into bounty reports. Focus on web-facing vulnerabilities (XSS, SQLi, SSRF, auth bypass, RCE) in software used by companies with active bounty programs.

2. EXPLOIT WEAPONIZATION — Track which CVEs have public exploits. These are highest priority — if an exploit exists, targets are vulnerable NOW and need to be scanned immediately.

3. NUCLEI TEMPLATE OPPORTUNITIES — Identify CVEs where we should write custom Nuclei templates before the community does. First-to-scan advantage = first-to-find = bounty is ours.

4. SMB MONITORING PRIORITIES — Which vulnerabilities affect common SMB stacks (WordPress, Shopify, AWS, Azure, GCP, nginx, Apache)? These drive our SaaS monitoring product.

5. ATTACK SURFACE TRENDS — What attack vectors are trending? Where should we focus scanning resources?

6. ZERO-DAY AWARENESS — Track actively exploited vulns (CISA KEV). These represent the highest-severity threats and generate the most valuable intelligence for customers.

Think like a hedge fund PM but for cybersecurity. Every CVE is a potential revenue opportunity.

Respond in JSON only:
{
  "alertLevel": "low|medium|high|critical",
  "summary": "3-5 sentence executive summary of the threat landscape",
  "threats": ["specific active threat with affected products"],
  "bountyOpportunities": [
    {"cveId": "CVE-xxx", "target": "what to scan", "estimatedBounty": "$500-$5000", "difficulty": "low|medium|high", "strategy": "how to find this in the wild"}
  ],
  "nucleiTemplatePriority": ["CVE to write template for — reason"],
  "smbAlerts": ["what SMB customers need to patch NOW"],
  "exploitWatch": ["newly weaponized vulns to monitor"],
  "affectedSectors": ["sector: specific impact"],
  "attackTrends": ["trending attack vector or technique"],
  "recommendations": ["specific action item"],
  "marketIntel": "one sentence on how this affects the cybersecurity market/stocks"
}`,
      messages: [{
        role: 'user',
        content: `THREAT INTELLIGENCE BRIEFING — ${new Date().toISOString()}

CVE STATS:
• Total tracked: ${stats.totalTracked}
• Critical (24h): ${stats.critical24h}
• High (24h): ${stats.high24h}
• Bounty-relevant: ${stats.bountyRelevant24h}
• Exploits available: ${stats.exploitsAvailable}
• CISA KEV catalog: ${stats.kevTotal} total, ${stats.kevNew} new today
• GitHub advisories: ${stats.ghAdvisoryCount}

CRITICAL/HIGH CVEs:
${cveContext || 'No critical CVEs in the last 24 hours.'}

BOUNTY-RELEVANT CVEs:
${bountyContext || 'None identified.'}

RECENT EXPLOITS (Exploit-DB + PacketStorm):
${exploitContext || 'No new exploits.'}

SECURITY NEWS:
${newsContext || 'No recent news.'}`,
      }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude API failed: ${res.status} — ${err}`);
  }

  const result = await res.json();
  const text = result.content?.[0]?.text || '{}';

  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error('No JSON in response');
    const parsed = JSON.parse(jsonMatch[0]);

    latestAnalysis = {
      ...parsed,
      timestamp: new Date().toISOString(),
      model: 'claude-sonnet-4-20250514',
      inputTokens: result.usage?.input_tokens,
      outputTokens: result.usage?.output_tokens,
    };

    // Keep analysis history (last 24 entries = 24 hours at hourly)
    analysisHistory.push(latestAnalysis);
    if (analysisHistory.length > 24) analysisHistory.shift();
    scheduleSaveAnalysis({ latest: latestAnalysis, history: analysisHistory });

    return latestAnalysis;
  } catch (err) {
    console.error('Failed to parse analysis:', err.message, text.slice(0, 200));
    return null;
  }
}

/**
 * Get the most recent threat analysis.
 */
export function getLatestAnalysis() {
  return latestAnalysis;
}

/**
 * Get analysis history (last 24 hours).
 */
export function getAnalysisHistory() {
  return analysisHistory;
}
