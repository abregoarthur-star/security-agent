/**
 * AI-Powered Threat Analysis
 *
 * Uses Claude Haiku to analyze the current CVE landscape
 * and generate actionable threat intelligence.
 */

const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';

let latestAnalysis = null;

/**
 * Run Claude-powered threat landscape analysis.
 */
export async function runAnalysis() {
  const { getCVEStats, getRecentCritical } = await import('./intel.js');

  const stats = getCVEStats();
  const critical = getRecentCritical();

  if (critical.length === 0 && stats.totalTracked === 0) {
    console.log('No CVE data yet, skipping analysis');
    return null;
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.log('No ANTHROPIC_API_KEY, skipping analysis');
    return null;
  }

  const cveContext = critical.slice(0, 15).map(c =>
    `${c.id} (CVSS: ${c.cvss || '?'}) — ${c.description?.slice(0, 200) || 'No description'}${c.cisaKEV ? ' [CISA KEV]' : ''}${c.exploitAvailable ? ' [EXPLOIT]' : ''}`
  ).join('\n');

  const res = await fetch(ANTHROPIC_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-haiku-4-5-20241022',
      max_tokens: 512,
      system: `You are a senior cybersecurity threat analyst. Analyze CVE data and produce actionable intelligence.

Focus on:
1. Which vulnerabilities pose the highest real-world risk RIGHT NOW
2. Active exploitation trends (CISA KEV additions = actively exploited)
3. Supply chain implications (popular libraries/frameworks affected)
4. Sector-specific impact (which industries should patch urgently)
5. Defensive recommendations

Respond in JSON only:
{
  "alertLevel": "low|medium|high|critical",
  "summary": "2-3 sentence executive summary",
  "threats": ["specific threat 1", "threat 2", "threat 3"],
  "affectedSectors": ["sector1", "sector2"],
  "recommendations": ["action1", "action2", "action3"],
  "exploitTrends": "one sentence on current exploit trends"
}`,
      messages: [{
        role: 'user',
        content: `Analyze today's vulnerability landscape:

CVE Stats: ${stats.totalTracked} tracked, ${stats.critical24h} critical in 24h, ${stats.kevTotal} in CISA KEV catalog

Recent Critical CVEs:
${cveContext || 'No critical CVEs in the last 24 hours.'}`,
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
    };

    return latestAnalysis;
  } catch (err) {
    console.error('Failed to parse analysis:', err.message);
    return null;
  }
}

/**
 * Get the most recent threat analysis.
 */
export function getLatestAnalysis() {
  return latestAnalysis;
}
