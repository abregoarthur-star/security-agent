/**
 * Bounty Program Manager — Scalable CVE-to-Program Matching
 *
 * Adding a new bounty program = adding a data entry.
 * Incoming CVEs are automatically matched against all programs' tech stacks.
 * One CVE can match multiple programs — that's a feature (multiple payouts).
 *
 * First to find + first to report = first to get paid.
 */

import { getBountyRelevantCVEs } from './intel.js';
import { getNewPOCs, getExploitedInWild } from './underground.js';

// ─── In-Memory Store ──────────────────────────────────────

let bountyStore = {
  programs: [],          // Program registry
  matches: [],           // CVE-to-program matches (scored)
  submissions: [],       // Submission tracking
  lastMatchRun: null,
};

// ─── Built-in Programs ────────────────────────────────────

const BUILT_IN_PROGRAMS = [
  {
    id: 'railway',
    name: 'Railway',
    platform: 'independent',
    url: 'https://railway.com/bug-bounty-program.pdf',
    submitTo: 'bugbounty@railway.com',
    techStack: [
      'node', 'docker', 'kubernetes', 'postgresql', 'redis', 'nginx',
      'graphql', 'rest', 'api', 'webhook', 'typescript', 'go', 'rust',
      'python', 'container', 'deploy', 'proxy', 'dns', 'ssl', 'tls',
    ],
    scope: {
      inScope: ['*.railway.app', 'railway.com', 'API endpoints', 'dashboard', 'CLI'],
      outOfScope: ['self-xss', 'rate-limiting', 'csv-injection', 'social-engineering', 'ddos'],
    },
    cweHighValue: [
      'CWE-79',   // XSS
      'CWE-89',   // SQL Injection
      'CWE-918',  // SSRF
      'CWE-287',  // Auth Bypass
      'CWE-284',  // Improper Access Control
      'CWE-502',  // Deserialization
      'CWE-78',   // OS Command Injection
      'CWE-22',   // Path Traversal
      'CWE-862',  // Missing Authorization
      'CWE-863',  // Incorrect Authorization
      'CWE-94',   // Code Injection
      'CWE-200',  // Information Exposure
    ],
    maxBounty: null,
    rewardsModel: 'cvss',
    safeHarbor: true,
    active: true,
    notes: 'CVSS 3.1 based rewards, paid within 30 days. Container escape / infra isolation bypass = highest value.',
    addedAt: '2026-03-14T00:00:00Z',
  },
];

// ─── Initialize ───────────────────────────────────────────

export function loadPrograms() {
  if (bountyStore.programs.length === 0) {
    bountyStore.programs = [...BUILT_IN_PROGRAMS];
    console.log(`[BOUNTY] Loaded ${bountyStore.programs.length} built-in programs`);
  }
  return bountyStore.programs;
}

// ─── Program CRUD ─────────────────────────────────────────

export function getPrograms(activeOnly = false) {
  if (activeOnly) return bountyStore.programs.filter(p => p.active);
  return bountyStore.programs;
}

export function getProgram(id) {
  return bountyStore.programs.find(p => p.id === id) || null;
}

export function addProgram(program) {
  // Validate required fields
  const required = ['id', 'name', 'platform', 'techStack'];
  for (const field of required) {
    if (!program[field]) throw new Error(`Missing required field: ${field}`);
  }

  // Prevent duplicate IDs
  if (bountyStore.programs.find(p => p.id === program.id)) {
    throw new Error(`Program '${program.id}' already exists`);
  }

  const entry = {
    scope: { inScope: [], outOfScope: [] },
    cweHighValue: [],
    maxBounty: null,
    rewardsModel: 'unknown',
    safeHarbor: false,
    active: true,
    notes: '',
    addedAt: new Date().toISOString(),
    ...program,
  };

  bountyStore.programs.push(entry);
  console.log(`[BOUNTY] Added program: ${entry.name} (${entry.id})`);
  return entry;
}

export function updateProgram(id, updates) {
  const program = bountyStore.programs.find(p => p.id === id);
  if (!program) throw new Error(`Program '${id}' not found`);

  // Don't allow changing the ID
  delete updates.id;
  Object.assign(program, updates);
  console.log(`[BOUNTY] Updated program: ${program.name}`);
  return program;
}

export function removeProgram(id) {
  const program = bountyStore.programs.find(p => p.id === id);
  if (!program) throw new Error(`Program '${id}' not found`);

  program.active = false;
  console.log(`[BOUNTY] Deactivated program: ${program.name}`);
  return program;
}

// ─── Matching Engine ──────────────────────────────────────

/**
 * Match bounty-relevant CVEs against all active programs.
 * One CVE can match multiple programs — multiple payouts.
 */
export function matchCVEsToPrograms() {
  const programs = getPrograms(true);
  if (programs.length === 0) return { newMatches: [], totalMatches: 0 };

  const cves = getBountyRelevantCVEs();
  const pocs = getNewPOCs();
  const wild = getExploitedInWild();

  // Build lookup sets for fast PoC/wild checks
  const pocCVEs = new Set(pocs.map(p => p.cveId).filter(Boolean));
  const wildCVEs = new Set(wild.map(w => w.cveId).filter(Boolean));

  // Existing match keys for dedup
  const existingKeys = new Set(bountyStore.matches.map(m => `${m.cveId}:${m.programId}`));

  const newMatches = [];

  for (const cve of cves) {
    for (const program of programs) {
      const key = `${cve.id}:${program.id}`;

      // Skip already-matched pairs
      if (existingKeys.has(key)) continue;

      // Skip if already submitted
      const alreadySubmitted = bountyStore.submissions.find(
        s => s.cveId === cve.id && s.programId === program.id
      );
      if (alreadySubmitted) continue;

      // Score the match
      const score = scoreCVEForProgram(cve, program, { pocCVEs, wildCVEs });

      // Only keep matches with meaningful relevance
      if (score.total >= 30) {
        const match = {
          id: `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          cveId: cve.id,
          programId: program.id,
          programName: program.name,
          score: score.total,
          breakdown: score,
          cve: {
            cvss: cve.cvss,
            severity: cve.severity,
            description: cve.description?.slice(0, 300),
            weaknesses: cve.weaknesses,
            exploitAvailable: cve.exploitAvailable,
            cisaKEV: cve.cisaKEV,
          },
          techOverlap: score.matchedKeywords,
          cweMatch: score.matchedCWEs,
          createdAt: new Date().toISOString(),
          analyzed: false,
        };

        newMatches.push(match);
        bountyStore.matches.push(match);
        existingKeys.add(key);
      }
    }
  }

  // Sort all matches by score (highest first)
  bountyStore.matches.sort((a, b) => b.score - a.score);

  // Prune old low-scoring matches (keep top 200)
  if (bountyStore.matches.length > 200) {
    bountyStore.matches = bountyStore.matches.slice(0, 200);
  }

  bountyStore.lastMatchRun = new Date().toISOString();

  // Sort new matches too for alerting
  newMatches.sort((a, b) => b.score - a.score);

  console.log(`[BOUNTY] Matching complete: ${newMatches.length} new matches, ${bountyStore.matches.length} total`);
  return { newMatches, totalMatches: bountyStore.matches.length };
}

// ─── Priority Scoring (0-100) ─────────────────────────────

/**
 * Score a CVE's relevance to a specific bounty program.
 *
 * | Factor            | Weight | Logic                                                |
 * |-------------------|--------|------------------------------------------------------|
 * | Tech stack match  | 30     | Count of matching keywords in description/CPE        |
 * | CWE relevance     | 20     | Is CWE in program's high-value list?                 |
 * | CVSS score        | 15     | Normalized: cvss / 10 * 15                           |
 * | Exploit available | 15     | Has PoC or in CISA KEV? +15                          |
 * | Freshness         | 10     | < 24h = 10, < 72h = 7, < 7d = 4, else 0             |
 * | Competition       | 10     | Independent = 10, HackerOne/Bugcrowd = 5             |
 */
function scoreCVEForProgram(cve, program, { pocCVEs, wildCVEs }) {
  const desc = (cve.description || '').toLowerCase();
  const products = (cve.affectedProducts || []).join(' ').toLowerCase();
  const searchText = `${desc} ${products}`;

  // ── Tech Stack Match (0-30) ──
  const matchedKeywords = [];
  for (const keyword of program.techStack) {
    if (searchText.includes(keyword.toLowerCase())) {
      matchedKeywords.push(keyword);
    }
  }
  // Scale: 1 match = 10, 2 = 18, 3+ = 24-30
  const techScore = Math.min(30, matchedKeywords.length * 8 + (matchedKeywords.length > 0 ? 2 : 0));

  // ── CWE Relevance (0-20) ──
  const cweList = cve.weaknesses || [];
  const matchedCWEs = cweList.filter(cwe => program.cweHighValue.includes(cwe));
  const cweScore = matchedCWEs.length > 0 ? 20 : 0;

  // ── CVSS Score (0-15) ──
  const cvssScore = cve.cvss ? Math.round((cve.cvss / 10) * 15) : 5;

  // ── Exploit Available (0-15) ──
  let exploitScore = 0;
  if (cve.exploitAvailable || pocCVEs.has(cve.id)) exploitScore = 15;
  else if (cve.cisaKEV || wildCVEs.has(cve.id)) exploitScore = 15;

  // ── Freshness (0-10) — first to report wins ──
  let freshnessScore = 0;
  const publishedTime = new Date(cve.published || 0).getTime();
  const ageMs = Date.now() - publishedTime;
  const ageHours = ageMs / (1000 * 60 * 60);
  if (ageHours < 24) freshnessScore = 10;
  else if (ageHours < 72) freshnessScore = 7;
  else if (ageHours < 168) freshnessScore = 4;

  // ── Competition Level (0-10) ──
  let competitionScore = 0;
  if (program.platform === 'independent') competitionScore = 10;
  else if (['hackerone', 'bugcrowd', 'intigriti'].includes(program.platform)) competitionScore = 5;
  else competitionScore = 7; // unknown platform = moderate competition

  // ── Out-of-scope filter ──
  const outOfScope = (program.scope?.outOfScope || []).map(s => s.toLowerCase());
  const isOutOfScope = outOfScope.some(item => desc.includes(item));
  if (isOutOfScope) {
    return {
      total: 0, techStack: 0, cwe: 0, cvss: 0,
      exploit: 0, freshness: 0, competition: 0,
      matchedKeywords: [], matchedCWEs: [],
      outOfScope: true,
    };
  }

  const total = techScore + cweScore + cvssScore + exploitScore + freshnessScore + competitionScore;

  return {
    total: Math.min(100, total),
    techStack: techScore,
    cwe: cweScore,
    cvss: cvssScore,
    exploit: exploitScore,
    freshness: freshnessScore,
    competition: competitionScore,
    matchedKeywords,
    matchedCWEs,
    outOfScope: false,
  };
}

// ─── Query Matches ────────────────────────────────────────

export function getTopMatches(limit = 20) {
  return bountyStore.matches.slice(0, limit);
}

export function getMatchesForProgram(programId, limit = 20) {
  return bountyStore.matches
    .filter(m => m.programId === programId)
    .slice(0, limit);
}

export function getMatchById(matchId) {
  return bountyStore.matches.find(m => m.id === matchId) || null;
}

// ─── Submission Tracker ───────────────────────────────────

/**
 * Track a submission to a bounty program.
 * Status flow: draft -> submitted -> acknowledged -> accepted -> paid | rejected
 */
export function addSubmission(programId, cveId, details = {}) {
  // Check for duplicate submission
  const existing = bountyStore.submissions.find(
    s => s.programId === programId && s.cveId === cveId
  );
  if (existing) {
    throw new Error(`Already submitted ${cveId} to ${programId} (status: ${existing.status})`);
  }

  const program = getProgram(programId);
  if (!program) throw new Error(`Program '${programId}' not found`);

  const submission = {
    id: `s_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    programId,
    programName: program.name,
    cveId,
    status: details.status || 'submitted',
    submittedAt: new Date().toISOString(),
    amount: details.amount || null,
    notes: details.notes || '',
    reportUrl: details.reportUrl || null,
    updatedAt: new Date().toISOString(),
  };

  bountyStore.submissions.push(submission);
  console.log(`[BOUNTY] Tracked submission: ${cveId} -> ${program.name} (${submission.status})`);
  return submission;
}

export function updateSubmission(id, updates) {
  const sub = bountyStore.submissions.find(s => s.id === id);
  if (!sub) throw new Error(`Submission '${id}' not found`);

  const allowed = ['status', 'amount', 'notes', 'reportUrl'];
  for (const key of allowed) {
    if (updates[key] !== undefined) sub[key] = updates[key];
  }
  sub.updatedAt = new Date().toISOString();
  return sub;
}

export function getSubmissions(filters = {}) {
  let results = bountyStore.submissions;
  if (filters.programId) results = results.filter(s => s.programId === filters.programId);
  if (filters.status) results = results.filter(s => s.status === filters.status);
  if (filters.cveId) results = results.filter(s => s.cveId === filters.cveId);
  return results;
}

// ─── Payout Analytics ─────────────────────────────────────

export function getPayoutStats() {
  const subs = bountyStore.submissions;

  const paid = subs.filter(s => s.status === 'paid');
  const pending = subs.filter(s => ['submitted', 'acknowledged', 'accepted'].includes(s.status));
  const rejected = subs.filter(s => s.status === 'rejected');

  const totalEarned = paid.reduce((sum, s) => sum + (s.amount || 0), 0);
  const totalPending = pending.reduce((sum, s) => sum + (s.amount || 0), 0);

  // Win rate
  const resolved = paid.length + rejected.length;
  const winRate = resolved > 0 ? Math.round((paid.length / resolved) * 100) : 0;

  // By program
  const byProgram = {};
  for (const sub of subs) {
    if (!byProgram[sub.programId]) {
      byProgram[sub.programId] = { name: sub.programName, submitted: 0, paid: 0, rejected: 0, earned: 0 };
    }
    byProgram[sub.programId].submitted++;
    if (sub.status === 'paid') {
      byProgram[sub.programId].paid++;
      byProgram[sub.programId].earned += sub.amount || 0;
    }
    if (sub.status === 'rejected') byProgram[sub.programId].rejected++;
  }

  // By CWE category (skill breakdown)
  const byCWE = {};
  for (const sub of subs) {
    const match = bountyStore.matches.find(m => m.cveId === sub.cveId && m.programId === sub.programId);
    const cwes = match?.cwe?.matchedCWEs || match?.cweMatch || ['Unknown'];
    for (const cwe of cwes) {
      if (!byCWE[cwe]) byCWE[cwe] = { count: 0, paid: 0 };
      byCWE[cwe].count++;
      if (sub.status === 'paid') byCWE[cwe].paid++;
    }
  }

  return {
    totalSubmissions: subs.length,
    totalEarned,
    totalPending,
    pendingCount: pending.length,
    rejectedCount: rejected.length,
    paidCount: paid.length,
    winRate,
    byProgram,
    byCWE,
    programs: bountyStore.programs.length,
    activePrograms: bountyStore.programs.filter(p => p.active).length,
    totalMatches: bountyStore.matches.length,
    lastMatchRun: bountyStore.lastMatchRun,
  };
}

// ─── Opus Analysis for High-Score Matches ─────────────────

/**
 * Analyze a high-scoring match with Opus 4.6.
 * Only called for matches scoring >= 70 to control API costs.
 */
export async function analyzeMatch(match) {
  // Dynamic import to avoid circular dependency
  const { default: _ } = await import('./exploit-analysis.js');

  const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  const program = getProgram(match.programId);
  if (!program) return null;

  const prompt = `You are a bug bounty strategist. Analyze this CVE match for the ${program.name} bounty program.

CVE: ${match.cveId}
CVSS: ${match.cve?.cvss || 'N/A'}
Description: ${match.cve?.description || 'N/A'}
Weaknesses: ${match.cve?.weaknesses?.join(', ') || 'N/A'}

Program: ${program.name}
Platform: ${program.platform}
Tech Stack: ${program.techStack.join(', ')}
In-Scope: ${program.scope?.inScope?.join(', ') || 'N/A'}
High-Value CWEs: ${program.cweHighValue.join(', ')}
Rewards: ${program.rewardsModel}
Max Bounty: ${program.maxBounty || 'Undisclosed'}

Match Score: ${match.score}/100
Tech Overlap: ${match.techOverlap?.join(', ') || 'None'}
CWE Match: ${match.cweMatch?.join(', ') || 'None'}

Respond in JSON:
{
  "attackStrategy": "specific steps to test for this vuln against ${program.name}",
  "estimatedBounty": "$X-$Y range",
  "duplicateRisk": "low|medium|high — have others likely found this?",
  "reportOutline": ["section 1", "section 2", "section 3"],
  "timeToTest": "estimated time to verify exploitability",
  "chainPotential": "can this be chained with other vulns for higher payout",
  "verdict": "submit|skip|investigate_further"
}`;

  try {
    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-opus-4-6',
        max_tokens: 1024,
        system: 'You are an expert bug bounty hunter and security researcher. You analyze vulnerabilities for authorized bounty programs. Be direct, actionable, and strategic.',
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!res.ok) {
      console.error(`[BOUNTY] Opus analysis failed: ${res.status}`);
      return null;
    }

    const result = await res.json();
    const text = result.content?.[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const analysis = JSON.parse(jsonMatch[0]);

    // Update the match with analysis
    match.analyzed = true;
    match.analysis = analysis;
    match.analyzedAt = new Date().toISOString();

    return analysis;
  } catch (err) {
    console.error(`[BOUNTY] Opus analysis error: ${err.message}`);
    return null;
  }
}

// ─── Store Access ─────────────────────────────────────────

export function getBountyStore() {
  return bountyStore;
}
