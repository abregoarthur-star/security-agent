/**
 * Bounty Pipeline — Research Package + Report Drafting
 *
 * When a high-scoring bounty match is detected (score >= 70):
 * 1. Build a research package (passive recon + PoC gathering)
 * 2. Draft a submission-ready bug bounty report via Opus 4.6
 * 3. Deliver both to Telegram as a ready-to-act package
 *
 * All recon is passive — public sources only. No active exploitation.
 */

import { runPassiveValidation } from './bounty-testing.js';

const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const SPLOITUS_API = 'https://sploitus.com/search';
const GITHUB_SEARCH_API = 'https://api.github.com/search/repositories';

// ─── Main Entry Point ────────────────────────────────────

/**
 * Run the full bounty pipeline for a high-scoring match.
 * @param {object} env - Environment variables (process.env)
 * @param {object} match - Match object from bounty-manager
 * @param {object} program - Program object from bounty-manager
 * @returns {{ researchPackage, draftReport, telegramMessage }}
 */
export async function runBountyPipeline(env, match, program) {
  console.log(`[PIPELINE] Starting pipeline for ${match.cveId} x ${program.name}...`);

  const researchPackage = await buildResearchPackage(env, match, program);

  // Phase 1: Passive validation — confirm the target actually runs the vulnerable software
  let testResults = null;
  try {
    testResults = await runPassiveValidation(match, program, researchPackage);
    console.log(`[PIPELINE] Validation: ${testResults.confidenceScore}/100 (${testResults.confidenceLabel})`);
  } catch (err) {
    console.error(`[PIPELINE] Validation error (non-blocking):`, err.message);
  }

  const draftReport = await draftBountyReport(env, match, program, researchPackage, testResults);

  // Push to Brain for review/edit/approve (includes test results)
  await pushReportToBrain(env, match, program, researchPackage, draftReport, testResults);

  const telegramMessage = formatBountyPackage(match, program, researchPackage, draftReport, testResults);

  console.log(`[PIPELINE] Pipeline complete for ${match.cveId} x ${program.name}`);
  return { researchPackage, draftReport, testResults, telegramMessage };
}

// ─── Research Package ────────────────────────────────────

/**
 * Build a passive research package for a CVE × program match.
 * Pulls disclosure details, searches for PoCs, runs passive recon.
 */
export async function buildResearchPackage(env, match, program) {
  const cveId = match.cveId;
  console.log(`[PIPELINE] Building research package for ${cveId}...`);

  // Run all research in parallel
  const [disclosure, pocs, targetRecon] = await Promise.allSettled([
    fetchDisclosureDetails(env, cveId),
    searchForPoCs(env, cveId),
    runPassiveRecon(env, program),
  ]);

  const disclosureData = disclosure.status === 'fulfilled' ? disclosure.value : {
    description: match.cve?.description || '',
    affectedVersions: [],
    affectedProducts: [],
    prerequisites: [],
    exploitConditions: '',
    references: [],
  };

  const pocData = pocs.status === 'fulfilled' ? pocs.value : [];
  const reconData = targetRecon.status === 'fulfilled' ? targetRecon.value : {
    confirmedTech: [],
    inferredTech: [],
    publicRepos: [],
    techClues: [],
    versionHints: [],
    exposedEndpoints: [],
  };

  // Assess exploitability based on all gathered data
  const exploitability = assessExploitability(match, disclosureData, pocData, reconData);

  const researchPackage = {
    cveId,
    programId: program.id,
    disclosure: disclosureData,
    pocs: pocData,
    targetRecon: reconData,
    exploitability,
    generatedAt: new Date().toISOString(),
  };

  console.log(`[PIPELINE] Research package built: ${pocData.length} PoCs, ${reconData.confirmedTech.length} confirmed tech`);
  return researchPackage;
}

// ─── Disclosure Details (NVD API) ────────────────────────

async function fetchDisclosureDetails(env, cveId) {
  try {
    const headers = { 'User-Agent': 'UberSecurityAgent/2.1' };
    if (env.NVD_API_KEY) {
      headers['apiKey'] = env.NVD_API_KEY;
    }

    const res = await fetch(`${NVD_API}?cveId=${encodeURIComponent(cveId)}`, {
      headers,
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      console.error(`[PIPELINE] NVD API returned ${res.status} for ${cveId}`);
      return defaultDisclosure();
    }

    const data = await res.json();
    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return defaultDisclosure();

    const description = vuln.descriptions?.find(d => d.lang === 'en')?.value || '';

    // Extract affected versions from configurations
    const affectedVersions = [];
    const affectedProducts = [];
    const configs = vuln.configurations || [];
    for (const config of configs) {
      for (const node of config.nodes || []) {
        for (const cpe of node.cpeMatch || []) {
          if (cpe.vulnerable) {
            affectedProducts.push(cpe.criteria);
            const parts = [];
            if (cpe.versionStartIncluding) parts.push(`>=${cpe.versionStartIncluding}`);
            if (cpe.versionEndExcluding) parts.push(`<${cpe.versionEndExcluding}`);
            if (cpe.versionEndIncluding) parts.push(`<=${cpe.versionEndIncluding}`);
            if (parts.length > 0) affectedVersions.push(parts.join(' '));
          }
        }
      }
    }

    // Extract references
    const references = (vuln.references || []).map(ref => ({
      url: ref.url,
      source: ref.source || 'unknown',
      type: (ref.tags || []).join(', '),
    }));

    // Extract prerequisites from description
    const prerequisites = extractPrerequisites(description);
    const exploitConditions = extractExploitConditions(description);

    return {
      description,
      affectedVersions: [...new Set(affectedVersions)],
      affectedProducts: affectedProducts.slice(0, 10),
      prerequisites,
      exploitConditions,
      references,
    };
  } catch (err) {
    console.error(`[PIPELINE] NVD fetch error for ${cveId}:`, err.message);
    return defaultDisclosure();
  }
}

function defaultDisclosure() {
  return {
    description: '',
    affectedVersions: [],
    affectedProducts: [],
    prerequisites: [],
    exploitConditions: '',
    references: [],
  };
}

function extractPrerequisites(description) {
  const prereqs = [];
  const lower = description.toLowerCase();
  if (lower.includes('authenticated') || lower.includes('authentication')) prereqs.push('Authentication required');
  if (lower.includes('local access') || lower.includes('locally')) prereqs.push('Local access');
  if (lower.includes('admin') || lower.includes('administrator')) prereqs.push('Admin privileges');
  if (lower.includes('network access')) prereqs.push('Network access');
  if (lower.includes('user interaction')) prereqs.push('User interaction');
  if (lower.includes('specific config') || lower.includes('non-default')) prereqs.push('Non-default configuration');
  return prereqs;
}

function extractExploitConditions(description) {
  const lower = description.toLowerCase();
  if (lower.includes('remote') && lower.includes('unauthenticated')) return 'Remote unauthenticated — highest risk';
  if (lower.includes('remote')) return 'Remote exploitation possible';
  if (lower.includes('local')) return 'Local access required';
  if (lower.includes('adjacent')) return 'Adjacent network access required';
  return 'See description for conditions';
}

// ─── PoC Search (GitHub + Sploitus) ──────────────────────

async function searchForPoCs(env, cveId) {
  const pocs = [];

  const [githubPocs, sploitusPocs] = await Promise.allSettled([
    searchGitHubPoCs(env, cveId),
    searchSploitus(cveId),
  ]);

  if (githubPocs.status === 'fulfilled') pocs.push(...githubPocs.value);
  if (sploitusPocs.status === 'fulfilled') pocs.push(...sploitusPocs.value);

  return pocs;
}

async function searchGitHubPoCs(env, cveId) {
  try {
    const headers = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'UberSecurityAgent/2.1',
    };
    if (env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${env.GITHUB_TOKEN}`;
    }

    const query = encodeURIComponent(`${cveId} poc OR exploit OR vulnerability`);
    const res = await fetch(`${GITHUB_SEARCH_API}?q=${query}&sort=updated&per_page=5`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      console.error(`[PIPELINE] GitHub search returned ${res.status}`);
      return [];
    }

    const data = await res.json();
    return (data.items || []).map(repo => ({
      source: 'github',
      url: repo.html_url,
      language: repo.language || 'unknown',
      description: repo.description?.slice(0, 200) || '',
      stars: repo.stargazers_count || 0,
      updatedAt: repo.updated_at,
    }));
  } catch (err) {
    console.error(`[PIPELINE] GitHub PoC search error:`, err.message);
    return [];
  }
}

async function searchSploitus(cveId) {
  try {
    const res = await fetch(`${SPLOITUS_API}?query=${encodeURIComponent(cveId)}&type=exploits`, {
      headers: { 'User-Agent': 'UberSecurityAgent/2.1' },
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) return [];

    const data = await res.json();
    return (data.exploits || []).slice(0, 5).map(exploit => ({
      source: 'sploitus',
      url: exploit.href || '',
      description: exploit.title?.slice(0, 200) || '',
    }));
  } catch (err) {
    console.error(`[PIPELINE] Sploitus search error:`, err.message);
    return [];
  }
}

// ─── Passive Recon on Target ─────────────────────────────

async function runPassiveRecon(env, program) {
  const recon = {
    confirmedTech: [],
    inferredTech: [],
    publicRepos: [],
    techClues: [],
    versionHints: [],
    exposedEndpoints: [],
  };

  // Confirm tech from program's known stack
  recon.confirmedTech = program.techStack.slice(0, 15);

  // Search for public GitHub repos if applicable
  const orgNames = extractOrgNames(program);
  if (orgNames.length > 0) {
    const repoPocs = await searchPublicRepos(env, orgNames);
    recon.publicRepos = repoPocs;
  }

  // Check HTTP headers for any in-scope URLs
  const urls = extractScopeUrls(program);
  if (urls.length > 0) {
    for (const url of urls.slice(0, 2)) {
      try {
        const techInfo = await checkHttpHeaders(url);
        if (techInfo.server) recon.techClues.push(`Server header: ${techInfo.server}`);
        if (techInfo.poweredBy) recon.techClues.push(`X-Powered-By: ${techInfo.poweredBy}`);
        if (techInfo.tech.length > 0) recon.inferredTech.push(...techInfo.tech);
        recon.exposedEndpoints.push(url);
      } catch {
        // Skip failed checks
      }
    }
  }

  // Infer tech from program notes and scope
  const inferred = inferTechFromContext(program);
  recon.inferredTech.push(...inferred);
  recon.inferredTech = [...new Set(recon.inferredTech)];

  return recon;
}

function extractOrgNames(program) {
  const orgs = [];
  const scopeItems = program.scope?.inScope || [];
  for (const item of scopeItems) {
    // Extract org from github URLs or domain names
    const ghMatch = item.match(/github\.com\/([^/\s]+)/i);
    if (ghMatch) orgs.push(ghMatch[1]);

    // Extract org name from known patterns
    const domainMatch = item.match(/\*?\.?(\w+)\.(com|io|app|dev)/i);
    if (domainMatch) orgs.push(domainMatch[1]);
  }
  return [...new Set(orgs)];
}

function extractScopeUrls(program) {
  const urls = [];
  if (program.url && !program.url.includes('hackerone') && !program.url.includes('bugcrowd')) {
    // Don't probe bounty platform URLs, only direct target URLs
  }
  const scopeItems = program.scope?.inScope || [];
  for (const item of scopeItems) {
    if (item.match(/^https?:\/\//)) urls.push(item);
    else if (item.match(/^\*?\./)) {
      // Wildcard domain — try the base domain
      const base = item.replace(/^\*\./, '');
      if (base.includes('.')) urls.push(`https://${base}`);
    }
  }
  return urls;
}

async function searchPublicRepos(env, orgNames) {
  const repos = [];
  const headers = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'UberSecurityAgent/2.1',
  };
  if (env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${env.GITHUB_TOKEN}`;
  }

  for (const org of orgNames.slice(0, 2)) {
    try {
      const res = await fetch(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos?sort=updated&per_page=5`, {
        headers,
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) continue;
      const data = await res.json();
      for (const repo of (data || []).slice(0, 5)) {
        repos.push(repo.html_url);
      }
    } catch {
      // Skip failed org lookups
    }
  }
  return repos;
}

async function checkHttpHeaders(url) {
  const result = { server: null, poweredBy: null, tech: [] };
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityAgent/2.1)' },
    });
    const server = res.headers.get('server');
    const poweredBy = res.headers.get('x-powered-by');
    if (server) {
      result.server = server;
      if (server.toLowerCase().includes('nginx')) result.tech.push('nginx');
      if (server.toLowerCase().includes('apache')) result.tech.push('apache');
      if (server.toLowerCase().includes('cloudflare')) result.tech.push('cloudflare');
    }
    if (poweredBy) {
      result.poweredBy = poweredBy;
      if (poweredBy.toLowerCase().includes('express')) result.tech.push('express');
      if (poweredBy.toLowerCase().includes('php')) result.tech.push('php');
      if (poweredBy.toLowerCase().includes('asp')) result.tech.push('asp.net');
    }
  } catch {
    // Silent fail for header checks
  }
  return result;
}

function inferTechFromContext(program) {
  const inferred = [];
  const notes = (program.notes || '').toLowerCase();
  const techKeywords = [
    'k8s', 'kubernetes', 'docker', 'aws', 'azure', 'gcp',
    'react', 'vue', 'angular', 'graphql', 'grpc',
  ];
  for (const kw of techKeywords) {
    if (notes.includes(kw) && !program.techStack.includes(kw)) {
      inferred.push(kw);
    }
  }
  return inferred;
}

// ─── Exploitability Assessment ───────────────────────────

function assessExploitability(match, disclosure, pocs, recon) {
  let score = 0;

  // PoC availability (0-30)
  const applicablePoCs = pocs.length;
  if (applicablePoCs > 0) score += Math.min(30, applicablePoCs * 10);

  // CVSS-based score (0-25)
  const cvss = match.cve?.cvss || 0;
  score += Math.round((cvss / 10) * 25);

  // Tech overlap (0-20)
  const techOverlap = match.techOverlap?.length || 0;
  score += Math.min(20, techOverlap * 7);

  // Exploit conditions (0-15)
  const conditions = (disclosure.exploitConditions || '').toLowerCase();
  if (conditions.includes('remote unauthenticated')) score += 15;
  else if (conditions.includes('remote')) score += 10;
  else if (conditions.includes('local')) score += 5;

  // CISA KEV / exploit available (0-10)
  if (match.cve?.cisaKEV || match.cve?.exploitAvailable) score += 10;

  score = Math.min(100, score);

  // Determine confidence
  let confidence = 'low';
  if (applicablePoCs > 0 && techOverlap > 0) confidence = 'high';
  else if (applicablePoCs > 0 || techOverlap > 1) confidence = 'medium';

  // Target likely vulnerable?
  const targetLikelyVulnerable = score >= 50 && techOverlap > 0;

  const rationale = buildRationale(match, disclosure, pocs, recon);

  return {
    score,
    rationale,
    applicablePoCs,
    targetLikelyVulnerable,
    confidence,
  };
}

function buildRationale(match, disclosure, pocs, recon) {
  const parts = [];

  if (pocs.length > 0) parts.push(`${pocs.length} PoC(s) available`);
  else parts.push('No public PoC found');

  if (match.techOverlap?.length > 0) {
    parts.push(`Tech overlap: ${match.techOverlap.join(', ')}`);
  }

  if (match.cve?.cisaKEV) parts.push('CISA KEV — confirmed actively exploited');
  if (match.cve?.exploitAvailable) parts.push('Exploit publicly available');

  const conditions = disclosure.exploitConditions;
  if (conditions) parts.push(conditions);

  if (disclosure.prerequisites.length > 0) {
    parts.push(`Prerequisites: ${disclosure.prerequisites.join(', ')}`);
  }

  return parts.join('. ') + '.';
}

// ─── Report Drafting (Opus 4.6) ──────────────────────────

/**
 * Draft a submission-ready bug bounty report using Opus 4.6.
 * One Opus call per pipeline run to control costs.
 */
export async function draftBountyReport(env, match, program, researchPackage, testResults = null) {
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    console.error('[PIPELINE] No ANTHROPIC_API_KEY — skipping report draft');
    return fallbackReport(match, program, researchPackage);
  }

  // Determine report format based on platform
  const format = getPlatformFormat(program.platform);

  const prompt = buildReportPrompt(match, program, researchPackage, format, testResults);

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
        max_tokens: 4096,
        system: `You are an expert bug bounty hunter who writes clear, professional vulnerability reports. You produce reports that maximize acceptance and payout. Your reports are thorough but concise, with clear reproduction steps and accurate CVSS scoring. You write for authorized bug bounty programs only.`,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error(`[PIPELINE] Opus report draft failed: ${res.status} — ${err}`);
      return fallbackReport(match, program, researchPackage);
    }

    const result = await res.json();
    const text = result.content?.[0]?.text || '';

    // Parse structured report from JSON
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.error('[PIPELINE] No JSON in Opus response — using raw text');
      return {
        format,
        title: `${match.cveId} — Vulnerability Report for ${program.name}`,
        severity: match.cve?.severity || 'High',
        cvssScore: match.cve?.cvss || 0,
        cvssVector: '',
        summary: text.slice(0, 500),
        description: text,
        reproductionSteps: [],
        impact: '',
        remediation: '',
        references: [],
        emailBody: text,
        hackeroneMarkdown: text,
        estimatedBounty: 'Unknown',
        duplicateRisk: 'unknown',
        duplicateRationale: '',
        generatedAt: new Date().toISOString(),
      };
    }

    const report = JSON.parse(jsonMatch[0]);

    return {
      format,
      title: report.title || `${match.cveId} — ${program.name}`,
      severity: report.severity || match.cve?.severity || 'High',
      cvssScore: report.cvssScore || match.cve?.cvss || 0,
      cvssVector: report.cvssVector || '',
      summary: report.summary || '',
      description: report.description || '',
      reproductionSteps: report.reproductionSteps || [],
      impact: report.impact || '',
      remediation: report.remediation || '',
      references: report.references || [],
      emailBody: report.emailBody || '',
      hackeroneMarkdown: report.hackeroneMarkdown || '',
      estimatedBounty: report.estimatedBounty || 'Unknown',
      duplicateRisk: report.duplicateRisk || 'unknown',
      duplicateRationale: report.duplicateRationale || '',
      generatedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.error(`[PIPELINE] Report draft error:`, err.message);
    return fallbackReport(match, program, researchPackage);
  }
}

function getPlatformFormat(platform) {
  switch (platform) {
    case 'hackerone': return 'hackerone';
    case 'bugcrowd': return 'bugcrowd';
    case 'intigriti': return 'intigriti';
    default: return 'email';
  }
}

function buildReportPrompt(match, program, researchPackage, format, testResults = null) {
  const formatInstructions = {
    email: `Format as a professional email to ${program.submitTo || 'the security team'}. Include subject line, greeting, full technical details, and sign-off. Put the full email in the "emailBody" field.`,
    hackerone: `Format for HackerOne submission. Use markdown formatting. Include all standard HackerOne report sections. Put the markdown report in the "hackeroneMarkdown" field.`,
    bugcrowd: `Format for Bugcrowd submission. Use markdown formatting. Include all standard Bugcrowd report sections. Put the markdown report in the "hackeroneMarkdown" field (same format).`,
    intigriti: `Format for Intigriti submission. Use markdown formatting. Include all standard Intigriti report sections. Put the markdown report in the "hackeroneMarkdown" field (same format).`,
  };

  return `Draft a complete bug bounty report for this vulnerability match.

CVE: ${match.cveId}
CVSS: ${match.cve?.cvss || 'N/A'}
Severity: ${match.cve?.severity || 'N/A'}
CWE: ${match.cweMatch?.join(', ') || match.cve?.weaknesses?.join(', ') || 'N/A'}

DESCRIPTION:
${researchPackage.disclosure.description || match.cve?.description || 'N/A'}

AFFECTED VERSIONS: ${researchPackage.disclosure.affectedVersions.join(', ') || 'N/A'}
AFFECTED PRODUCTS: ${researchPackage.disclosure.affectedProducts.slice(0, 5).join(', ') || 'N/A'}
PREREQUISITES: ${researchPackage.disclosure.prerequisites.join(', ') || 'None identified'}
EXPLOIT CONDITIONS: ${researchPackage.disclosure.exploitConditions || 'N/A'}

PoCs FOUND: ${researchPackage.pocs.length}
${researchPackage.pocs.map(p => `- [${p.source}] ${p.url || ''} — ${p.description || ''}`).join('\n') || 'None'}

TARGET PROGRAM: ${program.name}
PLATFORM: ${program.platform}
SUBMIT TO: ${program.submitTo || program.url || 'N/A'}
TECH STACK: ${program.techStack.slice(0, 15).join(', ')}
IN-SCOPE: ${program.scope?.inScope?.join(', ') || 'N/A'}
HIGH-VALUE CWEs: ${program.cweHighValue.join(', ')}
REWARDS: ${program.rewardsModel}${program.maxBounty ? ` (max $${program.maxBounty})` : ''}

TECH OVERLAP: ${match.techOverlap?.join(', ') || 'None'}
MATCH SCORE: ${match.score}/100

REFERENCES:
${researchPackage.disclosure.references.slice(0, 5).map(r => `- ${r.url} (${r.type || r.source})`).join('\n') || 'None'}

EXPLOITABILITY ASSESSMENT:
Score: ${researchPackage.exploitability.score}/100
Confidence: ${researchPackage.exploitability.confidence}
Target Likely Vulnerable: ${researchPackage.exploitability.targetLikelyVulnerable}
Rationale: ${researchPackage.exploitability.rationale}

PASSIVE VALIDATION RESULTS:
${testResults ? `Confidence: ${testResults.confidenceScore}/100 (${testResults.confidenceLabel})
Tests:
${testResults.tests.map(t => `- ${t.name}: ${t.result} — ${t.detail}`).join('\n')}` : 'No validation data available'}

FORMAT: ${format}
${formatInstructions[format]}

IMPORTANT: If passive validation data is available, incorporate the evidence into the report. Mention specific confirmed versions, detected endpoints, or technology confirmations. This transforms the report from theoretical to evidence-backed.

Respond with a single JSON object containing:
{
  "title": "Clear, specific vulnerability title",
  "severity": "Critical|High|Medium|Low",
  "cvssScore": 0.0,
  "cvssVector": "CVSS:3.1/...",
  "summary": "2-3 sentence executive summary",
  "description": "Detailed technical description",
  "reproductionSteps": ["Step 1...", "Step 2..."],
  "impact": "What an attacker could achieve",
  "remediation": "Recommended fix",
  "references": [{"title": "...", "url": "..."}],
  "emailBody": "Full formatted email text (for email format)",
  "hackeroneMarkdown": "Full HackerOne/Bugcrowd/Intigriti markdown report",
  "estimatedBounty": "$X - $Y",
  "duplicateRisk": "low|medium|high",
  "duplicateRationale": "Why this may/may not already be reported"
}

Be specific, accurate, and professional. Emphasize clear reproduction steps. Include accurate CVSS justification. Make this report ready to submit with minimal editing.`;
}

function fallbackReport(match, program, researchPackage) {
  const format = getPlatformFormat(program.platform);
  return {
    format,
    title: `${match.cveId} — Potential Impact on ${program.name}`,
    severity: match.cve?.severity || 'High',
    cvssScore: match.cve?.cvss || 0,
    cvssVector: '',
    summary: `${match.cveId} may affect ${program.name} based on tech stack overlap (${match.techOverlap?.join(', ') || 'N/A'}).`,
    description: researchPackage.disclosure.description || match.cve?.description || '',
    reproductionSteps: ['1. Verify affected version is in use', '2. Review CVE details and PoC if available', '3. Test in authorized environment'],
    impact: 'See CVE description for impact details.',
    remediation: 'Apply vendor patches or mitigations as available.',
    references: researchPackage.disclosure.references.slice(0, 5).map(r => ({ title: r.source, url: r.url })),
    emailBody: '',
    hackeroneMarkdown: '',
    estimatedBounty: 'Unknown — Opus API unavailable',
    duplicateRisk: 'unknown',
    duplicateRationale: 'Unable to assess without AI analysis.',
    generatedAt: new Date().toISOString(),
  };
}

// ─── Brain Integration ───────────────────────────────────

/**
 * Push a bounty report to the Brain for review/edit/approve.
 * Fire-and-forget — Brain failures don't block the pipeline.
 */
async function pushReportToBrain(env, match, program, researchPackage, draftReport, testResults = null) {
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
    // Validation evidence
    testResults: testResults ? {
      confidenceScore: testResults.confidenceScore,
      confidenceLabel: testResults.confidenceLabel,
      tier: testResults.tier,
      tests: testResults.tests.map(t => ({
        name: t.name,
        result: t.result,
        detail: t.detail,
      })),
    } : null,
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

// ─── Telegram Formatting ─────────────────────────────────

/**
 * Format the full bounty pipeline output for Telegram.
 * Returns an array of messages (split at 4096 char limit).
 */
export function formatBountyPackage(match, program, researchPackage, draftReport, testResults = null) {
  const e = esc;

  // ── Header message ──
  let header = `🔴 <b>BOUNTY PIPELINE — ${e(match.cveId)} x ${e(program.name)}</b>\n\n`;
  header += `📊 Match Score: ${match.score}/100 | Severity: ${e(draftReport.severity)}\n`;
  header += `💰 Est. Payout: ${e(draftReport.estimatedBounty)}\n`;
  header += `⚡ Duplicate Risk: ${e(draftReport.duplicateRisk)}\n\n`;

  // ── Validation section ──
  if (testResults) {
    const confIcon = testResults.confidenceScore >= 70 ? '🟢' : testResults.confidenceScore >= 50 ? '🟡' : '🔴';
    header += `${confIcon} <b>VALIDATION: ${testResults.confidenceScore}/100 — ${e(testResults.confidenceLabel)}</b>\n`;
    for (const test of testResults.tests) {
      const icon = test.result === 'pass' ? '✅' : test.result === 'partial' ? '🟡' : test.result === 'skip' ? '⏭' : '❌';
      header += `${icon} ${e(test.name)}: ${e(test.detail?.slice(0, 120))}\n`;
    }
    header += '\n';
  }

  header += `🔬 <b>RESEARCH PACKAGE</b>\n`;
  header += `Tech Match: ${e(researchPackage.targetRecon.confirmedTech.slice(0, 8).join(', '))}\n`;
  header += `Target Likely Vulnerable: ${researchPackage.exploitability.targetLikelyVulnerable ? 'Yes' : 'No'} (${e(researchPackage.exploitability.confidence)})\n`;

  const pocSources = [...new Set(researchPackage.pocs.map(p => p.source))].join(', ');
  header += `PoCs Found: ${researchPackage.pocs.length}${pocSources ? ` (${e(pocSources)})` : ''}\n`;

  if (researchPackage.disclosure.prerequisites.length > 0) {
    header += `Key Prerequisites: ${e(researchPackage.disclosure.prerequisites.join(', '))}\n`;
  }

  header += `\n📝 <b>DRAFT REPORT</b>\n`;
  header += `Title: ${e(draftReport.title)}\n`;
  header += `CVSS: ${draftReport.cvssScore}${draftReport.cvssVector ? ` (${e(draftReport.cvssVector)})` : ''}\n`;
  header += `Format: ${e(draftReport.format)} (${e(program.platform)})\n`;

  // ── Report body ──
  let reportBody = '';
  if (draftReport.emailBody) {
    reportBody = draftReport.emailBody;
  } else if (draftReport.hackeroneMarkdown) {
    reportBody = draftReport.hackeroneMarkdown;
  } else {
    // Build from structured fields
    reportBody = `${draftReport.summary}\n\n`;
    reportBody += `DESCRIPTION:\n${draftReport.description}\n\n`;
    if (draftReport.reproductionSteps?.length > 0) {
      reportBody += `REPRODUCTION STEPS:\n`;
      draftReport.reproductionSteps.forEach((s, i) => { reportBody += `${i + 1}. ${s}\n`; });
      reportBody += '\n';
    }
    if (draftReport.impact) reportBody += `IMPACT:\n${draftReport.impact}\n\n`;
    if (draftReport.remediation) reportBody += `REMEDIATION:\n${draftReport.remediation}\n`;
  }

  // ── TODO footer ──
  let footer = `\n⏳ <b>YOUR TODO:</b>\n`;
  footer += `1. Reproduce locally\n`;
  footer += `2. Review &amp; tweak the report above\n`;
  footer += `3. Submit to ${e(program.submitTo || program.url || program.name)}\n`;
  footer += `4. <code>/submit ${e(match.cveId)} ${e(program.id)}</code>`;

  // Split into messages respecting 4096 char limit
  const messages = [];
  messages.push(header);

  // Split report body into chunks
  const escapedReport = e(reportBody);
  const reportChunks = splitMessage(escapedReport, 3800);
  for (let i = 0; i < reportChunks.length; i++) {
    let chunk = '';
    if (i === 0) chunk += `\n<b>[Full report below ⬇️]</b>\n---\n`;
    chunk += reportChunks[i];
    if (i === reportChunks.length - 1) chunk += `\n---` + footer;
    messages.push(chunk);
  }

  return messages;
}

function splitMessage(text, maxLen) {
  if (text.length <= maxLen) return [text];

  const chunks = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      chunks.push(remaining);
      break;
    }
    // Find a good split point (newline or space)
    let splitAt = remaining.lastIndexOf('\n', maxLen);
    if (splitAt < maxLen * 0.5) splitAt = remaining.lastIndexOf(' ', maxLen);
    if (splitAt < maxLen * 0.5) splitAt = maxLen;

    chunks.push(remaining.slice(0, splitAt));
    remaining = remaining.slice(splitAt);
  }
  return chunks;
}

/** Escape HTML entities for Telegram HTML parse mode */
function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
