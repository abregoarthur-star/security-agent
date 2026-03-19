/**
 * Uber Security Agent — Entry Point
 *
 * Maximum coverage, maximum speed. This agent makes money.
 *
 * 15 intelligence feeds polled every 5 minutes.
 * Sonnet analysis every 60 minutes (Opus reserved for bounty reports only).
 * Daily security briefing at 8 AM ET.
 * Telegram throttled: max 5 alerts/hour.
 *
 * Revenue model:
 * 1. Bug bounties — first-to-find advantage via fast CVE → exploit correlation
 * 2. SMB monitoring — curated vulnerability alerts for business customers
 * 3. Intelligence feeds — premium threat intelligence delivery
 */

import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import cron from 'node-cron';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { sendMessage, handleCommand } from './telegram.js';
import { pollCVEFeeds, getCVEStats, searchCVE, getRecentCritical, getBountyRelevantCVEs, getRecentExploits, getSecurityNews, getFeedStatus } from './intel.js';
import { pollUndergroundFeeds, getUndergroundIntel, getNewPOCs, getExploitedInWild, getUndergroundFeedStatus } from './underground.js';
import { runAnalysis, getLatestAnalysis, getAnalysisHistory } from './analysis.js';
import { analyzeExploit } from './exploit-analysis.js';
import { loadFindings, getFindings } from './findings.js';
import {
  loadPrograms, getPrograms, getProgram, addProgram, getTopMatches,
  getMatchesForProgram, getMatchById, getSubmissions, getPayoutStats, matchCVEsToPrograms,
  analyzeMatch, getBountyStore,
} from './bounty-manager.js';
import { runBountyPipeline } from './bounty-pipeline.js';
import { runPassiveValidation, getTestResults, getTestResultByMatch, getTestResultByCVE } from './bounty-testing.js';
import { syncHackerOnePrograms, getHackerOneSyncStatus } from './hackerone.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3006;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// ─── Health ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    agent: 'uber-security-agent',
    model: 'claude-sonnet-4 (opus for bounty reports only)',
    feeds: 15,
    version: '2.3.0',
  });
});

app.get('/health', (req, res) => {
  const stats = getCVEStats();
  res.json({
    status: 'ok',
    agent: 'uber-security-agent',
    uptime: process.uptime(),
    cves: stats.totalTracked,
    lastPoll: stats.lastPoll,
    feeds: getFeedStatus(),
  });
});

// Architecture doc (public, no auth)
app.get('/architecture', (req, res) => {
  const archPath = path.join(__dirname, '../ARCHITECTURE.html');
  if (fs.existsSync(archPath)) res.sendFile(archPath);
  else res.status(404).json({ error: 'Architecture doc not found' });
});

// ─── Telegram Webhook ───────────────────────────────────
app.post('/webhook', async (req, res) => {
  try {
    const message = req.body?.message;
    if (message?.text) {
      await handleCommand(message);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.json({ ok: true });
  }
});

// ─── Intel API (for Brain integration) ──────────────────
app.get('/intel/security', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const stats = getCVEStats();
  const critical = getRecentCritical();
  const analysis = getLatestAnalysis();
  const bounty = getBountyRelevantCVEs();
  const exploits = getRecentExploits();
  const news = getSecurityNews();
  const findings = getFindings();
  const underground = getUndergroundIntel();
  const pocs = getNewPOCs();
  const wild = getExploitedInWild();

  res.json({
    stats,
    critical: critical.slice(0, 15),
    analysis,
    bountyOpportunities: bounty.slice(0, 10),
    recentExploits: exploits.slice(0, 10),
    securityNews: news.slice(0, 10),
    findings: findings.slice(0, 10),
    underground,
    pocs: pocs.slice(0, 10),
    exploitedInWild: wild.slice(0, 10),
    feeds: getFeedStatus(),
    undergroundFeeds: getUndergroundFeedStatus(),
    lastPoll: stats.lastPoll,
    // Bounty program data (for Brain)
    bountyPrograms: getPrograms(true),
    bountyMatches: getTopMatches(10),
    submissions: getSubmissions().slice(0, 10),
  });
});

// ─── CVE Search ─────────────────────────────────────────
app.get('/intel/cve', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { q, id } = req.query;
  try {
    const results = await searchCVE(q || id);
    res.json({ results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Analysis History ───────────────────────────────────
app.get('/intel/analysis', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  res.json({
    latest: getLatestAnalysis(),
    history: getAnalysisHistory(),
  });
});

// ─── Bounty Program API ─────────────────────────────────

app.get('/bounty/programs', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const activeOnly = req.query.active === 'true';
  res.json({ programs: getPrograms(activeOnly) });
});

app.get('/bounty/matches', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const limit = parseInt(req.query.limit) || 20;
  res.json({ matches: getTopMatches(limit) });
});

app.get('/bounty/matches/:programId', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const program = getProgram(req.params.programId);
  if (!program) return res.status(404).json({ error: 'Program not found' });
  const limit = parseInt(req.query.limit) || 20;
  res.json({ program: program.name, matches: getMatchesForProgram(req.params.programId, limit) });
});

app.get('/bounty/submissions', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({ submissions: getSubmissions(req.query), stats: getPayoutStats() });
});

app.post('/bounty/programs', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const program = addProgram(req.body);
    res.json({ ok: true, program });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ─── HackerOne Routes ──────────────────────────────────

app.post('/bounty/hackerone/sync', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const result = await syncHackerOnePrograms();
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/bounty/hackerone/status', (req, res) => {
  res.json(getHackerOneSyncStatus());
});

// ─── Testing / Validation Routes ─────────────────────────

// Static route must come before dynamic :matchId to avoid shadowing
app.get('/bounty/test/results', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const limit = parseInt(req.query.limit) || 50;
  res.json({ results: getTestResults(limit) });
});

app.get('/bounty/test/:matchId', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.BRAIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const match = getMatchById(req.params.matchId);
  if (!match) return res.status(404).json({ error: 'Match not found' });

  const program = getProgram(match.programId);
  if (!program) return res.status(404).json({ error: 'Program not found' });

  try {
    const { buildResearchPackage } = await import('./bounty-pipeline.js');
    const researchPackage = await buildResearchPackage(process.env, match, program);
    const testResult = await runPassiveValidation(match, program, researchPackage);
    res.json({ ok: true, testResult });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Cron Jobs ──────────────────────────────────────────

// Every 5 minutes: Poll ALL intelligence feeds — speed is money
cron.schedule('*/5 * * * *', async () => {
  console.log('[CRON] Polling 15 intelligence feeds (7 core + 8 underground)...');
  try {
    // Poll core and underground feeds in parallel
    const [results, ugResults] = await Promise.all([
      pollCVEFeeds(),
      pollUndergroundFeeds(),
    ]);

    // [PAUSED] Telegram alerts disabled — re-enable when automation is complete
    // const criticals = results.newCritical.filter(c => c.severity === 'CRITICAL' || (c.cvss && c.cvss >= 9.0));
    // if (criticals.length > 0 && CHAT_ID) { ... }
    // if (ugResults.newPocs?.length > 0 && CHAT_ID) { ... }

    console.log(`[CRON] Feed poll complete: ${results.total} CVEs, ${results.newCritical.length} new critical, ${results.newExploits?.length || 0} new exploits, ${ugResults.total} underground items, ${ugResults.newPocs?.length || 0} new PoCs`);
    if (ugResults.errors.length > 0) {
      ugResults.errors.forEach(e => console.log(`  Underground feed error: ${e}`));
    }

    // Run bounty matching after feeds are updated (free — no API calls)
    try {
      const matchResults = matchCVEsToPrograms();
      console.log(`[CRON] Bounty matching: ${matchResults.newMatches.length} new, ${matchResults.totalMatches} total`);
      // [PAUSED] Telegram alerts + Opus analysis + bounty pipeline disabled
      // Re-enable when full automation pipeline is complete
    } catch (matchErr) {
      console.error('[CRON] Bounty matching failed:', matchErr.message);
    }
  } catch (err) {
    console.error('[CRON] Feed poll failed:', err.message);
    if (CHAT_ID) {
      try { await sendMessage(CHAT_ID, `<b>⚠️ Feed poll error:</b> ${err.message}`, { alert: true }); } catch {}
    }
  }
});

// [PAUSED] Hourly Sonnet/Opus analysis — disabled to stop API charges
// Re-enable when full automation pipeline is complete
// cron.schedule('0 * * * *', async () => { ... });

// Daily 9am PT (17:00 UTC): Sync HackerOne programs
cron.schedule('0 17 * * *', async () => {
  if (!process.env.HACKERONE_API_TOKEN) return;
  console.log('[CRON] Syncing HackerOne programs...');
  try {
    const result = await syncHackerOnePrograms(true); // force=true for daily cron
    console.log(`[CRON] H1 sync: ${result.imported} imported, ${result.updated} updated, ${result.skipped} skipped`);
  } catch (err) {
    console.error('[CRON] H1 sync failed:', err.message);
  }
});

// [PAUSED] Daily briefing — disabled to stop Telegram spam while automation is incomplete
// Re-enable when full automation pipeline is complete
cron.schedule('0 13 * * *', async () => {
  console.log('[CRON] Daily briefing PAUSED — skipping');
  return;
  try {
    const stats = getCVEStats();
    const critical = getRecentCritical();
    const bounty = getBountyRelevantCVEs();
    const analysis = getLatestAnalysis();
    const exploits = getRecentExploits();
    const feedStatus = getFeedStatus();

    let msg = `<b>🛡️ DAILY SECURITY BRIEFING</b>\n`;
    msg += `<i>${new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</i>\n`;
    msg += `<i>Model: Claude Opus 4.6</i>\n\n`;

    // Feed health
    msg += `<b>Intelligence Feeds (7):</b>\n`;
    const feeds = feedStatus.feeds;
    msg += `NVD ${feeds.nvd} | KEV ${feeds.kev} | OSV ${feeds.osv}\n`;
    msg += `GitHub ${feeds.gh} | ExploitDB ${feeds.exploitdb}\n`;
    msg += `PacketStorm ${feeds.packetstorm} | THN ${feeds.thn}\n\n`;

    // Stats
    msg += `<b>24-Hour Stats:</b>\n`;
    msg += `• New CVEs: ${stats.last24h}\n`;
    msg += `• Critical: ${stats.critical24h}\n`;
    msg += `• High: ${stats.high24h}\n`;
    msg += `• Bounty-relevant: ${stats.bountyRelevant24h}\n`;
    msg += `• Exploits available: ${stats.exploitsAvailable}\n`;
    msg += `• CISA KEV new: ${stats.kevNew}\n\n`;

    // Critical CVEs
    if (critical.length > 0) {
      msg += `<b>Critical Vulnerabilities:</b>\n`;
      for (const cve of critical.slice(0, 5)) {
        msg += `• <b>${cve.id}</b> — CVSS ${cve.cvss || '?'}\n`;
        msg += `  ${cve.description?.slice(0, 100)}...\n`;
        if (cve.cisaKEV) msg += `  🏛️ CISA KEV\n`;
        if (cve.exploitAvailable) msg += `  ⚠️ Exploit available\n`;
      }
      msg += '\n';
    }

    // Bounty opportunities
    if (bounty.length > 0) {
      msg += `<b>💰 Bounty Opportunities:</b>\n`;
      for (const cve of bounty.slice(0, 5)) {
        msg += `• <b>${cve.id}</b> — CVSS ${cve.cvss} — ${cve.weaknesses?.join(', ') || 'Web vuln'}\n`;
      }
      msg += '\n';
    }

    // Analysis
    if (analysis) {
      msg += `<b>Threat Landscape (Opus 4.6):</b>\n`;
      msg += `Alert Level: ${analysis.alertLevel?.toUpperCase()}\n`;
      msg += `${analysis.summary}\n\n`;

      if (analysis.attackTrends?.length > 0) {
        msg += `<b>Attack Trends:</b>\n`;
        analysis.attackTrends.forEach(t => { msg += `• ${t}\n`; });
        msg += '\n';
      }

      if (analysis.recommendations?.length > 0) {
        msg += `<b>Actions:</b>\n`;
        analysis.recommendations.forEach(r => { msg += `• ${r}\n`; });
      }

      if (analysis.marketIntel) {
        msg += `\n<b>Market:</b> ${analysis.marketIntel}`;
      }
    }

    await sendMessage(CHAT_ID, msg);
    console.log('[CRON] Daily briefing sent');
  } catch (err) {
    console.error('[CRON] Daily briefing failed:', err.message);
  }
});

// ─── Alert Formatters ───────────────────────────────────

function formatCVEAlert(cve) {
  const severity = cve.cvss >= 9.0 ? 'CRITICAL' : cve.cvss >= 7.0 ? 'HIGH' : 'MEDIUM';
  const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : '🟡';

  let msg = `${icon} <b>${severity} CVE ALERT</b>\n\n`;
  msg += `<b>${cve.id}</b>\n`;
  msg += `CVSS: ${cve.cvss || 'N/A'} | ${cve.severity || 'Unknown'}\n`;
  msg += `Source: ${cve.source}\n`;
  if (cve.attackVector) msg += `Attack Vector: ${cve.attackVector}\n`;
  msg += `\n${cve.description?.slice(0, 400) || 'No description'}\n`;

  if (cve.weaknesses?.length > 0) {
    msg += `\n<b>Weaknesses:</b> ${cve.weaknesses.join(', ')}\n`;
  }

  if (cve.affectedProducts?.length > 0) {
    msg += `\n<b>Affected:</b> ${cve.affectedProducts.slice(0, 5).join(', ')}\n`;
  }

  if (cve.exploitAvailable) msg += `\n⚠️ <b>EXPLOIT AVAILABLE</b>`;
  if (cve.cisaKEV) msg += `\n🏛️ <b>CISA Known Exploited</b>`;
  if (cve.bountyRelevant) msg += `\n💰 <b>BOUNTY RELEVANT</b>`;

  return msg;
}

function formatExploitAlert(exploit) {
  let msg = `⚡ <b>NEW EXPLOIT</b>\n\n`;
  msg += `<b>${exploit.title}</b>\n`;
  if (exploit.cveId) msg += `CVE: ${exploit.cveId}\n`;
  msg += `Source: ${exploit.source}\n`;
  msg += `\n${exploit.description?.slice(0, 300) || 'No description'}\n`;
  return msg;
}

function formatAnalysisDigest(analysis) {
  let msg = `<b>🧠 THREAT INTELLIGENCE (Opus 4.6)</b>\n\n`;
  msg += `Alert: ${analysis.alertLevel?.toUpperCase() || 'NORMAL'}\n\n`;
  msg += `${analysis.summary}\n\n`;

  if (analysis.threats?.length > 0) {
    msg += `<b>Active Threats:</b>\n`;
    analysis.threats.slice(0, 3).forEach(t => { msg += `• ${t}\n`; });
    msg += '\n';
  }

  if (analysis.exploitWatch?.length > 0) {
    msg += `<b>Exploit Watch:</b>\n`;
    analysis.exploitWatch.slice(0, 3).forEach(e => { msg += `• ${e}\n`; });
    msg += '\n';
  }

  if (analysis.attackTrends?.length > 0) {
    msg += `<b>Trends:</b>\n`;
    analysis.attackTrends.slice(0, 2).forEach(t => { msg += `• ${t}\n`; });
  }

  if (analysis.marketIntel) {
    msg += `\n<b>Market:</b> ${analysis.marketIntel}`;
  }

  return msg;
}

function formatPoCAlert(poc) {
  let msg = `🔥 <b>NEW PoC EXPLOIT PUBLISHED</b>\n\n`;
  msg += `<b>${poc.title}</b>\n`;
  if (poc.cveId) msg += `CVE: ${poc.cveId}\n`;
  msg += `Source: ${poc.source}\n`;
  if (poc.url) msg += `URL: ${poc.url}\n`;
  msg += `\n${poc.description?.slice(0, 300) || 'Proof-of-concept exploit code published on GitHub'}\n`;
  msg += `\n<i>Action: Verify exploit, check if targets are in bounty scope.</i>`;
  return msg;
}

function formatBountyAlert(opportunities) {
  let msg = `<b>💰 BOUNTY OPPORTUNITIES</b>\n\n`;

  for (const opp of opportunities.slice(0, 3)) {
    msg += `<b>${opp.cveId || 'N/A'}</b>\n`;
    msg += `Target: ${opp.target}\n`;
    msg += `Est. Bounty: ${opp.estimatedBounty}\n`;
    msg += `Difficulty: ${opp.difficulty}\n`;
    msg += `Strategy: ${opp.strategy}\n\n`;
  }

  return msg;
}

function formatExploitAnalysisAlert(analysis) {
  const riskIcon = {
    critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', informational: 'ℹ️',
  };
  const icon = riskIcon[analysis.overallRisk] || '🔵';

  let msg = `${icon} <b>DEEP ANALYSIS: ${analysis.cveId}</b>\n`;
  msg += `<i>Risk: ${analysis.overallRisk?.toUpperCase() || 'UNKNOWN'}</i>\n\n`;
  msg += `${analysis.tldr || ''}\n\n`;

  if (analysis.exploitability) {
    const e = analysis.exploitability;
    msg += `<b>Exploit:</b> ${e.difficulty || '?'} difficulty, ${e.skillLevel || '?'} skill, ${e.timeToExploit || '?'} to exploit\n`;
  }

  if (analysis.impact) {
    const i = analysis.impact;
    msg += `<b>Impact:</b> ${i.blastRadius || '?'} blast radius, ${i.lateralMovement || '?'} lateral movement\n`;
  }

  if (analysis.fix) {
    const f = analysis.fix;
    msg += `<b>Fix:</b> ${f.priority || '?'} priority — ${f.primaryFix?.slice(0, 100) || 'N/A'}\n`;
  }

  if (analysis.bounty?.worthReporting) {
    msg += `<b>Bounty:</b> ${analysis.bounty.estimatedBounty || 'TBD'} — ${analysis.bounty.duplicateRisk || '?'} dupe risk\n`;
  }

  return msg;
}

// Escape HTML entities in dynamic text to prevent Telegram parse errors
function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function formatBountyMatch(match) {
  const scoreIcon = match.score >= 80 ? '🔴' : match.score >= 60 ? '🟠' : '🟡';
  let msg = `${scoreIcon} <b>BOUNTY MATCH: ${match.cveId}</b>\n`;
  msg += `<b>Program:</b> ${match.programName}\n`;
  msg += `<b>Score:</b> ${match.score}/100\n`;
  if (match.cve?.cvss) msg += `<b>CVSS:</b> ${match.cve.cvss}\n`;
  msg += `\n${esc(match.cve?.description) || 'No description'}\n`;

  if (match.techOverlap?.length > 0) {
    msg += `\n<b>Tech Overlap:</b> ${match.techOverlap.join(', ')}\n`;
  }
  if (match.cweMatch?.length > 0) {
    msg += `<b>CWE Match:</b> ${match.cweMatch.join(', ')}\n`;
  }

  msg += `\n<b>Breakdown:</b> tech=${match.breakdown?.techStack} cwe=${match.breakdown?.cwe} cvss=${match.breakdown?.cvss} exploit=${match.breakdown?.exploit} fresh=${match.breakdown?.freshness} comp=${match.breakdown?.competition}`;

  if (match.score >= 70) {
    msg += `\n\n<i>Running Opus 4.6 deep analysis...</i>`;
  }

  return msg;
}

function formatMatchAnalysis(match, analysis) {
  let msg = `<b>🧠 BOUNTY ANALYSIS: ${match.cveId} → ${esc(match.programName)}</b>\n\n`;
  msg += `<b>Verdict:</b> ${esc(analysis.verdict?.toUpperCase()) || 'UNKNOWN'}\n`;
  if (analysis.estimatedBounty) msg += `<b>Est. Bounty:</b> ${esc(analysis.estimatedBounty)}\n`;
  if (analysis.duplicateRisk) msg += `<b>Dupe Risk:</b> ${esc(analysis.duplicateRisk)}\n`;
  if (analysis.timeToTest) msg += `<b>Time to Test:</b> ${esc(analysis.timeToTest)}\n`;
  msg += `\n<b>Strategy:</b> ${esc(analysis.attackStrategy) || 'N/A'}\n`;
  if (analysis.chainPotential) msg += `\n<b>Chain:</b> ${esc(analysis.chainPotential)}\n`;

  if (analysis.reportOutline?.length > 0) {
    msg += `\n<b>Report Outline:</b>\n`;
    analysis.reportOutline.forEach((s, i) => { msg += `${i + 1}. ${esc(s)}\n`; });
  }

  return msg;
}

// ─── Global Error Handlers ──────────────────────────────
process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception:', err);
  process.exit(1);
});

// ─── Startup ────────────────────────────────────────────
const server = app.listen(PORT, async () => {
  // Initialize bounty programs
  loadPrograms();

  console.log(`\n🛡️  Uber Security Agent v2.2`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Model: Claude Opus 4.6`);
  console.log(`   Feeds: 15 (7 core + 8 underground)`);
  console.log(`   Bounty Programs: ${getPrograms(true).length} active`);
  console.log(`   Testing: Passive validation (Phase 1) + Nuclei detection (Phase 2)`);
  console.log(`   Core: NVD, CISA KEV, OSV, GitHub, ExploitDB, PacketStorm, THN`);
  console.log(`   Underground: Full Disclosure, oss-security, Vulners, GitHub PoCs, InTheWild, Nuclei, AttackerKB, MITRE ATT&CK`);
  console.log(`   CVE Poll: Every 5 minutes`);
  console.log(`   Deep Analysis: Every 15 minutes (Opus 4.6)`);
  console.log(`   Daily Briefing: 8:00 AM ET\n`);

  // Initial feed poll (core + underground in parallel)
  try {
    const [results, ugResults] = await Promise.all([
      pollCVEFeeds(),
      pollUndergroundFeeds(),
    ]);
    console.log(`Initial poll: ${results.total} CVEs, ${results.newCritical.length} critical, ${results.errors.length} feed errors`);
    console.log(`Underground: ${ugResults.total} items, ${ugResults.newPocs?.length || 0} PoCs, ${ugResults.errors.length} feed errors`);
    if (results.errors.length > 0) {
      results.errors.forEach(e => console.log(`  Feed error: ${e}`));
    }
    if (ugResults.errors.length > 0) {
      ugResults.errors.forEach(e => console.log(`  Underground error: ${e}`));
    }
  } catch (err) {
    console.error('Initial poll failed:', err.message);
  }

  // HackerOne sync runs daily at 9 AM PT (17:00 UTC) — no startup sync needed
  // Manual trigger: /h1sync command or POST /bounty/hackerone/sync
  if (process.env.HACKERONE_API_TOKEN) {
    console.log('[HACKERONE] Credentials set — daily sync at 9 AM PT, or use /h1sync');
  }

  // Startup notification
  if (CHAT_ID) {
    try {
      const stats = getCVEStats();
      const programs = getPrograms(true);
      let msg = `<b>🛡️ Uber Security Agent v2.2 Online</b>\n\n`;
      msg += `<b>Model:</b> Claude Opus 4.6\n`;
      msg += `<b>Core Feeds:</b> 7 active\n`;
      msg += `<b>Underground Feeds:</b> 8 active\n`;
      msg += `<b>Bounty Programs:</b> ${programs.length} active\n`;
      msg += `<b>CVEs loaded:</b> ${stats.totalTracked}\n`;
      msg += `<b>Schedule:</b>\n`;
      msg += `• Feed poll + bounty match: every 5 min\n`;
      msg += `• Deep analysis: every 15 min\n`;
      msg += `• Daily briefing: 8:00 AM ET\n\n`;
      msg += `\nType /help for commands.`;
      await sendMessage(CHAT_ID, msg);
    } catch (err) {
      console.error('Startup notification failed:', err.message);
    }
  }
});

// ─── Graceful Shutdown ──────────────────────────────────
function shutdown(signal) {
  console.log(`\n[${signal}] Shutting down gracefully...`);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  // Force exit after 10s if connections hang
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
