/**
 * Uber Security Agent — Entry Point
 *
 * Maximum coverage, maximum speed. This agent makes money.
 *
 * 7 intelligence feeds polled every 5 minutes.
 * Opus 4.6 deep analysis every 15 minutes.
 * Daily security briefing at 8 AM ET.
 *
 * Revenue model:
 * 1. Bug bounties — first-to-find advantage via fast CVE → exploit correlation
 * 2. SMB monitoring — curated vulnerability alerts for business customers
 * 3. Intelligence feeds — premium threat intelligence delivery
 */

import express from 'express';
import cron from 'node-cron';
import { sendMessage, handleCommand } from './telegram.js';
import { pollCVEFeeds, getCVEStats, searchCVE, getRecentCritical, getBountyRelevantCVEs, getRecentExploits, getSecurityNews, getFeedStatus } from './intel.js';
import { pollUndergroundFeeds, getUndergroundIntel, getNewPOCs, getExploitedInWild, getUndergroundFeedStatus } from './underground.js';
import { runAnalysis, getLatestAnalysis, getAnalysisHistory } from './analysis.js';
import { analyzeExploit } from './exploit-analysis.js';
import { loadFindings, getFindings } from './findings.js';
import {
  loadPrograms, getPrograms, getProgram, addProgram, getTopMatches,
  getMatchesForProgram, getSubmissions, getPayoutStats, matchCVEsToPrograms,
  analyzeMatch, getBountyStore,
} from './bounty-manager.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3006;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// ─── Health ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    agent: 'uber-security-agent',
    model: 'claude-opus-4-6',
    feeds: 15,
    version: '2.0.0',
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

    // Alert on new critical CVEs
    if (results.newCritical.length > 0 && CHAT_ID) {
      for (const cve of results.newCritical.slice(0, 5)) {
        const msg = formatCVEAlert(cve);
        await sendMessage(CHAT_ID, msg);
      }
    }

    // Alert on new exploits
    if (results.newExploits?.length > 0 && CHAT_ID) {
      for (const exploit of results.newExploits.slice(0, 3)) {
        const msg = formatExploitAlert(exploit);
        await sendMessage(CHAT_ID, msg);
      }
    }

    // Alert on new PoC exploit repos — URGENT: someone just published working exploit code
    if (ugResults.newPocs?.length > 0 && CHAT_ID) {
      for (const poc of ugResults.newPocs.slice(0, 5)) {
        const msg = formatPoCAlert(poc);
        await sendMessage(CHAT_ID, msg);
      }
    }

    console.log(`[CRON] Feed poll complete: ${results.total} CVEs, ${results.newCritical.length} new critical, ${results.newExploits?.length || 0} new exploits, ${ugResults.total} underground items, ${ugResults.newPocs?.length || 0} new PoCs`);
    if (ugResults.errors.length > 0) {
      ugResults.errors.forEach(e => console.log(`  Underground feed error: ${e}`));
    }

    // Run bounty matching after feeds are updated
    try {
      const matchResults = matchCVEsToPrograms();
      if (matchResults.newMatches.length > 0 && CHAT_ID) {
        // Alert on top 3 new matches
        for (const match of matchResults.newMatches.slice(0, 3)) {
          await sendMessage(CHAT_ID, formatBountyMatch(match));

          // Opus analysis for high-scoring matches (>= 70)
          if (match.score >= 70) {
            try {
              const analysis = await analyzeMatch(match);
              if (analysis) {
                await sendMessage(CHAT_ID, formatMatchAnalysis(match, analysis));
              }
            } catch (analysisErr) {
              console.error(`[BOUNTY] Analysis failed for ${match.cveId}:`, analysisErr.message);
            }
          }
        }
      }
      console.log(`[CRON] Bounty matching: ${matchResults.newMatches.length} new, ${matchResults.totalMatches} total`);
    } catch (matchErr) {
      console.error('[CRON] Bounty matching failed:', matchErr.message);
    }
  } catch (err) {
    console.error('[CRON] Feed poll failed:', err.message);
    if (CHAT_ID) {
      try { await sendMessage(CHAT_ID, `<b>⚠️ Feed poll error:</b> ${err.message}`); } catch {}
    }
  }
});

// Every 15 minutes: Opus 4.6 deep analysis — the brain of the operation
cron.schedule('*/15 * * * *', async () => {
  console.log('[CRON] Running Opus 4.6 threat analysis...');
  try {
    const analysis = await runAnalysis();

    if (analysis && CHAT_ID) {
      // Always send analysis digest (we're paying for Opus, use it)
      const msg = formatAnalysisDigest(analysis);
      await sendMessage(CHAT_ID, msg);

      // Extra alert for bounty opportunities
      if (analysis.bountyOpportunities?.length > 0) {
        const bountyMsg = formatBountyAlert(analysis.bountyOpportunities);
        await sendMessage(CHAT_ID, bountyMsg);
      }
    }

    // Deep exploit analysis on top 3 most critical new CVEs
    const critical = getRecentCritical();
    const top3 = critical.slice(0, 3);
    if (top3.length > 0 && CHAT_ID) {
      console.log(`[CRON] Running deep exploit analysis on ${top3.length} critical CVEs...`);
      for (const cve of top3) {
        try {
          const exploitAnalysis = await analyzeExploit(cve);
          if (exploitAnalysis && !exploitAnalysis.error) {
            const msg = formatExploitAnalysisAlert(exploitAnalysis);
            await sendMessage(CHAT_ID, msg);
          }
        } catch (analysisErr) {
          console.error(`[CRON] Exploit analysis failed for ${cve.id}:`, analysisErr.message);
        }
      }
      console.log(`[CRON] Deep exploit analysis complete for ${top3.length} CVEs`);
    }

    console.log('[CRON] Opus 4.6 analysis complete');
  } catch (err) {
    console.error('[CRON] Analysis failed:', err.message);
  }
});

// Daily 8am ET (13:00 UTC): Full security briefing
cron.schedule('0 13 * * *', async () => {
  console.log('[CRON] Generating daily security briefing...');
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

  console.log(`\n🛡️  Uber Security Agent v2.1`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Model: Claude Opus 4.6`);
  console.log(`   Feeds: 15 (7 core + 8 underground)`);
  console.log(`   Bounty Programs: ${getPrograms(true).length} active`);
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

  // Startup notification
  if (CHAT_ID) {
    try {
      const stats = getCVEStats();
      const programs = getPrograms(true);
      let msg = `<b>🛡️ Uber Security Agent v2.1 Online</b>\n\n`;
      msg += `<b>Model:</b> Claude Opus 4.6\n`;
      msg += `<b>Core Feeds:</b> 7 active\n`;
      msg += `<b>Underground Feeds:</b> 8 active\n`;
      msg += `<b>Bounty Programs:</b> ${programs.length} active\n`;
      msg += `<b>CVEs loaded:</b> ${stats.totalTracked}\n`;
      msg += `<b>Schedule:</b>\n`;
      msg += `• Feed poll + bounty match: every 5 min\n`;
      msg += `• Deep analysis: every 15 min\n`;
      msg += `• Daily briefing: 8:00 AM ET\n\n`;
      msg += `Programs: ${programs.map(p => p.name).join(', ')}\n\n`;
      msg += `Type /help for commands.`;
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
