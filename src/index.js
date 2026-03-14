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
import { runAnalysis, getLatestAnalysis, getAnalysisHistory } from './analysis.js';
import { loadFindings, getFindings } from './findings.js';

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
    feeds: 7,
    version: '1.0.0',
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

  res.json({
    stats,
    critical: critical.slice(0, 15),
    analysis,
    bountyOpportunities: bounty.slice(0, 10),
    recentExploits: exploits.slice(0, 10),
    securityNews: news.slice(0, 10),
    findings: findings.slice(0, 10),
    feeds: getFeedStatus(),
    lastPoll: stats.lastPoll,
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

// ─── Cron Jobs ──────────────────────────────────────────

// Every 5 minutes: Poll ALL intelligence feeds — speed is money
cron.schedule('*/5 * * * *', async () => {
  console.log('[CRON] Polling 7 intelligence feeds...');
  try {
    const results = await pollCVEFeeds();

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

    console.log(`[CRON] Feed poll complete: ${results.total} CVEs, ${results.newCritical.length} new critical, ${results.newExploits?.length || 0} new exploits`);
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

// ─── Startup ────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`\n🛡️  Uber Security Agent v1.0`);
  console.log(`   Port: ${PORT}`);
  console.log(`   Model: Claude Opus 4.6`);
  console.log(`   Feeds: 7 (NVD, CISA KEV, OSV, GitHub, ExploitDB, PacketStorm, THN)`);
  console.log(`   CVE Poll: Every 5 minutes`);
  console.log(`   Deep Analysis: Every 15 minutes (Opus 4.6)`);
  console.log(`   Daily Briefing: 8:00 AM ET\n`);

  // Initial feed poll
  try {
    const results = await pollCVEFeeds();
    console.log(`Initial poll: ${results.total} CVEs, ${results.newCritical.length} critical, ${results.errors.length} feed errors`);
    if (results.errors.length > 0) {
      results.errors.forEach(e => console.log(`  Feed error: ${e}`));
    }
  } catch (err) {
    console.error('Initial poll failed:', err.message);
  }

  // Startup notification
  if (CHAT_ID) {
    try {
      const stats = getCVEStats();
      let msg = `<b>🛡️ Uber Security Agent Online</b>\n\n`;
      msg += `<b>Model:</b> Claude Opus 4.6\n`;
      msg += `<b>Feeds:</b> 7 active\n`;
      msg += `<b>CVEs loaded:</b> ${stats.totalTracked}\n`;
      msg += `<b>Schedule:</b>\n`;
      msg += `• Feed poll: every 5 min\n`;
      msg += `• Deep analysis: every 15 min\n`;
      msg += `• Daily briefing: 8:00 AM ET\n\n`;
      msg += `Type /help for commands.`;
      await sendMessage(CHAT_ID, msg);
    } catch (err) {
      console.error('Startup notification failed:', err.message);
    }
  }
});
