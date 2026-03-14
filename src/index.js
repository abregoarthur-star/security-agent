/**
 * Uber Security Agent — Entry Point
 *
 * Express server + cron jobs for continuous security intelligence.
 * Polls CVE feeds, monitors vulnerabilities, sends Telegram alerts.
 */

import express from 'express';
import cron from 'node-cron';
import { sendMessage, handleCommand, setWebhook } from './telegram.js';
import { pollCVEFeeds, getCVEStats, searchCVE, getRecentCritical } from './intel.js';
import { runAnalysis, getLatestAnalysis } from './analysis.js';
import { loadFindings, getFindings } from './findings.js';

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3006;
const CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// ─── Health ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', agent: 'security-agent' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', agent: 'security-agent', uptime: process.uptime() });
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
    res.json({ ok: true }); // Always 200 for Telegram
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
  const findings = getFindings();

  res.json({
    stats,
    critical,
    analysis,
    findings: findings.slice(0, 10),
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

// ─── Cron Jobs ──────────────────────────────────────────

// Every 15 minutes: Poll CVE feeds (NVD, CISA KEV, OSV)
cron.schedule('*/15 * * * *', async () => {
  console.log('[CRON] Polling CVE feeds...');
  try {
    const results = await pollCVEFeeds();

    if (results.newCritical.length > 0) {
      for (const cve of results.newCritical) {
        const msg = formatCVEAlert(cve);
        await sendMessage(CHAT_ID, msg);
      }
    }

    console.log(`[CRON] CVE poll complete: ${results.total} checked, ${results.newCritical.length} critical`);
  } catch (err) {
    console.error('[CRON] CVE poll failed:', err.message);
  }
});

// Every hour: Claude analysis of threat landscape
cron.schedule('0 * * * *', async () => {
  console.log('[CRON] Running threat analysis...');
  try {
    const analysis = await runAnalysis();
    if (analysis && analysis.alertLevel === 'high') {
      const msg = `<b>THREAT LANDSCAPE UPDATE</b>\n\n${analysis.summary}\n\n<b>Key Threats:</b>\n${analysis.threats.map(t => `• ${t}`).join('\n')}`;
      await sendMessage(CHAT_ID, msg);
    }
    console.log('[CRON] Threat analysis complete');
  } catch (err) {
    console.error('[CRON] Threat analysis failed:', err.message);
  }
});

// Daily 8am ET (13:00 UTC): Security briefing
cron.schedule('0 13 * * *', async () => {
  console.log('[CRON] Generating daily security briefing...');
  try {
    const stats = getCVEStats();
    const critical = getRecentCritical();
    const analysis = getLatestAnalysis();

    let msg = `<b>DAILY SECURITY BRIEFING</b>\n`;
    msg += `<i>${new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}</i>\n\n`;

    msg += `<b>CVE Stats (24h):</b>\n`;
    msg += `• New CVEs: ${stats.last24h}\n`;
    msg += `• Critical: ${stats.critical24h}\n`;
    msg += `• CISA KEV additions: ${stats.kevNew}\n\n`;

    if (critical.length > 0) {
      msg += `<b>Critical Vulnerabilities:</b>\n`;
      for (const cve of critical.slice(0, 5)) {
        msg += `• <b>${cve.id}</b> — ${cve.description?.slice(0, 100)}...\n`;
        msg += `  CVSS: ${cve.cvss || 'N/A'} | ${cve.source}\n`;
      }
      msg += '\n';
    }

    if (analysis) {
      msg += `<b>Threat Landscape:</b>\n${analysis.summary}\n\n`;
      if (analysis.recommendations?.length > 0) {
        msg += `<b>Recommendations:</b>\n`;
        analysis.recommendations.forEach(r => { msg += `• ${r}\n`; });
      }
    }

    await sendMessage(CHAT_ID, msg);
    console.log('[CRON] Daily briefing sent');
  } catch (err) {
    console.error('[CRON] Daily briefing failed:', err.message);
  }
});

function formatCVEAlert(cve) {
  const severity = cve.cvss >= 9.0 ? 'CRITICAL' : cve.cvss >= 7.0 ? 'HIGH' : 'MEDIUM';
  const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : '🟡';

  let msg = `${icon} <b>${severity} CVE ALERT</b>\n\n`;
  msg += `<b>${cve.id}</b>\n`;
  msg += `CVSS: ${cve.cvss || 'N/A'}\n`;
  msg += `Source: ${cve.source}\n\n`;
  msg += `${cve.description?.slice(0, 300) || 'No description'}\n\n`;

  if (cve.affectedProducts?.length > 0) {
    msg += `<b>Affected:</b> ${cve.affectedProducts.slice(0, 5).join(', ')}\n`;
  }

  if (cve.exploitAvailable) {
    msg += `\n⚠️ <b>EXPLOIT AVAILABLE</b>`;
  }

  if (cve.cisaKEV) {
    msg += `\n🏛️ <b>CISA Known Exploited</b>`;
  }

  return msg;
}

// ─── Startup ────────────────────────────────────────────
app.listen(PORT, async () => {
  console.log(`Security Agent running on port ${PORT}`);

  // Initial CVE feed poll on startup
  try {
    const results = await pollCVEFeeds();
    console.log(`Initial CVE poll: ${results.total} CVEs loaded, ${results.newCritical.length} critical`);
  } catch (err) {
    console.error('Initial CVE poll failed:', err.message);
  }

  // Send startup notification
  if (CHAT_ID) {
    try {
      await sendMessage(CHAT_ID, '<b>🛡️ Security Agent Online</b>\n\nCVE intelligence feeds active.\nType /help for commands.');
    } catch (err) {
      console.error('Startup notification failed:', err.message);
    }
  }
});
