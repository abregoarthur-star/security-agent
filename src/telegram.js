/**
 * Telegram Bot — Security Agent Commands & Alerts
 *
 * All messages use HTML parse mode (more reliable than Markdown).
 */

const TELEGRAM_API = 'https://api.telegram.org/bot';

/**
 * Send a message to a Telegram chat.
 */
export async function sendMessage(chatId, text, options = {}) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) throw new Error('TELEGRAM_BOT_TOKEN not set');

  const url = `${TELEGRAM_API}${token}/sendMessage`;
  const body = {
    chat_id: chatId,
    text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
    ...options,
  };

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Telegram send failed: ${res.status} — ${err}`);
  }

  return res.json();
}

/**
 * Set the Telegram webhook URL.
 */
export async function setWebhook(webhookUrl) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const url = `${TELEGRAM_API}${token}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;
  const res = await fetch(url);
  return res.json();
}

/**
 * Handle incoming Telegram commands.
 */
export async function handleCommand(message) {
  const chatId = message.chat.id;
  const text = message.text?.trim() || '';
  const cmd = text.split(' ')[0].toLowerCase();
  const args = text.slice(cmd.length).trim();

  try {
    switch (cmd) {
      case '/start':
        await sendMessage(chatId, getStartMessage());
        break;

      case '/status':
        await handleStatus(chatId);
        break;

      case '/cve':
        await handleCVELookup(chatId, args);
        break;

      case '/critical':
        await handleCritical(chatId);
        break;

      case '/stats':
        await handleStats(chatId);
        break;

      case '/scan':
        await handleScan(chatId, args);
        break;

      case '/threats':
        await handleThreats(chatId);
        break;

      case '/chatid':
        await sendMessage(chatId, `Your chat ID: <code>${chatId}</code>`);
        break;

      case '/help':
        await sendMessage(chatId, getHelpMessage());
        break;

      default:
        if (text.startsWith('/')) {
          await sendMessage(chatId, `Unknown command. Type /help for available commands.`);
        }
    }
  } catch (err) {
    console.error(`Command ${cmd} failed:`, err.message);
    await sendMessage(chatId, `<b>Error:</b> ${err.message}`);
  }
}

function getStartMessage() {
  return `<b>🛡️ Uber Security Agent</b>

Autonomous CVE intelligence and vulnerability monitoring.

<b>Active Feeds:</b>
• NVD (National Vulnerability Database)
• CISA KEV (Known Exploited Vulnerabilities)
• OSV.dev (Open Source Vulnerabilities)
• GitHub Security Advisories

<b>Capabilities:</b>
• Real-time critical CVE alerts
• Threat landscape analysis (Claude AI)
• Daily security briefings
• CVE search and lookup

Type /help for all commands.`;
}

function getHelpMessage() {
  return `<b>🛡️ Security Agent Commands</b>

<b>Intelligence:</b>
/status — Agent health and feed status
/stats — CVE statistics (24h/7d/30d)
/critical — Recent critical CVEs
/cve [ID] — Look up a specific CVE
/threats — Current threat landscape analysis

<b>Scanning:</b>
/scan [domain] — Quick vulnerability scan (coming soon)

<b>System:</b>
/chatid — Show your chat ID
/help — This help message

<b>Automated Alerts:</b>
• Critical CVE alerts — immediate
• CISA KEV additions — immediate
• Threat landscape updates — hourly (high-severity only)
• Daily briefing — 8:00 AM ET`;
}

async function handleStatus(chatId) {
  const { getCVEStats } = await import('./intel.js');
  const stats = getCVEStats();

  let msg = `<b>🛡️ Security Agent Status</b>\n\n`;

  // Feed status
  msg += `<b>Intelligence Feeds:</b>\n`;
  msg += `• NVD API: ${stats.nvdStatus || '⏳ Pending'}\n`;
  msg += `• CISA KEV: ${stats.kevStatus || '⏳ Pending'}\n`;
  msg += `• OSV.dev: ${stats.osvStatus || '⏳ Pending'}\n`;
  msg += `• GitHub Advisories: ${stats.ghStatus || '⏳ Pending'}\n\n`;

  msg += `<b>Database:</b>\n`;
  msg += `• Total CVEs tracked: ${stats.totalTracked}\n`;
  msg += `• Critical (24h): ${stats.critical24h}\n`;
  msg += `• Last poll: ${stats.lastPoll || 'Never'}\n\n`;

  // Claude
  msg += `<b>Analysis Engine:</b>\n`;
  msg += `• Model: Claude Haiku 4.5\n`;
  msg += `• Status: ${process.env.ANTHROPIC_API_KEY ? '✅ Connected' : '❌ No API key'}\n\n`;

  // Telegram
  msg += `<b>Telegram:</b> ✅ Connected\n`;
  msg += `<b>Uptime:</b> ${formatUptime(process.uptime())}`;

  await sendMessage(chatId, msg);
}

async function handleCVELookup(chatId, cveId) {
  if (!cveId) {
    await sendMessage(chatId, 'Usage: /cve CVE-2024-3094');
    return;
  }

  const { searchCVE } = await import('./intel.js');
  const results = await searchCVE(cveId.toUpperCase());

  if (results.length === 0) {
    await sendMessage(chatId, `No results found for <code>${cveId}</code>`);
    return;
  }

  for (const cve of results.slice(0, 3)) {
    let msg = `<b>${cve.id}</b>\n\n`;
    msg += `<b>CVSS:</b> ${cve.cvss || 'N/A'}\n`;
    msg += `<b>Severity:</b> ${cve.severity || 'Unknown'}\n`;
    msg += `<b>Source:</b> ${cve.source}\n`;
    msg += `<b>Published:</b> ${cve.published || 'Unknown'}\n\n`;
    msg += `${cve.description?.slice(0, 500) || 'No description'}\n`;

    if (cve.affectedProducts?.length > 0) {
      msg += `\n<b>Affected Products:</b>\n`;
      cve.affectedProducts.slice(0, 5).forEach(p => { msg += `• ${p}\n`; });
    }

    if (cve.references?.length > 0) {
      msg += `\n<b>References:</b>\n`;
      cve.references.slice(0, 3).forEach(r => { msg += `• ${r}\n`; });
    }

    if (cve.cisaKEV) msg += `\n🏛️ <b>CISA Known Exploited Vulnerability</b>\n`;
    if (cve.exploitAvailable) msg += `⚠️ <b>Exploit Available</b>\n`;

    await sendMessage(chatId, msg);
  }
}

async function handleCritical(chatId) {
  const { getRecentCritical } = await import('./intel.js');
  const critical = getRecentCritical();

  if (critical.length === 0) {
    await sendMessage(chatId, 'No critical CVEs in the last 24 hours.');
    return;
  }

  let msg = `<b>🔴 Critical CVEs (Last 24h)</b>\n\n`;
  for (const cve of critical.slice(0, 10)) {
    msg += `<b>${cve.id}</b> — CVSS ${cve.cvss || '?'}\n`;
    msg += `${cve.description?.slice(0, 120) || 'No description'}...\n`;
    if (cve.cisaKEV) msg += `🏛️ CISA KEV\n`;
    msg += '\n';
  }

  await sendMessage(chatId, msg);
}

async function handleStats(chatId) {
  const { getCVEStats } = await import('./intel.js');
  const stats = getCVEStats();

  let msg = `<b>📊 CVE Statistics</b>\n\n`;
  msg += `<b>Last 24 Hours:</b>\n`;
  msg += `• New CVEs: ${stats.last24h}\n`;
  msg += `• Critical: ${stats.critical24h}\n`;
  msg += `• High: ${stats.high24h}\n\n`;
  msg += `<b>Total Tracked:</b> ${stats.totalTracked}\n`;
  msg += `<b>CISA KEV:</b> ${stats.kevTotal} entries\n`;
  msg += `<b>Last Poll:</b> ${stats.lastPoll || 'Never'}`;

  await sendMessage(chatId, msg);
}

async function handleScan(chatId, domain) {
  if (!domain) {
    await sendMessage(chatId, 'Usage: /scan example.com\n\n<i>Note: Full Nuclei scanning coming soon. Currently performs basic recon checks.</i>');
    return;
  }

  await sendMessage(chatId, `<b>🔍 Scanning ${domain}...</b>\n\n<i>Running basic security checks...</i>`);

  try {
    const results = await quickScan(domain);
    let msg = `<b>🔍 Scan Results: ${domain}</b>\n\n`;

    msg += `<b>SSL/TLS:</b> ${results.ssl ? '✅ Valid' : '❌ Invalid/Missing'}\n`;
    msg += `<b>HTTPS Redirect:</b> ${results.httpsRedirect ? '✅ Yes' : '⚠️ No'}\n\n`;

    if (results.headers) {
      msg += `<b>Security Headers:</b>\n`;
      msg += `• HSTS: ${results.headers.hsts ? '✅' : '❌'}\n`;
      msg += `• CSP: ${results.headers.csp ? '✅' : '❌'}\n`;
      msg += `• X-Frame-Options: ${results.headers.xfo ? '✅' : '❌'}\n`;
      msg += `• X-Content-Type: ${results.headers.xcto ? '✅' : '❌'}\n\n`;
    }

    if (results.server) {
      msg += `<b>Server:</b> ${results.server}\n`;
    }

    msg += `\n<i>Full Nuclei scanning coming in a future update.</i>`;
    await sendMessage(chatId, msg);
  } catch (err) {
    await sendMessage(chatId, `<b>Scan failed:</b> ${err.message}`);
  }
}

async function handleThreats(chatId) {
  const { getLatestAnalysis } = await import('./analysis.js');
  const analysis = getLatestAnalysis();

  if (!analysis) {
    await sendMessage(chatId, 'No threat analysis available yet. Next analysis runs on the hour.');
    return;
  }

  let msg = `<b>🌐 Threat Landscape</b>\n`;
  msg += `<i>Last updated: ${analysis.timestamp || 'Unknown'}</i>\n\n`;
  msg += `<b>Alert Level:</b> ${analysis.alertLevel?.toUpperCase() || 'NORMAL'}\n\n`;
  msg += `${analysis.summary}\n\n`;

  if (analysis.threats?.length > 0) {
    msg += `<b>Active Threats:</b>\n`;
    analysis.threats.forEach(t => { msg += `• ${t}\n`; });
    msg += '\n';
  }

  if (analysis.recommendations?.length > 0) {
    msg += `<b>Recommendations:</b>\n`;
    analysis.recommendations.forEach(r => { msg += `• ${r}\n`; });
  }

  await sendMessage(chatId, msg);
}

/**
 * Quick domain scan — basic HTTP/SSL checks without Nuclei.
 */
async function quickScan(domain) {
  const results = { ssl: false, httpsRedirect: false, headers: {}, server: null };

  try {
    // Check HTTPS
    const httpsRes = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });

    results.ssl = true;
    results.server = httpsRes.headers.get('server');

    const headers = httpsRes.headers;
    results.headers = {
      hsts: !!headers.get('strict-transport-security'),
      csp: !!headers.get('content-security-policy'),
      xfo: !!headers.get('x-frame-options'),
      xcto: !!headers.get('x-content-type-options'),
    };
  } catch (err) {
    // HTTPS failed, try HTTP
    try {
      const httpRes = await fetch(`http://${domain}`, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
      });

      results.server = httpRes.headers.get('server');
      const location = httpRes.headers.get('location');
      results.httpsRedirect = location?.startsWith('https://');
    } catch {
      // Both failed
    }
  }

  return results;
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
