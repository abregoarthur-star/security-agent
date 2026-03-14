/**
 * Telegram Bot — Security Agent Commands & Alerts
 *
 * 13 commands for maximum control. HTML parse mode.
 */

const TELEGRAM_API = 'https://api.telegram.org/bot';

export async function sendMessage(chatId, text, options = {}) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  if (!token) throw new Error('TELEGRAM_BOT_TOKEN not set');

  // Telegram max message length is 4096
  if (text.length > 4000) {
    text = text.slice(0, 3990) + '\n\n<i>...truncated</i>';
  }

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

export async function setWebhook(webhookUrl) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const url = `${TELEGRAM_API}${token}/setWebhook?url=${encodeURIComponent(webhookUrl)}`;
  const res = await fetch(url);
  return res.json();
}

export async function handleCommand(message) {
  const chatId = message.chat.id;
  const text = message.text?.trim() || '';
  const cmd = text.split(' ')[0].toLowerCase();
  const args = text.slice(cmd.length).trim();

  try {
    switch (cmd) {
      case '/start': await sendMessage(chatId, getStartMessage()); break;
      case '/status': await handleStatus(chatId); break;
      case '/cve': await handleCVELookup(chatId, args); break;
      case '/critical': await handleCritical(chatId); break;
      case '/stats': await handleStats(chatId); break;
      case '/scan': await handleScan(chatId, args); break;
      case '/threats': await handleThreats(chatId); break;
      case '/bounty': await handleBounty(chatId); break;
      case '/exploits': await handleExploits(chatId); break;
      case '/news': await handleNews(chatId); break;
      case '/feeds': await handleFeeds(chatId); break;
      case '/chatid': await sendMessage(chatId, `Your chat ID: <code>${chatId}</code>`); break;
      case '/help': await sendMessage(chatId, getHelpMessage()); break;
      default:
        if (text.startsWith('/')) {
          await sendMessage(chatId, `Unknown command. Type /help for commands.`);
        }
    }
  } catch (err) {
    console.error(`Command ${cmd} failed:`, err.message);
    try {
      await sendMessage(chatId, `<b>Error:</b> ${err.message}`);
    } catch (sendErr) {
      console.error('Failed to send error message to Telegram:', sendErr.message);
    }
  }
}

function getStartMessage() {
  return `<b>🛡️ Uber Security Agent</b>

Autonomous CVE intelligence and vulnerability monitoring powered by Claude Opus 4.6.

<b>7 Intelligence Feeds:</b>
• NVD (National Vulnerability Database)
• CISA KEV (Known Exploited Vulnerabilities)
• OSV.dev (Open Source Vulnerabilities)
• GitHub Security Advisories
• Exploit-DB (new exploits)
• Packet Storm Security
• The Hacker News

<b>Capabilities:</b>
• Real-time critical CVE + exploit alerts
• Opus 4.6 threat landscape analysis (every 15 min)
• Bug bounty opportunity identification
• Nuclei template prioritization
• SMB vulnerability monitoring
• Daily security briefings (8 AM ET)

Type /help for all commands.`;
}

function getHelpMessage() {
  return `<b>🛡️ Security Agent Commands</b>

<b>Intelligence:</b>
/status — Agent health, feeds, model info
/stats — CVE statistics (24h)
/critical — Recent critical/high CVEs
/cve [ID] — Look up a specific CVE
/threats — Opus 4.6 threat analysis
/bounty — Bug bounty opportunities
/exploits — Recent public exploits
/news — Security news headlines
/feeds — Feed health dashboard

<b>Scanning:</b>
/scan [domain] — Security header check

<b>System:</b>
/chatid — Show your chat ID
/help — This help message

<b>Automated Alerts:</b>
• Critical/High CVE alerts — every 5 min
• New exploit alerts — every 5 min
• Opus 4.6 threat digest — every 15 min
• Bounty opportunities — every 15 min
• Daily briefing — 8:00 AM ET`;
}

async function handleStatus(chatId) {
  const { getCVEStats, getFeedStatus } = await import('./intel.js');
  const { getLatestAnalysis } = await import('./analysis.js');
  const stats = getCVEStats();
  const feedStatus = getFeedStatus();
  const analysis = getLatestAnalysis();

  let msg = `<b>🛡️ Uber Security Agent Status</b>\n\n`;

  msg += `<b>Intelligence Feeds (7):</b>\n`;
  msg += `• NVD: ${stats.nvdStatus}\n`;
  msg += `• CISA KEV: ${stats.kevStatus}\n`;
  msg += `• OSV.dev: ${stats.osvStatus}\n`;
  msg += `• GitHub Advisories: ${stats.ghStatus}\n`;
  msg += `• Exploit-DB: ${stats.exploitdbStatus}\n`;
  msg += `• Packet Storm: ${stats.packetstormStatus}\n`;
  msg += `• The Hacker News: ${stats.thnStatus}\n\n`;

  msg += `<b>Database:</b>\n`;
  msg += `• CVEs tracked: ${stats.totalTracked}\n`;
  msg += `• Critical (24h): ${stats.critical24h}\n`;
  msg += `• Bounty-relevant: ${stats.bountyRelevant24h}\n`;
  msg += `• Exploits available: ${stats.exploitsAvailable}\n`;
  msg += `• CISA KEV: ${stats.kevTotal} total\n`;
  msg += `• Last poll: ${stats.lastPoll || 'Never'}\n\n`;

  msg += `<b>Analysis Engine:</b>\n`;
  msg += `• Model: Claude Opus 4.6\n`;
  msg += `• API: ${process.env.ANTHROPIC_API_KEY ? '✅ Connected' : '❌ No API key'}\n`;
  if (analysis) {
    msg += `• Last analysis: ${analysis.timestamp}\n`;
    msg += `• Alert level: ${analysis.alertLevel?.toUpperCase()}\n`;
    if (analysis.inputTokens) msg += `• Tokens: ${analysis.inputTokens} in / ${analysis.outputTokens} out\n`;
  }
  msg += '\n';

  msg += `<b>Brain Link:</b> ${process.env.BRAIN_API_URL ? '✅ Connected' : '❌ Not configured'}\n`;
  msg += `<b>Telegram:</b> ✅ Connected\n`;
  msg += `<b>Uptime:</b> ${formatUptime(process.uptime())}`;

  await sendMessage(chatId, msg);
}

async function handleCVELookup(chatId, cveId) {
  if (!cveId) {
    await sendMessage(chatId, 'Usage: /cve CVE-2024-3094\n\nLooks up CVE details from local store + NVD API.');
    return;
  }

  await sendMessage(chatId, `<b>🔍 Looking up ${cveId}...</b>`);

  const { searchCVE } = await import('./intel.js');
  const results = await searchCVE(cveId.toUpperCase());

  if (results.length === 0) {
    await sendMessage(chatId, `No results for <code>${cveId}</code>`);
    return;
  }

  for (const cve of results.slice(0, 3)) {
    let msg = `<b>${cve.id}</b>\n\n`;
    msg += `<b>CVSS:</b> ${cve.cvss || 'N/A'}\n`;
    msg += `<b>Severity:</b> ${cve.severity || 'Unknown'}\n`;
    if (cve.attackVector) msg += `<b>Attack Vector:</b> ${cve.attackVector}\n`;
    msg += `<b>Source:</b> ${cve.source}\n`;
    msg += `<b>Published:</b> ${cve.published || 'Unknown'}\n`;

    if (cve.weaknesses?.length > 0) {
      msg += `<b>Weaknesses:</b> ${cve.weaknesses.join(', ')}\n`;
    }

    msg += `\n${cve.description?.slice(0, 500) || 'No description'}\n`;

    if (cve.affectedProducts?.length > 0) {
      msg += `\n<b>Affected:</b>\n`;
      cve.affectedProducts.slice(0, 5).forEach(p => { msg += `• ${p}\n`; });
    }

    if (cve.references?.length > 0) {
      msg += `\n<b>References:</b>\n`;
      cve.references.slice(0, 3).forEach(r => { msg += `• ${r}\n`; });
    }

    if (cve.cisaKEV) msg += `\n🏛️ <b>CISA Known Exploited</b>`;
    if (cve.exploitAvailable) msg += `\n⚠️ <b>Exploit Available</b>`;
    if (cve.bountyRelevant) msg += `\n💰 <b>Bounty Relevant</b>`;

    await sendMessage(chatId, msg);
  }
}

async function handleCritical(chatId) {
  const { getRecentCritical } = await import('./intel.js');
  const critical = getRecentCritical();

  if (critical.length === 0) {
    await sendMessage(chatId, 'No critical/high CVEs in the last 24 hours.');
    return;
  }

  let msg = `<b>🔴 Critical/High CVEs (24h)</b>\n\n`;
  for (const cve of critical.slice(0, 10)) {
    msg += `<b>${cve.id}</b> — CVSS ${cve.cvss || '?'} | ${cve.severity || '?'}\n`;
    msg += `${cve.description?.slice(0, 120)}...\n`;
    if (cve.cisaKEV) msg += `🏛️ KEV `;
    if (cve.exploitAvailable) msg += `⚠️ Exploit `;
    if (cve.bountyRelevant) msg += `💰 Bounty`;
    msg += '\n\n';
  }

  msg += `<i>Total: ${critical.length} critical/high CVEs</i>`;
  await sendMessage(chatId, msg);
}

async function handleStats(chatId) {
  const { getCVEStats } = await import('./intel.js');
  const stats = getCVEStats();

  let msg = `<b>📊 CVE Intelligence Stats</b>\n\n`;
  msg += `<b>Last 24 Hours:</b>\n`;
  msg += `• New CVEs: ${stats.last24h}\n`;
  msg += `• Critical: ${stats.critical24h}\n`;
  msg += `• High: ${stats.high24h}\n`;
  msg += `• Bounty-relevant: ${stats.bountyRelevant24h}\n`;
  msg += `• Exploits available: ${stats.exploitsAvailable}\n\n`;
  msg += `<b>Global Database:</b>\n`;
  msg += `• Total tracked: ${stats.totalTracked}\n`;
  msg += `• CISA KEV: ${stats.kevTotal} entries\n`;
  msg += `• GitHub advisories: ${stats.ghAdvisoryCount}\n`;
  msg += `• Exploits indexed: ${stats.exploitCount}\n`;
  msg += `• Security news: ${stats.securityNewsCount} articles\n\n`;
  msg += `<b>Last Poll:</b> ${stats.lastPoll || 'Never'}`;

  await sendMessage(chatId, msg);
}

async function handleScan(chatId, domain) {
  if (!domain) {
    await sendMessage(chatId, 'Usage: /scan example.com\n\nChecks SSL, security headers, and server info.');
    return;
  }

  await sendMessage(chatId, `<b>🔍 Scanning ${domain}...</b>`);

  try {
    const results = await quickScan(domain);
    let msg = `<b>🔍 Scan: ${domain}</b>\n\n`;

    // Score
    let score = 0;
    const checks = [];

    if (results.ssl) { score += 20; checks.push('✅ SSL/TLS valid'); }
    else checks.push('❌ SSL/TLS invalid or missing');

    if (results.httpsRedirect) { score += 10; checks.push('✅ HTTPS redirect'); }
    else checks.push('⚠️ No HTTPS redirect');

    if (results.headers.hsts) { score += 15; checks.push('✅ HSTS enabled'); }
    else checks.push('❌ No HSTS');

    if (results.headers.csp) { score += 20; checks.push('✅ Content Security Policy'); }
    else checks.push('❌ No CSP');

    if (results.headers.xfo) { score += 10; checks.push('✅ X-Frame-Options'); }
    else checks.push('❌ No X-Frame-Options');

    if (results.headers.xcto) { score += 10; checks.push('✅ X-Content-Type-Options'); }
    else checks.push('❌ No X-Content-Type-Options');

    if (results.headers.referrer) { score += 5; checks.push('✅ Referrer-Policy'); }
    else checks.push('⚠️ No Referrer-Policy');

    if (results.headers.permissions) { score += 10; checks.push('✅ Permissions-Policy'); }
    else checks.push('⚠️ No Permissions-Policy');

    const grade = score >= 80 ? 'A' : score >= 60 ? 'B' : score >= 40 ? 'C' : score >= 20 ? 'D' : 'F';
    msg += `<b>Security Score: ${score}/100 (${grade})</b>\n\n`;

    checks.forEach(c => { msg += `${c}\n`; });

    if (results.server) msg += `\n<b>Server:</b> ${results.server}`;
    if (results.poweredBy) msg += `\n<b>X-Powered-By:</b> ${results.poweredBy} ⚠️ (info leak)`;

    await sendMessage(chatId, msg);
  } catch (err) {
    await sendMessage(chatId, `<b>Scan failed:</b> ${err.message}`);
  }
}

async function handleThreats(chatId) {
  const { getLatestAnalysis } = await import('./analysis.js');
  const analysis = getLatestAnalysis();

  if (!analysis) {
    await sendMessage(chatId, 'No threat analysis available yet. Next analysis runs in <15 minutes.');
    return;
  }

  let msg = `<b>🧠 Threat Landscape (Opus 4.6)</b>\n`;
  msg += `<i>${analysis.timestamp}</i>\n\n`;
  msg += `<b>Alert Level:</b> ${analysis.alertLevel?.toUpperCase()}\n\n`;
  msg += `${analysis.summary}\n\n`;

  if (analysis.threats?.length > 0) {
    msg += `<b>Active Threats:</b>\n`;
    analysis.threats.forEach(t => { msg += `• ${t}\n`; });
    msg += '\n';
  }

  if (analysis.exploitWatch?.length > 0) {
    msg += `<b>Exploit Watch:</b>\n`;
    analysis.exploitWatch.forEach(e => { msg += `• ${e}\n`; });
    msg += '\n';
  }

  if (analysis.attackTrends?.length > 0) {
    msg += `<b>Attack Trends:</b>\n`;
    analysis.attackTrends.forEach(t => { msg += `• ${t}\n`; });
    msg += '\n';
  }

  if (analysis.smbAlerts?.length > 0) {
    msg += `<b>SMB Alerts:</b>\n`;
    analysis.smbAlerts.forEach(a => { msg += `• ${a}\n`; });
    msg += '\n';
  }

  if (analysis.recommendations?.length > 0) {
    msg += `<b>Actions:</b>\n`;
    analysis.recommendations.forEach(r => { msg += `• ${r}\n`; });
  }

  if (analysis.marketIntel) {
    msg += `\n<b>Market:</b> ${analysis.marketIntel}`;
  }

  await sendMessage(chatId, msg);
}

async function handleBounty(chatId) {
  const { getLatestAnalysis } = await import('./analysis.js');
  const { getBountyRelevantCVEs } = await import('./intel.js');
  const analysis = getLatestAnalysis();
  const bountyVulns = getBountyRelevantCVEs();

  let msg = `<b>💰 Bug Bounty Intelligence</b>\n\n`;

  // Opus-identified opportunities
  if (analysis?.bountyOpportunities?.length > 0) {
    msg += `<b>Opus 4.6 Opportunities:</b>\n`;
    for (const opp of analysis.bountyOpportunities.slice(0, 5)) {
      msg += `\n<b>${opp.cveId || 'N/A'}</b>\n`;
      msg += `Target: ${opp.target}\n`;
      msg += `Bounty: ${opp.estimatedBounty}\n`;
      msg += `Difficulty: ${opp.difficulty}\n`;
      msg += `Strategy: ${opp.strategy}\n`;
    }
    msg += '\n';
  }

  // Nuclei template priorities
  if (analysis?.nucleiTemplatePriority?.length > 0) {
    msg += `<b>Nuclei Template Priority:</b>\n`;
    analysis.nucleiTemplatePriority.slice(0, 5).forEach(t => { msg += `• ${t}\n`; });
    msg += '\n';
  }

  // Bounty-relevant CVEs from feeds
  if (bountyVulns.length > 0) {
    msg += `<b>Bounty-Relevant CVEs:</b>\n`;
    for (const cve of bountyVulns.slice(0, 5)) {
      msg += `• <b>${cve.id}</b> — CVSS ${cve.cvss}`;
      if (cve.weaknesses?.length) msg += ` — ${cve.weaknesses[0]}`;
      if (cve.exploitAvailable) msg += ` ⚠️`;
      msg += '\n';
    }
  }

  if (!analysis?.bountyOpportunities?.length && bountyVulns.length === 0) {
    msg += 'No bounty opportunities identified yet. Analysis runs every 15 min.';
  }

  await sendMessage(chatId, msg);
}

async function handleExploits(chatId) {
  const { getRecentExploits } = await import('./intel.js');
  const exploits = getRecentExploits();

  if (exploits.length === 0) {
    await sendMessage(chatId, 'No recent exploits indexed yet.');
    return;
  }

  let msg = `<b>⚡ Recent Exploits</b>\n\n`;
  for (const e of exploits.slice(0, 10)) {
    msg += `• <b>${e.title?.slice(0, 80)}</b>\n`;
    if (e.cveId) msg += `  CVE: ${e.cveId}\n`;
    msg += `  Source: ${e.source}\n\n`;
  }

  await sendMessage(chatId, msg);
}

async function handleNews(chatId) {
  const { getSecurityNews } = await import('./intel.js');
  const news = getSecurityNews();

  if (news.length === 0) {
    await sendMessage(chatId, 'No security news loaded yet.');
    return;
  }

  let msg = `<b>📰 Security News</b>\n\n`;
  for (const n of news.slice(0, 10)) {
    msg += `• <b>${n.title}</b>\n`;
    msg += `  ${n.source}\n\n`;
  }

  await sendMessage(chatId, msg);
}

async function handleFeeds(chatId) {
  const { getFeedStatus } = await import('./intel.js');
  const status = getFeedStatus();

  let msg = `<b>📡 Feed Dashboard</b>\n\n`;

  for (const [name, state] of Object.entries(status.feeds)) {
    const lastPoll = status.lastPolls[name];
    msg += `<b>${name.toUpperCase()}:</b> ${state}\n`;
    if (lastPoll) msg += `  Last poll: ${lastPoll}\n`;
    msg += '\n';
  }

  await sendMessage(chatId, msg);
}

// ─── Quick Scan ─────────────────────────────────────────

async function quickScan(domain) {
  const results = {
    ssl: false, httpsRedirect: false,
    headers: { hsts: false, csp: false, xfo: false, xcto: false, referrer: false, permissions: false },
    server: null, poweredBy: null,
  };

  try {
    const httpsRes = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });

    results.ssl = true;
    results.server = httpsRes.headers.get('server');
    results.poweredBy = httpsRes.headers.get('x-powered-by');

    const h = httpsRes.headers;
    results.headers = {
      hsts: !!h.get('strict-transport-security'),
      csp: !!h.get('content-security-policy'),
      xfo: !!h.get('x-frame-options'),
      xcto: !!h.get('x-content-type-options'),
      referrer: !!h.get('referrer-policy'),
      permissions: !!h.get('permissions-policy'),
    };
  } catch {
    try {
      const httpRes = await fetch(`http://${domain}`, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
      });

      results.server = httpRes.headers.get('server');
      results.poweredBy = httpRes.headers.get('x-powered-by');
      const location = httpRes.headers.get('location');
      results.httpsRedirect = location?.startsWith('https://');
    } catch {}
  }

  return results;
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
