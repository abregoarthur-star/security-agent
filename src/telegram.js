/**
 * Telegram Bot — Security Agent Commands & Alerts
 *
 * 16 commands for maximum control. HTML parse mode.
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
      case '/underground': await handleUnderground(chatId); break;
      case '/pocs': await handlePOCs(chatId); break;
      case '/wild': await handleWild(chatId); break;
      case '/analyze': await handleAnalyzeCVE(chatId, args); break;
      case '/template': await handleTemplateCVE(chatId, args); break;
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
  return `<b>🛡️ Uber Security Agent v2.0</b>

Autonomous CVE intelligence and vulnerability monitoring powered by Claude Opus 4.6.

<b>15 Intelligence Feeds:</b>

<b>Core (7):</b>
• NVD, CISA KEV, OSV.dev, GitHub Advisories
• Exploit-DB, Packet Storm, The Hacker News

<b>Underground (8):</b>
• Full Disclosure, oss-security
• Vulners.com (200+ sources)
• GitHub PoC Monitor, InTheWild.io
• Nuclei Templates, AttackerKB, MITRE ATT&CK

<b>Capabilities:</b>
• Real-time critical CVE + exploit + PoC alerts
• Underground intelligence from researcher communities
• Opus 4.6 threat landscape analysis (every 15 min)
• Bug bounty opportunity identification
• In-the-wild exploitation tracking
• Daily security briefings (8 AM ET)

Type /help for all commands.`;
}

function getHelpMessage() {
  return `<b>🛡️ Security Agent Commands</b>

<b>Intelligence:</b>
/status — Agent health, feeds (15), model info
/stats — CVE statistics (24h)
/critical — Recent critical/high CVEs
/cve [ID] — Look up a specific CVE
/threats — Opus 4.6 threat analysis
/bounty — Bug bounty opportunities
/exploits — Recent public exploits
/news — Security news headlines
/feeds — Feed health dashboard

<b>Underground Intel:</b>
/underground — Latest underground intelligence
/pocs — Recent GitHub PoC exploit repos
/wild — CVEs exploited in the wild

<b>Deep Analysis (Opus 4.6):</b>
/analyze [CVE-ID] — Full exploit analysis (exploitability, impact, fix, bounty)
/template [CVE-ID] — Generate Nuclei detection template

<b>Scanning:</b>
/scan [domain] — Full security scan

<b>System:</b>
/chatid — Show your chat ID
/help — This help message

<b>Automated Alerts:</b>
• Critical/High CVE alerts — every 5 min
• New exploit alerts — every 5 min
• New PoC exploit code alerts — every 5 min
• Opus 4.6 threat digest — every 15 min
• Top 3 critical CVE deep analysis — every 15 min
• Bounty opportunities — every 15 min
• Daily briefing — 8:00 AM ET`;
}

async function handleStatus(chatId) {
  const { getCVEStats, getFeedStatus } = await import('./intel.js');
  const { getLatestAnalysis } = await import('./analysis.js');
  const { getUndergroundFeedStatus } = await import('./underground.js');
  const stats = getCVEStats();
  const feedStatus = getFeedStatus();
  const analysis = getLatestAnalysis();
  const ugStatus = getUndergroundFeedStatus();

  let msg = `<b>🛡️ Uber Security Agent v2.0 Status</b>\n\n`;

  msg += `<b>Core Feeds (7):</b>\n`;
  msg += `• NVD: ${stats.nvdStatus}\n`;
  msg += `• CISA KEV: ${stats.kevStatus}\n`;
  msg += `• OSV.dev: ${stats.osvStatus}\n`;
  msg += `• GitHub Advisories: ${stats.ghStatus}\n`;
  msg += `• Exploit-DB: ${stats.exploitdbStatus}\n`;
  msg += `• Packet Storm: ${stats.packetstormStatus}\n`;
  msg += `• The Hacker News: ${stats.thnStatus}\n\n`;

  msg += `<b>Underground Feeds (8):</b>\n`;
  msg += `• Full Disclosure: ${ugStatus.feeds.fulldisclosure}\n`;
  msg += `• oss-security: ${ugStatus.feeds.osssecurity}\n`;
  msg += `• Vulners: ${ugStatus.feeds.vulners}\n`;
  msg += `• GitHub PoCs: ${ugStatus.feeds.pocs}\n`;
  msg += `• InTheWild: ${ugStatus.feeds.inthewild}\n`;
  msg += `• Nuclei Templates: ${ugStatus.feeds.nuclei}\n`;
  msg += `• AttackerKB: ${ugStatus.feeds.attackerkb}\n`;
  msg += `• MITRE ATT&CK: ${ugStatus.feeds.mitre}\n\n`;

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
    await sendMessage(chatId, 'Usage: /scan example.com\n\nComprehensive security scan: SSL, headers, DNS, tech detection, exposure checks.');
    return;
  }

  await sendMessage(chatId, `<b>🔍 Scanning ${domain}...</b>\n<i>Running SSL, headers, DNS, technology, and exposure checks...</i>`);

  try {
    const { runDomainScan } = await import('./scanner.js');
    const results = await runDomainScan(domain);

    // Build the report — split into multiple messages if needed
    let msg = `<b>🔍 Scan Report: ${results.domain}</b>\n`;
    msg += `<i>Completed in ${(results.scanTime / 1000).toFixed(1)}s</i>\n\n`;

    // Score and grade
    msg += `<b>Security Score: ${results.score}/100 (${results.grade})</b>\n`;
    msg += `Findings: ${results.summary.critical} critical, ${results.summary.high} high, ${results.summary.medium} medium, ${results.summary.low} low, ${results.summary.info} info\n\n`;

    // Critical and High findings first
    const urgent = results.findings.filter(f => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.status !== 'PASS' && f.status !== 'INFO');
    if (urgent.length > 0) {
      msg += `<b>🔴 Critical/High Issues:</b>\n`;
      for (const f of urgent) {
        const icon = f.severity === 'CRITICAL' ? '🔴' : '🟠';
        msg += `${icon} <b>[${f.severity}]</b> ${f.check}\n`;
        msg += `   ${f.detail}\n`;
      }
      msg += '\n';
    }

    // Medium findings
    const medium = results.findings.filter(f => f.severity === 'MEDIUM' && f.status !== 'PASS' && f.status !== 'INFO');
    if (medium.length > 0) {
      msg += `<b>🟡 Medium Issues:</b>\n`;
      for (const f of medium) {
        msg += `⚠️ ${f.check}: ${f.detail}\n`;
      }
      msg += '\n';
    }

    // Passed checks summary
    const passed = results.findings.filter(f => f.status === 'PASS');
    if (passed.length > 0) {
      msg += `<b>✅ Passed (${passed.length}):</b>\n`;
      for (const f of passed) {
        msg += `✅ ${f.check}\n`;
      }
      msg += '\n';
    }

    // Technology detection
    if (results.technology?.server || results.technology?.poweredBy || results.technology?.detectedTech?.length > 0) {
      msg += `<b>🔧 Technology:</b>\n`;
      if (results.technology.server) msg += `Server: ${results.technology.server}\n`;
      if (results.technology.poweredBy) msg += `X-Powered-By: ${results.technology.poweredBy} ⚠️\n`;
      if (results.technology.detectedTech?.length > 0) msg += `Stack: ${results.technology.detectedTech.join(', ')}\n`;
      msg += '\n';
    }

    // DNS summary
    if (results.dns && !results.dns.error) {
      msg += `<b>📡 DNS:</b>\n`;
      if (results.dns.a?.length) msg += `A: ${results.dns.a.slice(0, 2).join(', ')}\n`;
      if (results.dns.ns?.length) msg += `NS: ${results.dns.ns.slice(0, 2).join(', ')}\n`;
      if (results.dns.mx?.length) msg += `MX: ${results.dns.mx.slice(0, 2).map(m => m.exchange).join(', ')}\n`;
      msg += `Email: SPF ${results.dns.emailSecurity?.spf ? '✅' : '❌'} | DMARC ${results.dns.emailSecurity?.dmarc ? '✅' : '❌'} | DKIM ${results.dns.emailSecurity?.dkim ? '✅' : '❌'}\n`;
      msg += '\n';
    }

    // Exposure alerts
    const exposures = results.exposures?.filter(e => e.exposed) || [];
    if (exposures.length > 0) {
      msg += `<b>🚨 Exposed Paths:</b>\n`;
      for (const e of exposures) {
        const icon = e.severity === 'CRITICAL' ? '🔴' : e.severity === 'HIGH' ? '🟠' : '🟡';
        msg += `${icon} ${e.path} (HTTP ${e.status}) — ${e.desc}\n`;
      }
    }

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
  const { getUndergroundFeedStatus } = await import('./underground.js');
  const status = getFeedStatus();
  const ugStatus = getUndergroundFeedStatus();

  let msg = `<b>📡 Feed Dashboard (15 Feeds)</b>\n\n`;

  msg += `<b>Core Feeds (7):</b>\n`;
  for (const [name, state] of Object.entries(status.feeds)) {
    const lastPoll = status.lastPolls[name];
    msg += `<b>${name.toUpperCase()}:</b> ${state}\n`;
    if (lastPoll) msg += `  Last poll: ${lastPoll}\n`;
    msg += '\n';
  }

  msg += `<b>Underground Feeds (8):</b>\n`;
  for (const [name, state] of Object.entries(ugStatus.feeds)) {
    msg += `<b>${name.toUpperCase()}:</b> ${state}\n`;
  }
  if (ugStatus.lastPoll) {
    msg += `\nLast underground poll: ${ugStatus.lastPoll}`;
  }

  await sendMessage(chatId, msg);
}

async function handleUnderground(chatId) {
  const { getUndergroundIntel } = await import('./underground.js');
  const intel = getUndergroundIntel();

  let msg = `<b>🕵️ Underground Intelligence</b>\n`;
  msg += `<i>Last poll: ${intel.lastPoll || 'Never'}</i>\n\n`;

  // Full Disclosure
  if (intel.fullDisclosure.length > 0) {
    msg += `<b>Full Disclosure:</b>\n`;
    for (const item of intel.fullDisclosure.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
      if (item.cveId) msg += `  CVE: ${item.cveId}\n`;
    }
    msg += '\n';
  }

  // oss-security
  if (intel.ossSecurity.length > 0) {
    msg += `<b>oss-security:</b>\n`;
    for (const item of intel.ossSecurity.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
      if (item.cveId) msg += `  CVE: ${item.cveId}\n`;
    }
    msg += '\n';
  }

  // Vulners
  if (intel.vulners.cves.length > 0 || intel.vulners.exploits.length > 0) {
    msg += `<b>Vulners (${intel.vulners.cves.length} CVEs, ${intel.vulners.exploits.length} exploits):</b>\n`;
    for (const item of intel.vulners.cves.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
    }
    msg += '\n';
  }

  // PoCs
  if (intel.pocs.length > 0) {
    msg += `<b>GitHub PoCs (${intel.pocs.length}):</b>\n`;
    for (const poc of intel.pocs.slice(0, 3)) {
      msg += `• ${poc.title?.slice(0, 60)}`;
      if (poc.cveId) msg += ` [${poc.cveId}]`;
      msg += '\n';
    }
    msg += '\n';
  }

  // InTheWild
  if (intel.inTheWild.length > 0) {
    msg += `<b>Exploited in Wild (${intel.inTheWild.length}):</b>\n`;
    for (const item of intel.inTheWild.slice(0, 3)) {
      msg += `• ${item.cveId || item.title?.slice(0, 60)}\n`;
    }
    msg += '\n';
  }

  // AttackerKB
  if (intel.attackerKB.length > 0) {
    msg += `<b>AttackerKB:</b>\n`;
    for (const item of intel.attackerKB.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
    }
    msg += '\n';
  }

  // Nuclei Templates
  if (intel.nucleiTemplates.length > 0) {
    msg += `<b>Nuclei Templates:</b>\n`;
    for (const item of intel.nucleiTemplates.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
    }
    msg += '\n';
  }

  // MITRE ATT&CK
  if (intel.mitreAttack.length > 0) {
    msg += `<b>MITRE ATT&CK (recent):</b>\n`;
    for (const item of intel.mitreAttack.slice(0, 3)) {
      msg += `• ${item.title?.slice(0, 80)}\n`;
    }
  }

  const totalItems = intel.fullDisclosure.length + intel.ossSecurity.length +
    intel.vulners.cves.length + intel.vulners.exploits.length +
    intel.pocs.length + intel.inTheWild.length +
    intel.nucleiTemplates.length + intel.attackerKB.length + intel.mitreAttack.length;

  if (totalItems === 0) {
    msg += 'No underground intelligence loaded yet. First poll runs on startup.';
  }

  await sendMessage(chatId, msg);
}

async function handlePOCs(chatId) {
  const { getNewPOCs } = await import('./underground.js');
  const pocs = getNewPOCs();

  if (pocs.length === 0) {
    await sendMessage(chatId, 'No PoC exploit repos found yet.');
    return;
  }

  let msg = `<b>🔥 GitHub PoC Exploit Repos</b>\n\n`;
  for (const poc of pocs.slice(0, 10)) {
    msg += `<b>${poc.title}</b>\n`;
    if (poc.cveId) msg += `CVE: ${poc.cveId}\n`;
    if (poc.url) msg += `${poc.url}\n`;
    msg += `${poc.description?.slice(0, 120) || ''}\n\n`;
  }

  msg += `<i>Total: ${pocs.length} PoC repos tracked</i>`;
  await sendMessage(chatId, msg);
}

async function handleWild(chatId) {
  const { getExploitedInWild } = await import('./underground.js');
  const wild = getExploitedInWild();

  if (wild.length === 0) {
    await sendMessage(chatId, 'No in-the-wild exploitation data loaded yet.');
    return;
  }

  let msg = `<b>🌍 CVEs Exploited in the Wild</b>\n`;
  msg += `<i>Source: InTheWild.io</i>\n\n`;
  for (const item of wild.slice(0, 15)) {
    msg += `• <b>${item.cveId || 'Unknown'}</b>`;
    if (item.published) msg += ` — ${new Date(item.published).toLocaleDateString()}`;
    msg += '\n';
    if (item.description && !item.description.includes('is being actively exploited')) {
      msg += `  ${item.description.slice(0, 100)}\n`;
    }
  }

  msg += `\n<i>Total: ${wild.length} CVEs with confirmed exploitation</i>`;
  await sendMessage(chatId, msg);
}

async function handleAnalyzeCVE(chatId, cveId) {
  if (!cveId) {
    await sendMessage(chatId, 'Usage: /analyze CVE-2024-3094\n\nDeep AI analysis: exploitability, impact, fix strategy, bounty potential.');
    return;
  }

  await sendMessage(chatId, `<b>🧠 Analyzing ${cveId} with Opus 4.6...</b>\n<i>Running exploitability, impact, fix, and bounty analysis...</i>`);

  const { searchCVE } = await import('./intel.js');
  const results = await searchCVE(cveId.toUpperCase());

  if (results.length === 0) {
    await sendMessage(chatId, `No CVE data found for <code>${cveId}</code>. Try /cve first to verify it exists.`);
    return;
  }

  const { analyzeExploit } = await import('./exploit-analysis.js');
  const analysis = await analyzeExploit(results[0]);

  if (analysis.error) {
    await sendMessage(chatId, `<b>Analysis failed:</b> ${analysis.error}\n\n${analysis.rawText?.slice(0, 500) || ''}`);
    return;
  }

  // Exploitability
  let msg = `<b>🧠 EXPLOIT ANALYSIS: ${analysis.cveId}</b>\n`;
  msg += `<i>Risk: ${analysis.overallRisk?.toUpperCase() || 'UNKNOWN'}</i>\n\n`;
  msg += `<b>TL;DR:</b> ${analysis.tldr || 'N/A'}\n\n`;

  if (analysis.exploitability) {
    const e = analysis.exploitability;
    msg += `<b>Exploitability:</b>\n`;
    msg += `• Difficulty: ${e.difficulty || 'N/A'}\n`;
    msg += `• Skill Level: ${e.skillLevel || 'N/A'}\n`;
    msg += `• Time to Exploit: ${e.timeToExploit || 'N/A'}\n`;
    msg += `• Auth Required: ${e.authRequired || 'N/A'}\n`;
    msg += `• Exploit Maturity: ${e.exploitMaturity || 'N/A'}\n`;
    if (e.prerequisites?.length) {
      msg += `• Prerequisites: ${e.prerequisites.join(', ')}\n`;
    }
    msg += '\n';
  }

  // Impact
  if (analysis.impact) {
    const i = analysis.impact;
    msg += `<b>Impact:</b>\n`;
    msg += `• Worst Case: ${i.worstCase || 'N/A'}\n`;
    msg += `• Data Exposure: ${i.dataExposure || 'N/A'}\n`;
    msg += `• Lateral Movement: ${i.lateralMovement || 'N/A'}\n`;
    msg += `• Persistence: ${i.persistence || 'N/A'}\n`;
    msg += `• Blast Radius: ${i.blastRadius || 'N/A'}\n`;
    msg += '\n';
  }

  // Send first message (exploitability + impact)
  await sendMessage(chatId, msg);

  // Fix
  let msg2 = '';
  if (analysis.fix) {
    const f = analysis.fix;
    msg2 += `<b>Fix/Remediation:</b>\n`;
    msg2 += `• Priority: ${f.priority || 'N/A'}\n`;
    msg2 += `• Fix: ${f.primaryFix || 'N/A'}\n`;
    msg2 += `• Time to Fix: ${f.timeToFix || 'N/A'}\n`;
    msg2 += `• Vendor Patch: ${f.vendorPatchStatus || 'N/A'}\n`;
    if (f.workaround) msg2 += `• Workaround: ${f.workaround}\n`;
    if (f.steps?.length) {
      msg2 += `• Steps:\n`;
      f.steps.forEach((s, i) => { msg2 += `  ${i + 1}. ${s}\n`; });
    }
    msg2 += '\n';
  }

  // Bounty
  if (analysis.bounty) {
    const b = analysis.bounty;
    msg2 += `<b>Bounty Strategy:</b>\n`;
    msg2 += `• Worth Reporting: ${b.worthReporting ? 'YES' : 'NO'}\n`;
    msg2 += `• Estimated Bounty: ${b.estimatedBounty || 'N/A'}\n`;
    msg2 += `• Duplicate Risk: ${b.duplicateRisk || 'N/A'}\n`;
    if (b.targetPrograms?.length) {
      msg2 += `• Programs: ${b.targetPrograms.join(', ')}\n`;
    }
    if (b.reportStrategy) msg2 += `• Strategy: ${b.reportStrategy}\n`;
    if (b.chainPotential) msg2 += `• Chain Potential: ${b.chainPotential}\n`;
    msg2 += '\n';
  }

  // Nuclei template feasibility
  if (analysis.nucleiTemplate) {
    const n = analysis.nucleiTemplate;
    msg2 += `<b>Nuclei Template:</b>\n`;
    msg2 += `• Feasible: ${n.feasible ? 'YES' : 'NO'}\n`;
    msg2 += `• Detection: ${n.detectionMethod || 'N/A'}\n`;
    msg2 += `• FP Risk: ${n.falsePositiveRisk || 'N/A'}\n`;
    if (n.feasible) msg2 += `\nUse /template ${analysis.cveId} to generate the template.\n`;
  }

  if (msg2) {
    await sendMessage(chatId, msg2);
  }
}

async function handleTemplateCVE(chatId, cveId) {
  if (!cveId) {
    await sendMessage(chatId, 'Usage: /template CVE-2024-3094\n\nGenerates a Nuclei YAML detection template for the CVE.');
    return;
  }

  await sendMessage(chatId, `<b>Generating Nuclei template for ${cveId}...</b>`);

  const { searchCVE } = await import('./intel.js');
  const results = await searchCVE(cveId.toUpperCase());

  if (results.length === 0) {
    await sendMessage(chatId, `No CVE data found for <code>${cveId}</code>.`);
    return;
  }

  const { generateNucleiTemplate } = await import('./exploit-analysis.js');
  const template = await generateNucleiTemplate(results[0]);

  let msg = `<b>Nuclei Template: ${cveId}</b>\n\n`;
  msg += `<pre>${template.slice(0, 3500)}</pre>`;

  await sendMessage(chatId, msg);
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
