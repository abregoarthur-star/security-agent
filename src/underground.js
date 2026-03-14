/**
 * Underground Intelligence Engine — Deep Sources
 *
 * 8 additional feeds from security researcher communities and exploit databases.
 * All legal, public sources — not actual dark web.
 *
 * 1. Full Disclosure Mailing List — raw vulnerability disclosures (RSS)
 * 2. oss-security Mailing List — open source security discussions (RSS)
 * 3. Vulners.com API — aggregates 200+ sources (free tier)
 * 4. POC-in-GitHub Monitor — proof-of-concept exploit repos (GitHub search)
 * 5. InTheWild.io — CVEs exploited in the wild
 * 6. Nuclei Templates Watch — new detection templates (GitHub API)
 * 7. AttackerKB (Rapid7) — community-rated exploit assessments
 * 8. MITRE ATT&CK Updates — new attack techniques (weekly poll)
 *
 * These feeds provide early-warning intelligence that often surfaces
 * before NVD or mainstream feeds pick it up.
 */

// ─── In-memory store ────────────────────────────────────
let undergroundStore = {
  fullDisclosure: [],
  ossSecurity: [],
  vulners: { cves: [], exploits: [] },
  pocs: [],
  inTheWild: [],
  nucleiTemplates: [],
  attackerKB: [],
  mitreAttack: { techniques: [], lastPoll: null },
  lastPoll: null,
  feedStatus: {
    fulldisclosure: 'pending',
    osssecurity: 'pending',
    vulners: 'pending',
    pocs: 'pending',
    inthewild: 'pending',
    nuclei: 'pending',
    attackerkb: 'pending',
    mitre: 'pending',
  },
};

// ─── RSS Parser (same pattern as intel.js) ──────────────

function parseRSSItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;

  while ((match = itemRegex.exec(xml)) !== null) {
    const content = match[1];
    items.push({
      title: extractTag(content, 'title'),
      link: extractTag(content, 'link'),
      description: extractTag(content, 'description'),
      pubDate: extractTag(content, 'pubDate'),
    });
  }

  return items;
}

function extractTag(xml, tag) {
  const match = xml.match(new RegExp(`<${tag}>\\s*(?:<!\\[CDATA\\[)?([\\s\\S]*?)(?:\\]\\]>)?\\s*</${tag}>`, 'i'));
  return match ? match[1].trim() : null;
}

/**
 * Extract CVE IDs from text.
 */
function extractCVEIds(text) {
  if (!text) return [];
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map(m => m.toUpperCase()))];
}

/**
 * Standardize output format for all feeds.
 */
function makeIntelItem({ title, url, cveId, published, source, description, type }) {
  return {
    title: title || 'Untitled',
    url: url || null,
    cveId: cveId || null,
    published: published || new Date().toISOString(),
    source,
    description: description?.slice(0, 500) || '',
    type: type || 'disclosure',
  };
}

// ─── 1. Full Disclosure Mailing List ────────────────────

async function pollFullDisclosure() {
  const res = await fetch('https://seclists.org/rss/fulldisclosure.rss', {
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'SecurityAgent/1.0' },
  });

  if (!res.ok) throw new Error(`Full Disclosure RSS: ${res.status}`);

  const xml = await res.text();
  const items = parseRSSItems(xml).map(item => {
    const cveIds = extractCVEIds(`${item.title} ${item.description}`);
    return makeIntelItem({
      title: item.title,
      url: item.link,
      cveId: cveIds[0] || null,
      published: item.pubDate,
      source: 'Full Disclosure',
      description: item.description?.replace(/<[^>]+>/g, ''),
      type: 'disclosure',
    });
  });

  undergroundStore.fullDisclosure = items.slice(0, 30);
  undergroundStore.feedStatus.fulldisclosure = '✅ Active';
  return items;
}

// ─── 2. oss-security Mailing List ───────────────────────

async function pollOSSSecurity() {
  // Openwall removed their RSS feeds. Use seclists.org mirror instead.
  const urls = [
    'https://seclists.org/rss/oss-sec.rss',
    'https://www.openwall.com/lists/oss-security/rss.xml',
  ];

  let xml = null;
  let lastErr = null;

  for (const url of urls) {
    try {
      const res = await fetch(url, {
        signal: AbortSignal.timeout(15000),
        headers: { 'User-Agent': 'SecurityAgent/1.0' },
      });
      if (res.ok) {
        xml = await res.text();
        break;
      }
    } catch (err) {
      lastErr = err;
    }
  }

  if (!xml) throw lastErr || new Error('oss-security: all RSS URLs failed');

  const items = parseRSSItems(xml).map(item => {
    const cveIds = extractCVEIds(`${item.title} ${item.description}`);
    return makeIntelItem({
      title: item.title,
      url: item.link,
      cveId: cveIds[0] || null,
      published: item.pubDate,
      source: 'oss-security',
      description: item.description?.replace(/<[^>]+>/g, ''),
      type: 'disclosure',
    });
  });

  undergroundStore.ossSecurity = items.slice(0, 30);
  undergroundStore.feedStatus.osssecurity = '✅ Active';
  return items;
}

// ─── 3. Vulners.com API ─────────────────────────────────

async function pollVulners() {
  // Fetch recent CVEs
  const cveRes = await fetch(
    'https://vulners.com/api/v3/search/lucene/?query=type:cve%20AND%20published:[now-1d%20TO%20now]&size=20',
    {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'SecurityAgent/1.0' },
    }
  );

  const cves = [];
  const exploits = [];

  if (cveRes.ok) {
    const data = await cveRes.json();
    for (const doc of (data.data?.search || [])) {
      const src = doc._source || doc;
      cves.push(makeIntelItem({
        title: src.title || src.id,
        url: src.href || `https://vulners.com/${src.type}/${src.id}`,
        cveId: src.id?.startsWith('CVE-') ? src.id : (extractCVEIds(src.description)?.[0] || null),
        published: src.published,
        source: 'Vulners',
        description: src.description,
        type: 'disclosure',
      }));
    }
  }

  // Fetch recent exploits
  try {
    const exploitRes = await fetch(
      'https://vulners.com/api/v3/search/lucene/?query=type:exploit%20AND%20published:[now-1d%20TO%20now]&size=20',
      {
        signal: AbortSignal.timeout(15000),
        headers: { 'User-Agent': 'SecurityAgent/1.0' },
      }
    );

    if (exploitRes.ok) {
      const data = await exploitRes.json();
      for (const doc of (data.data?.search || [])) {
        const src = doc._source || doc;
        exploits.push(makeIntelItem({
          title: src.title || src.id,
          url: src.href || `https://vulners.com/${src.type}/${src.id}`,
          cveId: extractCVEIds(src.description)?.[0] || null,
          published: src.published,
          source: 'Vulners',
          description: src.description,
          type: 'exploit',
        }));
      }
    }
  } catch {
    // Exploit query failure is non-critical
  }

  undergroundStore.vulners = { cves, exploits };
  undergroundStore.feedStatus.vulners = '✅ Active';
  return { cves, exploits };
}

// ─── 4. POC-in-GitHub Monitor ───────────────────────────

async function pollGitHubPOCs() {
  const year = new Date().getFullYear();
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];

  const res = await fetch(
    `https://api.github.com/search/repositories?q=CVE-${year}+created:>${since}&sort=updated&per_page=20`,
    {
      signal: AbortSignal.timeout(15000),
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(process.env.GITHUB_TOKEN ? { 'Authorization': `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
      },
    }
  );

  if (!res.ok) throw new Error(`GitHub PoC search: ${res.status}`);

  const data = await res.json();
  const pocs = (data.items || []).map(repo => {
    const cveIds = extractCVEIds(`${repo.name} ${repo.description}`);
    return makeIntelItem({
      title: repo.full_name,
      url: repo.html_url,
      cveId: cveIds[0] || null,
      published: repo.created_at,
      source: 'GitHub PoC',
      description: repo.description || `PoC repo: ${repo.full_name} (${repo.stargazers_count} stars)`,
      type: 'poc',
    });
  });

  // Detect new PoCs (not seen before)
  const existingUrls = new Set(undergroundStore.pocs.map(p => p.url));
  const newPocs = pocs.filter(p => !existingUrls.has(p.url));

  undergroundStore.pocs = pocs;
  undergroundStore.feedStatus.pocs = '✅ Active';
  return { pocs, newPocs };
}

// ─── 5. InTheWild.io ────────────────────────────────────

async function pollInTheWild() {
  // Original GitHub repo (inthewildio/exploited) was deleted.
  // Use the official API endpoint instead.
  const res = await fetch(
    'https://inthewild.io/api/exploited',
    {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'SecurityAgent/1.0', 'Accept': 'application/json' },
    }
  );

  if (!res.ok) throw new Error(`InTheWild: ${res.status}`);

  const data = await res.json();

  // API returns [{id: "CVE-2025-XXXX", earliestReport: "2025-03-10T00:00:00.000Z"}, ...]
  const items = (Array.isArray(data) ? data : []).slice(0, 50).map(entry => {
    const cveId = entry.id || entry.cve || null;
    return makeIntelItem({
      title: `${cveId} — Exploited in the Wild`,
      url: `https://inthewild.io/vuln/${cveId}`,
      cveId,
      published: entry.earliestReport || entry.timestamp || entry.date,
      source: 'InTheWild',
      description: `${cveId} is being actively exploited in the wild (first reported: ${entry.earliestReport || 'unknown'})`,
      type: 'exploit',
    });
  });

  undergroundStore.inTheWild = items;
  undergroundStore.feedStatus.inthewild = '✅ Active';
  return items;
}

// ─── 6. Nuclei Templates Watch ──────────────────────────

async function pollNucleiTemplates() {
  const res = await fetch(
    'https://api.github.com/repos/projectdiscovery/nuclei-templates/commits?per_page=10',
    {
      signal: AbortSignal.timeout(15000),
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(process.env.GITHUB_TOKEN ? { 'Authorization': `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
      },
    }
  );

  if (!res.ok) throw new Error(`Nuclei Templates: ${res.status}`);

  const commits = await res.json();
  const items = (commits || []).map(commit => {
    const msg = commit.commit?.message || '';
    const cveIds = extractCVEIds(msg);
    return makeIntelItem({
      title: msg.split('\n')[0]?.slice(0, 120) || 'Nuclei template update',
      url: commit.html_url,
      cveId: cveIds[0] || null,
      published: commit.commit?.author?.date || commit.commit?.committer?.date,
      source: 'Nuclei Templates',
      description: `Nuclei template commit: ${msg.slice(0, 300)}${cveIds.length > 0 ? ` | CVEs: ${cveIds.join(', ')}` : ''}`,
      type: 'technique',
    });
  });

  undergroundStore.nucleiTemplates = items;
  undergroundStore.feedStatus.nuclei = '✅ Active';
  return items;
}

// ─── 7. VulDB (replaced AttackerKB — CloudFront WAF blocks all API requests) ──

async function pollVulDB() {
  const res = await fetch(
    'https://vuldb.com/?rss.recent',
    {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'SecurityAgent/1.0' },
    }
  );

  if (!res.ok) throw new Error(`VulDB: ${res.status}`);

  const xml = await res.text();
  const items = parseRSSItems(xml).map(item => {
    const cveIds = extractCVEIds(`${item.title} ${item.description}`);
    return makeIntelItem({
      title: item.title,
      url: item.link,
      cveId: cveIds[0] || null,
      published: item.pubDate,
      source: 'VulDB',
      description: item.description?.replace(/<[^>]+>/g, '')?.slice(0, 400) || item.title,
      type: 'disclosure',
    });
  });

  undergroundStore.attackerKB = items;
  undergroundStore.feedStatus.attackerkb = '✅ Active';
  return items;
}

// ─── 8. MITRE ATT&CK Updates ───────────────────────────

async function pollMITREAttack() {
  // Large file — only poll if last poll was >24h ago (weekly in practice via cron gating)
  const lastPoll = undergroundStore.mitreAttack.lastPoll;
  if (lastPoll && (Date.now() - new Date(lastPoll).getTime()) < 7 * 24 * 60 * 60 * 1000) {
    // Skip — polled within the last week
    undergroundStore.feedStatus.mitre = '✅ Cached (weekly)';
    return undergroundStore.mitreAttack.techniques;
  }

  const res = await fetch(
    'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    {
      signal: AbortSignal.timeout(60000), // Large file, generous timeout
      headers: { 'User-Agent': 'SecurityAgent/1.0' },
    }
  );

  if (!res.ok) throw new Error(`MITRE ATT&CK: ${res.status}`);

  const data = await res.json();
  const objects = data.objects || [];

  // Extract techniques modified in the last 30 days
  const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const recentTechniques = objects
    .filter(obj =>
      obj.type === 'attack-pattern' &&
      obj.modified > cutoff
    )
    .map(tech => makeIntelItem({
      title: `${tech.external_references?.[0]?.external_id || ''} — ${tech.name}`,
      url: tech.external_references?.[0]?.url || null,
      cveId: null,
      published: tech.modified,
      source: 'MITRE ATT&CK',
      description: tech.description?.replace(/<[^>]+>/g, '')?.slice(0, 400) || tech.name,
      type: 'technique',
    }))
    .slice(0, 30);

  undergroundStore.mitreAttack = { techniques: recentTechniques, lastPoll: new Date().toISOString() };
  undergroundStore.feedStatus.mitre = '✅ Active';
  return recentTechniques;
}

// ─── Master Poller ──────────────────────────────────────

/**
 * Poll ALL underground feeds in parallel.
 * Individual feed failures do not crash the agent.
 */
export async function pollUndergroundFeeds() {
  const results = { total: 0, newPocs: [], errors: [] };

  const [
    fdResult,
    ossResult,
    vulnersResult,
    pocResult,
    wildResult,
    nucleiResult,
    akbResult,
    mitreResult,
  ] = await Promise.allSettled([
    pollFullDisclosure(),
    pollOSSSecurity(),
    pollVulners(),
    pollGitHubPOCs(),
    pollInTheWild(),
    pollNucleiTemplates(),
    pollVulDB(),
    pollMITREAttack(),
  ]);

  // Process results
  if (fdResult.status === 'fulfilled') {
    results.total += fdResult.value.length;
  } else {
    undergroundStore.feedStatus.fulldisclosure = `❌ ${fdResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`Full Disclosure: ${fdResult.reason?.message}`);
  }

  if (ossResult.status === 'fulfilled') {
    results.total += ossResult.value.length;
  } else {
    undergroundStore.feedStatus.osssecurity = `❌ ${ossResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`oss-security: ${ossResult.reason?.message}`);
  }

  if (vulnersResult.status === 'fulfilled') {
    results.total += vulnersResult.value.cves.length + vulnersResult.value.exploits.length;
  } else {
    undergroundStore.feedStatus.vulners = `❌ ${vulnersResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`Vulners: ${vulnersResult.reason?.message}`);
  }

  if (pocResult.status === 'fulfilled') {
    results.total += pocResult.value.pocs.length;
    results.newPocs = pocResult.value.newPocs || [];
  } else {
    undergroundStore.feedStatus.pocs = `❌ ${pocResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`GitHub PoCs: ${pocResult.reason?.message}`);
  }

  if (wildResult.status === 'fulfilled') {
    results.total += wildResult.value.length;
  } else {
    undergroundStore.feedStatus.inthewild = `❌ ${wildResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`InTheWild: ${wildResult.reason?.message}`);
  }

  if (nucleiResult.status === 'fulfilled') {
    results.total += nucleiResult.value.length;
  } else {
    undergroundStore.feedStatus.nuclei = `❌ ${nucleiResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`Nuclei: ${nucleiResult.reason?.message}`);
  }

  if (akbResult.status === 'fulfilled') {
    results.total += akbResult.value.length;
  } else {
    undergroundStore.feedStatus.attackerkb = `❌ ${akbResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`AttackerKB: ${akbResult.reason?.message}`);
  }

  if (mitreResult.status === 'fulfilled') {
    results.total += (Array.isArray(mitreResult.value) ? mitreResult.value.length : 0);
  } else {
    undergroundStore.feedStatus.mitre = `❌ ${mitreResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`MITRE ATT&CK: ${mitreResult.reason?.message}`);
  }

  undergroundStore.lastPoll = new Date().toISOString();
  return results;
}

// ─── Public API ─────────────────────────────────────────

/**
 * Get all cached underground intelligence.
 */
export function getUndergroundIntel() {
  return {
    fullDisclosure: undergroundStore.fullDisclosure.slice(0, 15),
    ossSecurity: undergroundStore.ossSecurity.slice(0, 15),
    vulners: {
      cves: undergroundStore.vulners.cves.slice(0, 15),
      exploits: undergroundStore.vulners.exploits.slice(0, 15),
    },
    pocs: undergroundStore.pocs.slice(0, 15),
    inTheWild: undergroundStore.inTheWild.slice(0, 20),
    nucleiTemplates: undergroundStore.nucleiTemplates.slice(0, 10),
    attackerKB: undergroundStore.attackerKB.slice(0, 15),
    mitreAttack: undergroundStore.mitreAttack.techniques.slice(0, 15),
    lastPoll: undergroundStore.lastPoll,
    feedStatus: { ...undergroundStore.feedStatus },
  };
}

/**
 * Get GitHub PoC exploit repos — these are urgent.
 * Someone just published working exploit code.
 */
export function getNewPOCs() {
  return undergroundStore.pocs.slice(0, 20);
}

/**
 * Get CVEs being exploited in the wild (InTheWild.io data).
 */
export function getExploitedInWild() {
  return undergroundStore.inTheWild.slice(0, 30);
}

/**
 * Get underground feed status.
 */
export function getUndergroundFeedStatus() {
  return {
    feeds: { ...undergroundStore.feedStatus },
    lastPoll: undergroundStore.lastPoll,
  };
}
