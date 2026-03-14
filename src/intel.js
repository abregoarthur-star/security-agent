/**
 * CVE Intelligence Engine — Maximum Coverage
 *
 * 7 intelligence feeds, all free:
 * 1. NVD (National Vulnerability Database) — 337K+ CVEs, CVSS scores
 * 2. CISA KEV (Known Exploited Vulnerabilities) — actively exploited in the wild
 * 3. OSV.dev (Open Source Vulnerabilities) — npm, PyPI, Go, Rust, Maven
 * 4. GitHub Security Advisories — reviewed advisories via API
 * 5. Exploit-DB RSS — new exploits as they drop
 * 6. Packet Storm Security RSS — exploit/advisory feed
 * 7. The Hacker News RSS — security news for threat context
 *
 * Speed is money: first to find = first to report = bounty is yours.
 */

// In-memory CVE store
let cveStore = {
  cves: [],
  kevCatalog: [],
  exploits: [],
  securityNews: [],
  ghAdvisories: [],
  lastPoll: null,
  lastNVDPoll: null,
  lastKEVPoll: null,
  lastOSVPoll: null,
  lastGHPoll: null,
  lastExploitDBPoll: null,
  lastPacketStormPoll: null,
  lastTHNPoll: null,
  feedStatus: { nvd: 'pending', kev: 'pending', osv: 'pending', gh: 'pending', exploitdb: 'pending', packetstorm: 'pending', thn: 'pending' },
};

/**
 * Poll ALL intelligence feeds in parallel — maximum coverage.
 */
export async function pollCVEFeeds() {
  const results = { total: 0, newCritical: [], newExploits: [], errors: [] };

  const [nvdResult, kevResult, osvResult, ghResult, edbResult, psResult, thnResult] = await Promise.allSettled([
    pollNVD(),
    pollCISAKEV(),
    pollOSV(),
    pollGitHubAdvisories(),
    pollExploitDB(),
    pollPacketStorm(),
    pollTheHackerNews(),
  ]);

  // ── NVD ──
  if (nvdResult.status === 'fulfilled') {
    const { cves, count } = nvdResult.value;
    results.total += count;
    cveStore.feedStatus.nvd = '✅ Active';
    cveStore.lastNVDPoll = new Date().toISOString();

    for (const cve of cves) {
      if (!cveStore.cves.find(c => c.id === cve.id)) {
        cveStore.cves.push(cve);
        if (cve.cvss >= 9.0) results.newCritical.push(cve);
        else if (cve.cvss >= 7.0) results.newCritical.push(cve); // High severity too — money is in volume
      }
    }
  } else {
    cveStore.feedStatus.nvd = `❌ ${nvdResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`NVD: ${nvdResult.reason?.message}`);
  }

  // ── CISA KEV ──
  if (kevResult.status === 'fulfilled') {
    const { entries, newEntries } = kevResult.value;
    cveStore.kevCatalog = entries;
    cveStore.feedStatus.kev = '✅ Active';
    cveStore.lastKEVPoll = new Date().toISOString();

    for (const entry of newEntries) {
      const existing = cveStore.cves.find(c => c.id === entry.id);
      if (existing) {
        existing.cisaKEV = true;
        existing.exploitAvailable = true;
      } else {
        cveStore.cves.push({ ...entry, cisaKEV: true, exploitAvailable: true });
        results.newCritical.push({ ...entry, cisaKEV: true });
      }
    }
  } else {
    cveStore.feedStatus.kev = `❌ ${kevResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`KEV: ${kevResult.reason?.message}`);
  }

  // ── OSV ──
  if (osvResult.status === 'fulfilled') {
    const { vulns, count } = osvResult.value;
    cveStore.feedStatus.osv = '✅ Active';
    cveStore.lastOSVPoll = new Date().toISOString();
    results.total += count;

    // Cross-reference OSV vulns with CVE store
    for (const vuln of vulns) {
      if (vuln.cveId && !cveStore.cves.find(c => c.id === vuln.cveId)) {
        cveStore.cves.push({
          id: vuln.cveId,
          description: vuln.summary,
          published: vuln.published,
          severity: vuln.severity,
          source: `OSV (${vuln.ecosystem})`,
          affectedProducts: vuln.affected || [],
          osvId: vuln.id,
        });
      }
    }
  } else {
    cveStore.feedStatus.osv = `❌ ${osvResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`OSV: ${osvResult.reason?.message}`);
  }

  // ── GitHub Advisories ──
  if (ghResult.status === 'fulfilled') {
    cveStore.ghAdvisories = ghResult.value.advisories;
    cveStore.feedStatus.gh = '✅ Active';
    cveStore.lastGHPoll = new Date().toISOString();

    for (const adv of ghResult.value.newAdvisories) {
      if (adv.cveId && !cveStore.cves.find(c => c.id === adv.cveId)) {
        cveStore.cves.push({
          id: adv.cveId,
          description: adv.summary,
          published: adv.publishedAt,
          severity: adv.severity,
          cvss: adv.cvss,
          source: 'GitHub Advisory',
          affectedProducts: adv.vulnerablePackages || [],
          references: adv.references || [],
          ghsaId: adv.ghsaId,
        });
        if (adv.cvss >= 9.0 || adv.severity === 'CRITICAL') {
          results.newCritical.push({ ...adv, id: adv.cveId, source: 'GitHub Advisory' });
        }
      }
    }
  } else {
    cveStore.feedStatus.gh = `❌ ${ghResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`GitHub: ${ghResult.reason?.message}`);
  }

  // ── Exploit-DB ──
  if (edbResult.status === 'fulfilled') {
    cveStore.exploits = [...edbResult.value.exploits, ...cveStore.exploits].slice(0, 100);
    cveStore.feedStatus.exploitdb = '✅ Active';
    cveStore.lastExploitDBPoll = new Date().toISOString();
    results.newExploits.push(...edbResult.value.newExploits);

    // Cross-reference: if an exploit exists for a CVE we're tracking, flag it
    for (const exploit of edbResult.value.exploits) {
      if (exploit.cveId) {
        const cve = cveStore.cves.find(c => c.id === exploit.cveId);
        if (cve) {
          cve.exploitAvailable = true;
          cve.exploitUrl = exploit.url;
        }
      }
    }
  } else {
    cveStore.feedStatus.exploitdb = `❌ ${edbResult.reason?.message?.slice(0, 50)}`;
  }

  // ── Packet Storm ──
  if (psResult.status === 'fulfilled') {
    cveStore.feedStatus.packetstorm = '✅ Active';
    cveStore.lastPacketStormPoll = new Date().toISOString();

    for (const item of psResult.value.items) {
      if (item.cveId) {
        const cve = cveStore.cves.find(c => c.id === item.cveId);
        if (cve) {
          cve.exploitAvailable = true;
          cve.packetStormUrl = item.url;
        }
      }
    }
  } else {
    cveStore.feedStatus.packetstorm = `❌ ${psResult.reason?.message?.slice(0, 50)}`;
  }

  // ── The Hacker News ──
  if (thnResult.status === 'fulfilled') {
    cveStore.securityNews = thnResult.value.articles;
    cveStore.feedStatus.thn = '✅ Active';
    cveStore.lastTHNPoll = new Date().toISOString();
  } else {
    cveStore.feedStatus.thn = `❌ ${thnResult.reason?.message?.slice(0, 50)}`;
  }

  // Prune old CVEs (keep 7 days, always keep KEV)
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  cveStore.cves = cveStore.cves.filter(c => {
    const pubDate = new Date(c.published || c.dateAdded || 0).getTime();
    return pubDate > cutoff || c.cisaKEV;
  });

  cveStore.lastPoll = new Date().toISOString();
  results.total = cveStore.cves.length;

  return results;
}

// ─── NVD ────────────────────────────────────────────────

async function pollNVD() {
  const since = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();

  const params = new URLSearchParams({
    pubStartDate: since,
    pubEndDate: new Date().toISOString(),
    resultsPerPage: '100',
  });

  const headers = {};
  if (process.env.NVD_API_KEY) {
    headers.apiKey = process.env.NVD_API_KEY;
  }

  const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?${params}`, {
    headers,
    signal: AbortSignal.timeout(30000),
  });

  if (!res.ok) throw new Error(`NVD API: ${res.status}`);

  const data = await res.json();
  const cves = (data.vulnerabilities || []).map(v => {
    const cve = v.cve;
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV40?.[0] || cve.metrics?.cvssMetricV2?.[0];

    return {
      id: cve.id,
      description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
      published: cve.published,
      lastModified: cve.lastModified,
      cvss: metrics?.cvssData?.baseScore || null,
      severity: metrics?.cvssData?.baseSeverity || null,
      attackVector: metrics?.cvssData?.attackVector || null,
      source: 'NVD',
      weaknesses: (cve.weaknesses || [])
        .flatMap(w => w.description || [])
        .map(d => d.value)
        .filter(v => v !== 'NVD-CWE-noinfo'),
      affectedProducts: (cve.configurations || [])
        .flatMap(c => c.nodes || [])
        .flatMap(n => n.cpeMatch || [])
        .filter(m => m.vulnerable)
        .map(m => m.criteria?.split(':').slice(3, 5).join(' ') || '')
        .filter(Boolean)
        .slice(0, 10),
      references: (cve.references || []).map(r => r.url).slice(0, 5),
      // Bug bounty relevance scoring
      bountyRelevant: isBountyRelevant(cve),
    };
  });

  return { cves, count: cves.length };
}

/**
 * Score whether a CVE is relevant for bug bounty hunting.
 * Web-facing vulns in popular software = money.
 */
function isBountyRelevant(cve) {
  const desc = (cve.descriptions?.find(d => d.lang === 'en')?.value || '').toLowerCase();
  const weaknesses = (cve.weaknesses || []).flatMap(w => w.description || []).map(d => d.value);

  // High-value weakness types for bounties
  const bountyWeaknesses = [
    'CWE-79',   // XSS
    'CWE-89',   // SQL Injection
    'CWE-94',   // Code Injection
    'CWE-78',   // OS Command Injection
    'CWE-22',   // Path Traversal
    'CWE-918',  // SSRF
    'CWE-502',  // Deserialization
    'CWE-611',  // XXE
    'CWE-352',  // CSRF
    'CWE-287',  // Authentication Bypass
    'CWE-862',  // Missing Authorization
    'CWE-863',  // Incorrect Authorization
    'CWE-434',  // Unrestricted Upload
    'CWE-601',  // Open Redirect
    'CWE-200',  // Information Exposure
    'CWE-269',  // Improper Privilege Management
  ];

  const hasBountyWeakness = weaknesses.some(w => bountyWeaknesses.includes(w));

  // Web-related keywords
  const webKeywords = ['web', 'http', 'api', 'rest', 'graphql', 'wordpress', 'drupal', 'joomla',
    'nginx', 'apache', 'plugin', 'extension', 'saas', 'cloud', 'portal', 'dashboard',
    'admin panel', 'login', 'authentication', 'authorization', 'upload', 'injection',
    'cross-site', 'xss', 'sqli', 'rce', 'remote code', 'ssrf', 'idor'];

  const isWebRelated = webKeywords.some(kw => desc.includes(kw));

  return hasBountyWeakness || isWebRelated;
}

// ─── CISA KEV ───────────────────────────────────────────

async function pollCISAKEV() {
  const res = await fetch(
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    { signal: AbortSignal.timeout(30000) }
  );

  if (!res.ok) throw new Error(`CISA KEV: ${res.status}`);

  const data = await res.json();
  const entries = (data.vulnerabilities || []).map(v => ({
    id: v.cveID,
    description: v.shortDescription,
    published: v.dateAdded,
    cvss: null,
    severity: 'CRITICAL',
    source: 'CISA KEV',
    vendor: v.vendorProject,
    product: v.product,
    affectedProducts: [`${v.vendorProject} ${v.product}`],
    dueDate: v.dueDate,
    knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
    dateAdded: v.dateAdded,
    requiredAction: v.requiredAction,
    notes: v.notes,
  }));

  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const newEntries = entries.filter(e => e.dateAdded >= yesterday);

  return { entries, newEntries };
}

// ─── OSV.dev ────────────────────────────────────────────

async function pollOSV() {
  const ecosystems = ['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet', 'RubyGems', 'Packagist'];
  const allVulns = [];

  // Query for popular packages with known vulns
  const popularPackages = [
    { ecosystem: 'npm', name: 'express' },
    { ecosystem: 'npm', name: 'lodash' },
    { ecosystem: 'npm', name: 'axios' },
    { ecosystem: 'npm', name: 'next' },
    { ecosystem: 'npm', name: 'react' },
    { ecosystem: 'npm', name: 'webpack' },
    { ecosystem: 'npm', name: 'jsonwebtoken' },
    { ecosystem: 'PyPI', name: 'django' },
    { ecosystem: 'PyPI', name: 'flask' },
    { ecosystem: 'PyPI', name: 'requests' },
    { ecosystem: 'PyPI', name: 'fastapi' },
    { ecosystem: 'Go', name: 'golang.org/x/crypto' },
    { ecosystem: 'Go', name: 'github.com/gin-gonic/gin' },
    { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core' },
    { ecosystem: 'Maven', name: 'org.springframework:spring-core' },
  ];

  for (const pkg of popularPackages) {
    try {
      const res = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: pkg }),
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const data = await res.json();
        for (const vuln of (data.vulns || []).slice(0, 5)) {
          const cveAlias = (vuln.aliases || []).find(a => a.startsWith('CVE-'));
          allVulns.push({
            id: vuln.id,
            cveId: cveAlias || null,
            summary: vuln.summary || vuln.details?.slice(0, 200),
            published: vuln.published,
            severity: vuln.database_specific?.severity || 'UNKNOWN',
            ecosystem: pkg.ecosystem,
            affected: [`${pkg.ecosystem}/${pkg.name}`],
          });
        }
      }
    } catch {
      // Individual package failures are non-critical
    }
  }

  return { vulns: allVulns, count: allVulns.length };
}

// ─── GitHub Security Advisories ─────────────────────────

async function pollGitHubAdvisories() {
  // Use the REST API (no auth needed for public advisories)
  const since = new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString();

  const res = await fetch(
    `https://api.github.com/advisories?type=reviewed&per_page=30&sort=published&direction=desc`,
    {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(process.env.GITHUB_TOKEN ? { 'Authorization': `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
      },
      signal: AbortSignal.timeout(15000),
    }
  );

  if (!res.ok) throw new Error(`GitHub Advisories: ${res.status}`);

  const advisories = await res.json();
  const parsed = advisories.map(adv => ({
    ghsaId: adv.ghsa_id,
    cveId: adv.cve_id,
    summary: adv.summary,
    description: adv.description?.slice(0, 500),
    severity: adv.severity?.toUpperCase(),
    cvss: adv.cvss?.score || null,
    publishedAt: adv.published_at,
    updatedAt: adv.updated_at,
    vulnerablePackages: (adv.vulnerabilities || []).map(v =>
      `${v.package?.ecosystem}/${v.package?.name} ${v.vulnerable_version_range || ''}`
    ),
    references: (adv.references || []).slice(0, 5),
    cwes: (adv.cwes || []).map(c => c.cwe_id),
  }));

  // Find new (published in last 6 hours)
  const newAdvisories = parsed.filter(a => {
    const pub = new Date(a.publishedAt).getTime();
    return pub > Date.now() - 6 * 60 * 60 * 1000;
  });

  return { advisories: parsed, newAdvisories };
}

// ─── Exploit-DB RSS ─────────────────────────────────────

async function pollExploitDB() {
  const res = await fetch('https://www.exploit-db.com/rss.xml', {
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'SecurityAgent/1.0' },
  });

  if (!res.ok) throw new Error(`Exploit-DB: ${res.status}`);

  const xml = await res.text();
  const exploits = parseRSSItems(xml).map(item => {
    const cveMatch = item.title?.match(/CVE-\d{4}-\d+/i);
    return {
      title: item.title,
      url: item.link,
      published: item.pubDate,
      description: item.description?.slice(0, 300),
      cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
      source: 'Exploit-DB',
    };
  });

  const newExploits = exploits.filter(e => {
    const pub = new Date(e.published).getTime();
    return pub > Date.now() - 6 * 60 * 60 * 1000;
  });

  return { exploits, newExploits };
}

// ─── Packet Storm Security ──────────────────────────────

async function pollPacketStorm() {
  const res = await fetch('https://rss.packetstormsecurity.com/files/tags/exploit/', {
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'SecurityAgent/1.0' },
  });

  if (!res.ok) throw new Error(`PacketStorm: ${res.status}`);

  const xml = await res.text();
  const items = parseRSSItems(xml).map(item => {
    const cveMatch = item.title?.match(/CVE-\d{4}-\d+/i);
    return {
      title: item.title,
      url: item.link,
      published: item.pubDate,
      description: item.description?.slice(0, 300),
      cveId: cveMatch ? cveMatch[0].toUpperCase() : null,
      source: 'PacketStorm',
    };
  });

  return { items };
}

// ─── The Hacker News ────────────────────────────────────

async function pollTheHackerNews() {
  const res = await fetch('https://feeds.feedburner.com/TheHackersNews', {
    signal: AbortSignal.timeout(15000),
    headers: { 'User-Agent': 'SecurityAgent/1.0' },
  });

  if (!res.ok) throw new Error(`THN: ${res.status}`);

  const xml = await res.text();
  const articles = parseRSSItems(xml).map(item => ({
    title: item.title,
    url: item.link,
    published: item.pubDate,
    description: item.description?.replace(/<[^>]+>/g, '').slice(0, 300),
    source: 'The Hacker News',
  }));

  return { articles: articles.slice(0, 20) };
}

// ─── RSS Parser ─────────────────────────────────────────

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

// ─── Public API ─────────────────────────────────────────

export async function searchCVE(query) {
  if (!query) return [];

  const local = cveStore.cves.filter(c =>
    c.id?.toLowerCase().includes(query.toLowerCase()) ||
    c.description?.toLowerCase().includes(query.toLowerCase())
  );

  if (local.length > 0) return local;

  // NVD API lookup for specific CVE IDs
  if (query.match(/^CVE-\d{4}-\d+$/i)) {
    try {
      const res = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${query.toUpperCase()}`,
        {
          headers: process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {},
          signal: AbortSignal.timeout(15000),
        }
      );

      if (res.ok) {
        const data = await res.json();
        return (data.vulnerabilities || []).map(v => {
          const cve = v.cve;
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV40?.[0] || cve.metrics?.cvssMetricV2?.[0];
          return {
            id: cve.id,
            description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
            published: cve.published,
            cvss: metrics?.cvssData?.baseScore || null,
            severity: metrics?.cvssData?.baseSeverity || null,
            attackVector: metrics?.cvssData?.attackVector || null,
            source: 'NVD',
            weaknesses: (cve.weaknesses || []).flatMap(w => w.description || []).map(d => d.value),
            affectedProducts: (cve.configurations || [])
              .flatMap(c => c.nodes || [])
              .flatMap(n => n.cpeMatch || [])
              .filter(m => m.vulnerable)
              .map(m => m.criteria?.split(':').slice(3, 5).join(' ') || '')
              .filter(Boolean)
              .slice(0, 10),
            references: (cve.references || []).map(r => r.url).slice(0, 5),
          };
        });
      }
    } catch (err) {
      console.error('NVD lookup failed:', err.message);
    }
  }

  return [];
}

export function getCVEStats() {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;

  const last24h = cveStore.cves.filter(c => {
    const t = new Date(c.published || c.dateAdded || 0).getTime();
    return now - t < day;
  });

  return {
    totalTracked: cveStore.cves.length,
    last24h: last24h.length,
    critical24h: last24h.filter(c => c.cvss >= 9.0 || c.severity === 'CRITICAL').length,
    high24h: last24h.filter(c => (c.cvss >= 7.0 && c.cvss < 9.0) || c.severity === 'HIGH').length,
    bountyRelevant24h: last24h.filter(c => c.bountyRelevant).length,
    exploitsAvailable: cveStore.cves.filter(c => c.exploitAvailable).length,
    kevTotal: cveStore.kevCatalog.length,
    kevNew: cveStore.kevCatalog.filter(k => {
      const d = new Date(k.dateAdded).getTime();
      return now - d < day;
    }).length,
    securityNewsCount: cveStore.securityNews.length,
    ghAdvisoryCount: cveStore.ghAdvisories.length,
    exploitCount: cveStore.exploits.length,
    lastPoll: cveStore.lastPoll,
    nvdStatus: cveStore.feedStatus.nvd,
    kevStatus: cveStore.feedStatus.kev,
    osvStatus: cveStore.feedStatus.osv,
    ghStatus: cveStore.feedStatus.gh,
    exploitdbStatus: cveStore.feedStatus.exploitdb,
    packetstormStatus: cveStore.feedStatus.packetstorm,
    thnStatus: cveStore.feedStatus.thn,
  };
}

export function getRecentCritical() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  return cveStore.cves
    .filter(c => {
      const t = new Date(c.published || c.dateAdded || 0).getTime();
      return t > cutoff && (c.cvss >= 7.0 || c.severity === 'CRITICAL' || c.severity === 'HIGH' || c.cisaKEV);
    })
    .sort((a, b) => (b.cvss || 10) - (a.cvss || 10));
}

/**
 * Get bounty-relevant CVEs — the money-makers.
 */
export function getBountyRelevantCVEs() {
  return cveStore.cves
    .filter(c => c.bountyRelevant && c.cvss >= 7.0)
    .sort((a, b) => (b.cvss || 0) - (a.cvss || 0))
    .slice(0, 20);
}

/**
 * Get all recent exploits.
 */
export function getRecentExploits() {
  return cveStore.exploits.slice(0, 20);
}

/**
 * Get security news for context.
 */
export function getSecurityNews() {
  return cveStore.securityNews.slice(0, 15);
}

/**
 * Get full feed status.
 */
export function getFeedStatus() {
  return {
    feeds: cveStore.feedStatus,
    lastPolls: {
      nvd: cveStore.lastNVDPoll,
      kev: cveStore.lastKEVPoll,
      osv: cveStore.lastOSVPoll,
      gh: cveStore.lastGHPoll,
      exploitdb: cveStore.lastExploitDBPoll,
      packetstorm: cveStore.lastPacketStormPoll,
      thn: cveStore.lastTHNPoll,
    },
  };
}
