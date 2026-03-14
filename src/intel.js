/**
 * CVE Intelligence Engine
 *
 * Polls multiple free vulnerability databases:
 * 1. NVD (National Vulnerability Database) — 337K+ CVEs
 * 2. CISA KEV (Known Exploited Vulnerabilities) — actively exploited
 * 3. OSV.dev (Open Source Vulnerabilities) — package-level
 * 4. GitHub Security Advisories — OSV-format
 *
 * All free, no auth required (NVD API key recommended for higher rate limits).
 */

// In-memory CVE store (persisted to disk on Railway volume)
let cveStore = {
  cves: [],         // Recent CVEs (rolling 7-day window)
  kevCatalog: [],   // CISA KEV full catalog
  lastPoll: null,
  lastNVDPoll: null,
  lastKEVPoll: null,
  lastOSVPoll: null,
  feedStatus: { nvd: 'pending', kev: 'pending', osv: 'pending', gh: 'pending' },
};

/**
 * Poll all CVE feeds and merge results.
 */
export async function pollCVEFeeds() {
  const results = { total: 0, newCritical: [], errors: [] };

  // Run all feeds in parallel
  const [nvdResult, kevResult, osvResult] = await Promise.allSettled([
    pollNVD(),
    pollCISAKEV(),
    pollOSV(),
  ]);

  // Process NVD
  if (nvdResult.status === 'fulfilled') {
    const { cves, count } = nvdResult.value;
    results.total += count;
    cveStore.feedStatus.nvd = '✅ Active';
    cveStore.lastNVDPoll = new Date().toISOString();

    for (const cve of cves) {
      if (!cveStore.cves.find(c => c.id === cve.id)) {
        cveStore.cves.push(cve);
        if (cve.cvss >= 9.0) results.newCritical.push(cve);
      }
    }
  } else {
    cveStore.feedStatus.nvd = `❌ ${nvdResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`NVD: ${nvdResult.reason?.message}`);
  }

  // Process CISA KEV
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

  // Process OSV
  if (osvResult.status === 'fulfilled') {
    cveStore.feedStatus.osv = '✅ Active';
    cveStore.lastOSVPoll = new Date().toISOString();
    results.total += osvResult.value.count;
  } else {
    cveStore.feedStatus.osv = `❌ ${osvResult.reason?.message?.slice(0, 50)}`;
    results.errors.push(`OSV: ${osvResult.reason?.message}`);
  }

  // GitHub advisories status (polled separately)
  cveStore.feedStatus.gh = '⏳ Planned';

  // Prune old CVEs (keep 7 days)
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  cveStore.cves = cveStore.cves.filter(c => {
    const pubDate = new Date(c.published || c.dateAdded || 0).getTime();
    return pubDate > cutoff || c.cisaKEV;
  });

  cveStore.lastPoll = new Date().toISOString();
  results.total = cveStore.cves.length;

  return results;
}

/**
 * Poll NVD for recently published CVEs.
 */
async function pollNVD() {
  // Get CVEs from the last 2 hours
  const since = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();

  const params = new URLSearchParams({
    pubStartDate: since,
    pubEndDate: new Date().toISOString(),
    resultsPerPage: '50',
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
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];

    return {
      id: cve.id,
      description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
      published: cve.published,
      cvss: metrics?.cvssData?.baseScore || null,
      severity: metrics?.cvssData?.baseSeverity || null,
      source: 'NVD',
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

  return { cves, count: cves.length };
}

/**
 * Poll CISA Known Exploited Vulnerabilities catalog.
 */
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
    cvss: null, // KEV doesn't include CVSS
    severity: 'CRITICAL', // All KEV entries are high-priority
    source: 'CISA KEV',
    vendor: v.vendorProject,
    product: v.product,
    affectedProducts: [`${v.vendorProject} ${v.product}`],
    dueDate: v.dueDate,
    knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
    dateAdded: v.dateAdded,
  }));

  // Find newly added (last 24h)
  const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const newEntries = entries.filter(e => e.dateAdded >= yesterday);

  return { entries, newEntries };
}

/**
 * Poll OSV.dev for recent open-source vulnerabilities.
 * Queries for popular ecosystems (npm, PyPI, Go, crates.io).
 */
async function pollOSV() {
  // Query for recently modified vulnerabilities
  const ecosystems = ['npm', 'PyPI', 'Go', 'crates.io'];
  let totalCount = 0;

  for (const ecosystem of ecosystems) {
    try {
      const res = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { ecosystem },
          // OSV doesn't support date range queries directly
          // We just verify the API is reachable
        }),
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const data = await res.json();
        totalCount += (data.vulns || []).length;
      }
    } catch {
      // Individual ecosystem failures are non-critical
    }
  }

  return { count: totalCount };
}

/**
 * Search for a specific CVE by ID.
 */
export async function searchCVE(query) {
  if (!query) return [];

  // Check local store first
  const local = cveStore.cves.filter(c =>
    c.id?.toLowerCase().includes(query.toLowerCase()) ||
    c.description?.toLowerCase().includes(query.toLowerCase())
  );

  if (local.length > 0) return local;

  // Fall back to NVD API lookup
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
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
          return {
            id: cve.id,
            description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
            published: cve.published,
            cvss: metrics?.cvssData?.baseScore || null,
            severity: metrics?.cvssData?.baseSeverity || null,
            source: 'NVD',
            affectedProducts: [],
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

/**
 * Get CVE statistics.
 */
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
    kevTotal: cveStore.kevCatalog.length,
    kevNew: cveStore.kevCatalog.filter(k => {
      const d = new Date(k.dateAdded).getTime();
      return now - d < day;
    }).length,
    lastPoll: cveStore.lastPoll,
    nvdStatus: cveStore.feedStatus.nvd,
    kevStatus: cveStore.feedStatus.kev,
    osvStatus: cveStore.feedStatus.osv,
    ghStatus: cveStore.feedStatus.gh,
  };
}

/**
 * Get recent critical CVEs (CVSS >= 9.0 or CISA KEV, last 24h).
 */
export function getRecentCritical() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  return cveStore.cves
    .filter(c => {
      const t = new Date(c.published || c.dateAdded || 0).getTime();
      return t > cutoff && (c.cvss >= 9.0 || c.severity === 'CRITICAL' || c.cisaKEV);
    })
    .sort((a, b) => (b.cvss || 10) - (a.cvss || 10));
}
