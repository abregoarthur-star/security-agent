/**
 * HackerOne API Integration — Auto-import bounty programs
 *
 * Fetches bounty-eligible programs from HackerOne, extracts scopes,
 * infers tech stacks, and registers them with the bounty manager.
 *
 * Auth: Basic Auth (HACKERONE_USERNAME + HACKERONE_API_TOKEN)
 * Sync: Daily cron + on-demand via /h1sync or API
 */

import { upsertProgram, getProgram } from './bounty-manager.js';

const H1_API = 'https://api.hackerone.com/v1';

// ─── In-Memory Sync State ────────────────────────────────

let syncState = {
  lastSync: null,
  imported: 0,
  updated: 0,
  skipped: 0,
  errors: [],
  status: 'idle', // 'idle' | 'syncing' | 'complete' | 'error'
};

// Built-in programs already in bounty-manager — skip to avoid duplication
const BUILT_IN_H1_HANDLES = new Set([
  'gitlab', 'shopify', 'automattic', 'docker-desktop', 'redis',
]);

// ─── Main Sync Function ──────────────────────────────────

/**
 * Sync bounty-eligible programs from HackerOne API.
 * Fetches programs + scopes, converts to bounty-manager schema, upserts.
 *
 * @returns {{ imported, updated, skipped, errors, totalPrograms }}
 */
export async function syncHackerOnePrograms(force = false) {
  const username = process.env.HACKERONE_USERNAME;
  const token = process.env.HACKERONE_API_TOKEN;

  if (!username || !token) {
    console.log('[HACKERONE] No credentials set — skipping sync');
    return { imported: 0, updated: 0, skipped: 0, errors: ['No credentials'], totalPrograms: 0 };
  }

  // Cooldown: don't sync more than once every 6 hours (unless forced)
  if (!force && syncState.lastSync) {
    const hoursSince = (Date.now() - new Date(syncState.lastSync).getTime()) / 3600000;
    if (hoursSince < 6) {
      console.log(`[HACKERONE] Skipping sync — last sync was ${hoursSince.toFixed(1)}h ago (cooldown: 6h)`);
      return { imported: 0, updated: 0, skipped: 0, errors: [], totalPrograms: 0, skippedCooldown: true };
    }
  }

  // Prevent concurrent syncs
  if (syncState.status === 'syncing') {
    console.log('[HACKERONE] Sync already in progress — skipping');
    return { imported: 0, updated: 0, skipped: 0, errors: [], totalPrograms: 0, skippedConcurrent: true };
  }

  console.log('[HACKERONE] Starting program sync...');
  syncState.status = 'syncing';
  syncState.errors = [];

  const authHeader = 'Basic ' + btoa(`${username}:${token}`);
  let imported = 0;
  let updated = 0;
  let skipped = 0;
  const errors = [];

  try {
    // Step 1: Fetch all bounty-eligible programs (paginated)
    const programs = await fetchAllPrograms(authHeader);
    console.log(`[HACKERONE] Fetched ${programs.length} bounty-eligible programs`);

    // Step 2: For each program, fetch scopes and convert
    for (const h1Program of programs) {
      const handle = h1Program.attributes.handle;

      // Skip built-in programs
      if (BUILT_IN_H1_HANDLES.has(handle)) {
        skipped++;
        continue;
      }

      try {
        // Fetch structured scopes
        const scopes = await fetchProgramScopes(authHeader, handle);
        await sleep(200); // Rate limit respect

        // Filter: must have bounty-eligible digital assets
        const bountyScopes = scopes.filter(s => s.attributes.eligible_for_bounty);
        if (bountyScopes.length === 0) {
          skipped++;
          continue;
        }

        const hasDigitalAsset = bountyScopes.some(s =>
          ['URL', 'CIDR', 'SOURCE_CODE', 'APPLE_STORE_APP_ID',
           'GOOGLE_PLAY_APP_ID', 'SMART_CONTRACT'].includes(s.attributes.asset_type)
        );
        if (!hasDigitalAsset) {
          skipped++;
          continue;
        }

        // Convert to bounty-manager schema
        const program = convertH1Program(h1Program, bountyScopes);

        // Upsert into bounty manager
        const existing = getProgram(program.id);
        upsertProgram(program);

        if (existing) {
          updated++;
        } else {
          imported++;
        }
      } catch (err) {
        errors.push(`${handle}: ${err.message}`);
        console.error(`[HACKERONE] Failed to process ${handle}:`, err.message);
      }
    }

    syncState = {
      lastSync: new Date().toISOString(),
      imported,
      updated,
      skipped,
      errors,
      status: 'complete',
    };

    console.log(`[HACKERONE] Sync complete: ${imported} imported, ${updated} updated, ${skipped} skipped, ${errors.length} errors`);
    return { imported, updated, skipped, errors, totalPrograms: programs.length };

  } catch (err) {
    syncState.status = 'error';
    syncState.errors = [err.message];
    console.error('[HACKERONE] Sync failed:', err.message);
    throw err;
  }
}

/**
 * Get current sync status.
 */
export function getHackerOneSyncStatus() {
  return { ...syncState };
}

// ─── API Fetching ────────────────────────────────────────

/**
 * Fetch all bounty-eligible, open programs (paginated).
 */
async function fetchAllPrograms(authHeader) {
  const allPrograms = [];
  let url = `${H1_API}/hackers/programs?page%5Bsize%5D=100`;
  let pageCount = 0;
  const maxPages = 20; // Safety limit (~2000 programs max)

  while (url && pageCount < maxPages) {
    const res = await h1Fetch(url, authHeader);
    if (!res) break;

    const data = await res.json();
    const programs = data.data || [];

    // Filter to bounty-eligible, open programs
    const eligible = programs.filter(p =>
      p.attributes.offers_bounties === true &&
      p.attributes.submission_state === 'open' &&
      p.attributes.state === 'public_mode'
    );

    allPrograms.push(...eligible);
    pageCount++;

    // Follow pagination
    url = data.links?.next || null;
    if (url) await sleep(500); // Rate limit between pages
  }

  return allPrograms;
}

/**
 * Fetch structured scopes for a specific program.
 */
async function fetchProgramScopes(authHeader, handle) {
  const url = `${H1_API}/hackers/programs/${encodeURIComponent(handle)}/structured_scopes?page%5Bsize%5D=100`;

  const res = await h1Fetch(url, authHeader);
  if (!res) return [];

  const data = await res.json();
  return data.data || [];
}

/**
 * Fetch with auth, retries on 429, and error handling.
 */
async function h1Fetch(url, authHeader, retries = 3) {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(url, {
        headers: {
          'Authorization': authHeader,
          'Accept': 'application/json',
          'User-Agent': 'SecurityAgent/2.1',
        },
        signal: AbortSignal.timeout(15000),
      });

      if (res.ok) return res;

      if (res.status === 429) {
        const retryAfter = parseInt(res.headers.get('retry-after') || '5', 10);
        const delay = Math.min(retryAfter * 1000, 30000) * (attempt + 1);
        console.warn(`[HACKERONE] Rate limited, waiting ${delay / 1000}s...`);
        await sleep(delay);
        continue;
      }

      if (res.status === 401) {
        console.error('[HACKERONE] Authentication failed — check HACKERONE_USERNAME and HACKERONE_API_TOKEN');
        return null;
      }

      console.error(`[HACKERONE] API returned ${res.status} for ${url}`);
      return null;

    } catch (err) {
      if (attempt === retries - 1) {
        console.error(`[HACKERONE] Fetch failed after ${retries} attempts:`, err.message);
        return null;
      }
      await sleep(2000 * (attempt + 1));
    }
  }
  return null;
}

// ─── Schema Conversion ──────────────────────────────────

/**
 * Convert a HackerOne program + scopes to bounty-manager schema.
 */
function convertH1Program(h1Program, bountyScopes) {
  const attrs = h1Program.attributes;
  const handle = attrs.handle;

  const inScope = bountyScopes
    .filter(s => s.attributes.eligible_for_bounty)
    .map(s => s.attributes.asset_identifier);

  const techStack = inferTechStack(bountyScopes);
  const cweHighValue = inferHighValueCWEs(bountyScopes);

  return {
    id: `h1-${handle}`,
    name: attrs.name,
    platform: 'hackerone',
    url: `https://hackerone.com/${handle}`,
    submitTo: `https://hackerone.com/${handle}`,
    techStack,
    scope: {
      inScope,
      outOfScope: extractOutOfScope(attrs.policy),
    },
    cweHighValue,
    maxBounty: null,
    rewardsModel: 'fixed-tier',
    safeHarbor: attrs.gold_standard_safe_harbor || true,
    active: true,
    notes: `Auto-imported from HackerOne API`,
    source: 'hackerone-api',
    h1Handle: handle,
    h1Id: h1Program.id,
    addedAt: new Date().toISOString(),
  };
}

// ─── Tech Stack Inference ────────────────────────────────

/**
 * Infer technology stack from scope assets.
 * URL scopes → web technologies, app IDs → mobile, etc.
 */
function inferTechStack(scopes) {
  const tech = new Set();

  for (const scope of scopes) {
    const asset = (scope.attributes.asset_identifier || '').toLowerCase();
    const type = scope.attributes.asset_type;

    // Asset type inference
    switch (type) {
      case 'URL':
        tech.add('web');
        if (asset.includes('api.') || asset.includes('/api')) tech.add('api');
        if (asset.includes('graphql')) tech.add('graphql');
        if (asset.includes('grpc')) tech.add('grpc');
        if (asset.includes('admin')) tech.add('admin-panel');
        if (asset.includes('oauth') || asset.includes('auth')) tech.add('oauth');
        break;
      case 'CIDR':
        tech.add('network');
        tech.add('infrastructure');
        break;
      case 'APPLE_STORE_APP_ID':
        tech.add('ios');
        tech.add('mobile');
        tech.add('swift');
        break;
      case 'GOOGLE_PLAY_APP_ID':
        tech.add('android');
        tech.add('mobile');
        tech.add('kotlin');
        break;
      case 'SOURCE_CODE':
        tech.add('open-source');
        inferFromSourceUrl(asset, tech);
        break;
      case 'SMART_CONTRACT':
        tech.add('solidity');
        tech.add('blockchain');
        tech.add('smart-contract');
        tech.add('web3');
        break;
      case 'HARDWARE':
        tech.add('iot');
        tech.add('firmware');
        break;
    }

    // Keyword scanning on asset identifier
    const keywords = {
      'aws': ['aws', 'cloud'], 'azure': ['azure', 'cloud'],
      'gcp': ['gcp', 'cloud'], 'docker': ['docker', 'container'],
      'kubernetes': ['kubernetes', 'k8s'], 'k8s': ['kubernetes', 'k8s'],
      'redis': ['redis'], 'postgres': ['postgresql'],
      'mysql': ['mysql'], 'mongo': ['mongodb'],
      'nginx': ['nginx'], 'apache': ['apache'],
      'node': ['node'], 'react': ['react', 'javascript'],
      'angular': ['angular', 'javascript'], 'vue': ['vue', 'javascript'],
      'django': ['django', 'python'], 'flask': ['flask', 'python'],
      'rails': ['rails', 'ruby'], 'laravel': ['laravel', 'php'],
      'spring': ['spring', 'java'], 'wordpress': ['wordpress', 'php'],
      'graphql': ['graphql'], 'webhook': ['webhook'],
      'cdn': ['cdn'], 'vpn': ['vpn'],
      's3': ['aws', 's3'], 'lambda': ['aws', 'serverless'],
      'cloudflare': ['cloudflare', 'cdn'],
    };

    for (const [kw, techs] of Object.entries(keywords)) {
      if (asset.includes(kw)) techs.forEach(t => tech.add(t));
    }
  }

  // Generic web stack additions for URL-heavy programs
  if (tech.has('web') && tech.size < 5) {
    ['rest', 'api', 'jwt', 'oauth'].forEach(t => tech.add(t));
  }

  return [...tech];
}

/**
 * Infer tech from source code repository URLs.
 */
function inferFromSourceUrl(asset, tech) {
  if (asset.includes('github.com') || asset.includes('gitlab.com')) {
    tech.add('git');
  }
  // Common language indicators in repo names/paths
  const langHints = {
    '-js': 'javascript', '-ts': 'typescript', '-py': 'python',
    '-go': 'go', '-rs': 'rust', '-rb': 'ruby', '-java': 'java',
    '-php': 'php', '-swift': 'swift', '-kt': 'kotlin',
  };
  for (const [suffix, lang] of Object.entries(langHints)) {
    if (asset.includes(suffix)) tech.add(lang);
  }
}

/**
 * Infer high-value CWEs based on scope asset types.
 */
function inferHighValueCWEs(scopes) {
  // Default web CWE set — applicable to most bounty programs
  const cweSet = new Set([
    'CWE-79',  // XSS
    'CWE-89',  // SQL Injection
    'CWE-918', // SSRF
    'CWE-287', // Authentication bypass
    'CWE-862', // Missing authorization
    'CWE-863', // Incorrect authorization
    'CWE-502', // Deserialization
    'CWE-78',  // OS Command Injection
    'CWE-22',  // Path Traversal
    'CWE-352', // CSRF
    'CWE-200', // Info Exposure
  ]);

  const hasAPI = scopes.some(s => {
    const asset = (s.attributes.asset_identifier || '').toLowerCase();
    return asset.includes('api') || s.attributes.asset_type === 'URL';
  });

  const hasMobile = scopes.some(s =>
    ['APPLE_STORE_APP_ID', 'GOOGLE_PLAY_APP_ID'].includes(s.attributes.asset_type)
  );

  const hasSmartContract = scopes.some(s =>
    s.attributes.asset_type === 'SMART_CONTRACT'
  );

  if (hasAPI) {
    cweSet.add('CWE-94');  // Code Injection
    cweSet.add('CWE-611'); // XXE
    cweSet.add('CWE-284'); // Improper Access Control
  }

  if (hasMobile) {
    cweSet.add('CWE-312'); // Cleartext Storage
    cweSet.add('CWE-319'); // Cleartext Transmission
    cweSet.add('CWE-939'); // Improper Authorization in Handler
  }

  if (hasSmartContract) {
    cweSet.add('CWE-682'); // Incorrect Calculation (reentrancy, overflow)
    cweSet.add('CWE-400'); // Resource Exhaustion
  }

  return [...cweSet];
}

/**
 * Extract common out-of-scope items from program policy text.
 */
function extractOutOfScope(policy) {
  if (!policy) return [];

  const common = [];
  const lower = policy.toLowerCase();

  const patterns = [
    { match: 'self-xss', label: 'self-xss' },
    { match: 'rate limit', label: 'rate-limiting' },
    { match: 'csv injection', label: 'csv-injection' },
    { match: 'social engineering', label: 'social-engineering' },
    { match: 'denial of service', label: 'ddos' },
    { match: 'dos attack', label: 'ddos' },
    { match: 'clickjacking', label: 'clickjacking' },
    { match: 'missing security header', label: 'missing-headers' },
    { match: 'spm ', label: 'spf-dkim-dmarc' },
    { match: 'spf', label: 'spf-dkim-dmarc' },
    { match: 'autocomplete', label: 'autocomplete' },
    { match: 'logout csrf', label: 'logout-csrf' },
    { match: 'open redirect', label: 'open-redirect' },
    { match: 'content spoofing', label: 'content-spoofing' },
  ];

  for (const { match, label } of patterns) {
    if (lower.includes(match)) common.push(label);
  }

  return [...new Set(common)];
}

// ─── Utilities ───────────────────────────────────────────

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
