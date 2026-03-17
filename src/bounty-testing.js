/**
 * Bounty Testing — Passive Validation + Nuclei Detection
 *
 * Phase 1: Passive validation (zero risk)
 *   - Version fingerprinting from HTTP headers
 *   - Endpoint existence checks (HEAD requests)
 *   - Technology confirmation via known paths
 *   - Shodan InternetDB correlation (free, no API key)
 *   - CPE match verification against NVD data
 *
 * Phase 2: Nuclei detection templates (minimal risk)
 *   - Detection-only templates (info/detection severity)
 *   - Scope-validated, rate-limited
 *   - Requires Nuclei binary in PATH (Dockerfile)
 *
 * All tests are read-only. No payloads. No exploitation.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import dns from 'node:dns';

const execFileAsync = promisify(execFile);
const resolve4 = promisify(dns.resolve4);

const FETCH_TIMEOUT = 8000;

// ─── In-Memory Test Results Store ────────────────────────

const testResultsStore = [];

// ─── Main Entry Point ────────────────────────────────────

/**
 * Run passive validation for a CVE × program match.
 * Returns confidence score (0-100), label, and detailed test results.
 *
 * @param {object} match - Match object from bounty-manager
 * @param {object} program - Program object from bounty-manager
 * @param {object} researchPackage - Research package from pipeline
 * @returns {object} Test results with confidence score and evidence
 */
export async function runPassiveValidation(match, program, researchPackage) {
  const startTime = Date.now();
  const matchId = match.id || `t_${Date.now()}`;
  const auditLog = [];

  auditLog.push({ timestamp: new Date().toISOString(), action: 'validation_started', result: `${match.cveId} x ${program.name}` });

  console.log(`[TESTING] Starting passive validation for ${match.cveId} x ${program.name}...`);

  // Extract target URLs from program scope
  const targetUrls = extractTargetUrls(program);
  if (targetUrls.length === 0) {
    console.log(`[TESTING] No testable URLs in scope for ${program.name}`);
    const result = buildResult(matchId, match.cveId, program.id, 1, 'completed', 0, [], auditLog, startTime);
    testResultsStore.push(result);
    return result;
  }

  // Run all passive tests in parallel
  const tests = await Promise.allSettled([
    runVersionFingerprint(targetUrls, match, researchPackage),
    runEndpointExistence(targetUrls, match, researchPackage),
    runTechnologyConfirmation(targetUrls, program),
    runShodanLookup(targetUrls),
    runCPEMatchVerification(match, researchPackage),
  ]);

  const testResults = [];
  const testNames = ['version_fingerprint', 'endpoint_existence', 'technology_confirmation', 'shodan_lookup', 'cpe_match'];

  for (let i = 0; i < tests.length; i++) {
    if (tests[i].status === 'fulfilled') {
      testResults.push(tests[i].value);
      auditLog.push({
        timestamp: new Date().toISOString(),
        action: `test_${testNames[i]}`,
        result: tests[i].value.result,
      });
    } else {
      testResults.push({
        name: testNames[i],
        result: 'error',
        detail: tests[i].reason?.message || 'Unknown error',
        evidence: {},
        duration: 0,
      });
      auditLog.push({
        timestamp: new Date().toISOString(),
        action: `test_${testNames[i]}`,
        result: 'error',
      });
    }
  }

  // Calculate confidence score
  const confidenceScore = calculateConfidence(testResults);
  const confidenceLabel = getConfidenceLabel(confidenceScore);

  auditLog.push({
    timestamp: new Date().toISOString(),
    action: 'validation_completed',
    result: `${confidenceScore}/100 — ${confidenceLabel}`,
  });

  const result = buildResult(matchId, match.cveId, program.id, 1, 'completed', confidenceScore, testResults, auditLog, startTime);
  result.confidenceLabel = confidenceLabel;

  // Store result
  testResultsStore.push(result);

  // Prune old results (keep 100)
  if (testResultsStore.length > 100) {
    testResultsStore.splice(0, testResultsStore.length - 100);
  }

  console.log(`[TESTING] Validation complete: ${confidenceScore}/100 (${confidenceLabel}) for ${match.cveId} x ${program.name}`);
  return result;
}

// ─── Test 1: Version Fingerprinting ──────────────────────

async function runVersionFingerprint(urls, match, researchPackage) {
  const startTime = Date.now();
  const evidence = { detectedVersions: [], headers: {} };
  let matchFound = false;

  const affectedProducts = researchPackage?.disclosure?.affectedProducts || [];
  const affectedVersions = researchPackage?.disclosure?.affectedVersions || [];

  for (const url of urls.slice(0, 3)) {
    try {
      const res = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch/1.0)' },
      });

      const server = res.headers.get('server');
      const poweredBy = res.headers.get('x-powered-by');
      const aspnetVersion = res.headers.get('x-aspnet-version');
      const generator = res.headers.get('x-generator');

      evidence.headers[url] = {};
      if (server) evidence.headers[url].server = server;
      if (poweredBy) evidence.headers[url]['x-powered-by'] = poweredBy;
      if (aspnetVersion) evidence.headers[url]['x-aspnet-version'] = aspnetVersion;
      if (generator) evidence.headers[url]['x-generator'] = generator;

      // Extract version strings
      const versionSources = [server, poweredBy, aspnetVersion, generator].filter(Boolean);
      for (const source of versionSources) {
        const versionMatch = source.match(/[\d]+\.[\d]+(?:\.[\d]+)?/);
        if (versionMatch) {
          evidence.detectedVersions.push({
            version: versionMatch[0],
            source: source,
            url,
          });

          // Compare against affected version ranges
          if (isVersionInRange(versionMatch[0], affectedVersions)) {
            matchFound = true;
          }

          // Check against CPE product names
          for (const cpe of affectedProducts) {
            const cpeLower = cpe.toLowerCase();
            const sourceLower = source.toLowerCase();
            if (sourceLower.includes('apache') && cpeLower.includes('apache') ||
                sourceLower.includes('nginx') && cpeLower.includes('nginx') ||
                sourceLower.includes('iis') && cpeLower.includes('iis') ||
                sourceLower.includes('php') && cpeLower.includes('php') ||
                sourceLower.includes('express') && cpeLower.includes('express')) {
              matchFound = true;
            }
          }
        }
      }
    } catch {
      // Skip unreachable URLs
    }
  }

  // Also try GET to read HTML meta generators
  for (const url of urls.slice(0, 1)) {
    try {
      const res = await fetch(url, {
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch/1.0)' },
      });
      const body = await res.text();
      const head = body.slice(0, 10000);

      // Extract meta generator
      const genMatch = head.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
      if (genMatch) {
        evidence.detectedVersions.push({ version: genMatch[1], source: 'meta-generator', url });
        const vMatch = genMatch[1].match(/[\d]+\.[\d]+(?:\.[\d]+)?/);
        if (vMatch && isVersionInRange(vMatch[0], affectedVersions)) {
          matchFound = true;
        }
      }
    } catch {
      // Skip
    }
  }

  return {
    name: 'version_fingerprint',
    result: evidence.detectedVersions.length > 0 ? (matchFound ? 'pass' : 'partial') : 'fail',
    detail: matchFound
      ? `Version match found: ${evidence.detectedVersions.map(v => v.source).join(', ')}`
      : evidence.detectedVersions.length > 0
        ? `Versions detected but no match to affected range: ${evidence.detectedVersions.map(v => v.version).join(', ')}`
        : 'No version information detected in headers',
    evidence,
    duration: Date.now() - startTime,
  };
}

// ─── Test 2: Endpoint Existence ──────────────────────────

async function runEndpointExistence(urls, match, researchPackage) {
  const startTime = Date.now();
  const evidence = { checkedPaths: [], existingPaths: [] };

  // Extract vulnerable paths from CVE description and references
  const vulnerablePaths = extractVulnerablePaths(
    researchPackage?.disclosure?.description || match.cve?.description || '',
    researchPackage?.disclosure?.references || []
  );

  if (vulnerablePaths.length === 0) {
    return {
      name: 'endpoint_existence',
      result: 'skip',
      detail: 'No vulnerable paths identified from CVE description',
      evidence,
      duration: Date.now() - startTime,
    };
  }

  for (const baseUrl of urls.slice(0, 2)) {
    for (const path of vulnerablePaths.slice(0, 5)) {
      const fullUrl = new URL(path, baseUrl).toString();
      evidence.checkedPaths.push(fullUrl);

      try {
        const res = await fetch(fullUrl, {
          method: 'HEAD',
          redirect: 'follow',
          signal: AbortSignal.timeout(FETCH_TIMEOUT),
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch/1.0)' },
        });

        if (res.status >= 200 && res.status < 404) {
          evidence.existingPaths.push({
            url: fullUrl,
            status: res.status,
            contentType: res.headers.get('content-type') || 'unknown',
          });
        }
      } catch {
        // Skip unreachable
      }
    }
  }

  const found = evidence.existingPaths.length;
  return {
    name: 'endpoint_existence',
    result: found > 0 ? 'pass' : 'fail',
    detail: found > 0
      ? `${found} vulnerable endpoint(s) exist: ${evidence.existingPaths.map(p => p.url).join(', ')}`
      : `None of ${evidence.checkedPaths.length} checked paths returned a valid response`,
    evidence,
    duration: Date.now() - startTime,
  };
}

// ─── Test 3: Technology Confirmation ─────────────────────

async function runTechnologyConfirmation(urls, program) {
  const startTime = Date.now();
  const evidence = { confirmedTech: [], probedPaths: [] };

  // Technology-specific probe paths
  const techProbes = [
    { tech: ['wordpress', 'php'], path: '/wp-login.php', name: 'WordPress' },
    { tech: ['graphql'], path: '/__graphql', name: 'GraphQL' },
    { tech: ['graphql'], path: '/graphql', name: 'GraphQL' },
    { tech: ['spring', 'java'], path: '/actuator/health', name: 'Spring Boot' },
    { tech: ['spring', 'java'], path: '/actuator/info', name: 'Spring Boot' },
    { tech: ['rails', 'ruby'], path: '/rails/info/properties', name: 'Rails' },
    { tech: ['django', 'python'], path: '/admin/', name: 'Django' },
    { tech: ['laravel', 'php'], path: '/telescope', name: 'Laravel' },
    { tech: ['express', 'node'], path: '/api/health', name: 'Express API' },
    { tech: ['next.js', 'react'], path: '/_next/static', name: 'Next.js' },
    { tech: ['docker', 'container'], path: '/v2/', name: 'Docker Registry' },
    { tech: ['kubernetes', 'k8s'], path: '/healthz', name: 'Kubernetes' },
    { tech: ['swagger', 'api'], path: '/swagger-ui.html', name: 'Swagger UI' },
    { tech: ['swagger', 'api'], path: '/api-docs', name: 'Swagger/OpenAPI' },
  ];

  // Only probe for technologies in the program's stack
  const stackLower = program.techStack.map(t => t.toLowerCase());
  const relevantProbes = techProbes.filter(probe =>
    probe.tech.some(t => stackLower.includes(t))
  );

  for (const baseUrl of urls.slice(0, 2)) {
    for (const probe of relevantProbes.slice(0, 8)) {
      const fullUrl = new URL(probe.path, baseUrl).toString();
      evidence.probedPaths.push({ url: fullUrl, tech: probe.name });

      try {
        const res = await fetch(fullUrl, {
          method: 'HEAD',
          redirect: 'follow',
          signal: AbortSignal.timeout(FETCH_TIMEOUT),
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch/1.0)' },
        });

        if (res.status >= 200 && res.status < 400) {
          evidence.confirmedTech.push({
            technology: probe.name,
            url: fullUrl,
            status: res.status,
          });
        }
      } catch {
        // Skip
      }
    }
  }

  const confirmed = evidence.confirmedTech.length;
  return {
    name: 'technology_confirmation',
    result: confirmed > 0 ? 'pass' : 'fail',
    detail: confirmed > 0
      ? `Confirmed: ${[...new Set(evidence.confirmedTech.map(t => t.technology))].join(', ')}`
      : `None of ${evidence.probedPaths.length} technology probes returned positive`,
    evidence,
    duration: Date.now() - startTime,
  };
}

// ─── Test 4: Shodan InternetDB Lookup ────────────────────

async function runShodanLookup(urls) {
  const startTime = Date.now();
  const evidence = { lookups: [] };

  // Resolve IPs from target URLs
  const ips = new Set();
  for (const url of urls.slice(0, 3)) {
    try {
      const hostname = new URL(url).hostname;
      const resolved = await resolve4(hostname);
      for (const ip of resolved) ips.add(ip);
    } catch {
      // Skip unresolvable
    }
  }

  if (ips.size === 0) {
    return {
      name: 'shodan_lookup',
      result: 'skip',
      detail: 'Could not resolve any target IPs',
      evidence,
      duration: Date.now() - startTime,
    };
  }

  let hasData = false;
  for (const ip of [...ips].slice(0, 2)) {
    try {
      const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
        headers: { 'User-Agent': 'SecurityResearch/1.0' },
      });

      if (res.ok) {
        const data = await res.json();
        evidence.lookups.push({
          ip,
          ports: data.ports || [],
          hostnames: data.hostnames || [],
          cpes: data.cpes || [],
          vulns: data.vulns || [],
          tags: data.tags || [],
        });
        if (data.ports?.length > 0 || data.vulns?.length > 0) hasData = true;
      }
    } catch {
      // Skip failed lookups
    }
  }

  return {
    name: 'shodan_lookup',
    result: hasData ? 'pass' : 'fail',
    detail: hasData
      ? `Shodan data for ${evidence.lookups.length} IP(s): ${evidence.lookups.map(l => `${l.ip} (${l.ports.length} ports, ${l.vulns.length} known vulns)`).join('; ')}`
      : 'No Shodan InternetDB data available for target IPs',
    evidence,
    duration: Date.now() - startTime,
  };
}

// ─── Test 5: CPE Match Verification ──────────────────────

async function runCPEMatchVerification(match, researchPackage) {
  const startTime = Date.now();
  const evidence = { cveProducts: [], matchedProducts: [] };

  const affectedProducts = researchPackage?.disclosure?.affectedProducts || [];
  if (affectedProducts.length === 0) {
    return {
      name: 'cpe_match',
      result: 'skip',
      detail: 'No CPE data available from NVD',
      evidence,
      duration: Date.now() - startTime,
    };
  }

  evidence.cveProducts = affectedProducts.slice(0, 10);

  // Parse CPE strings and compare against detected tech from other tests
  // CPE format: cpe:2.3:a:vendor:product:version:...
  const parsedCPEs = affectedProducts.map(cpe => {
    const parts = cpe.split(':');
    return {
      raw: cpe,
      vendor: parts[3] || '',
      product: parts[4] || '',
      version: parts[5] || '*',
    };
  });

  // Check if any CPE products match the match's tech overlap
  const techOverlap = (match.techOverlap || []).map(t => t.toLowerCase());
  for (const cpe of parsedCPEs) {
    const product = cpe.product.toLowerCase().replace(/_/g, ' ');
    const vendor = cpe.vendor.toLowerCase().replace(/_/g, ' ');
    const combined = `${vendor} ${product}`;

    for (const tech of techOverlap) {
      if (combined.includes(tech) || product.includes(tech) || tech.includes(product)) {
        evidence.matchedProducts.push({
          cpe: cpe.raw,
          matchedTech: tech,
          vendor: cpe.vendor,
          product: cpe.product,
          version: cpe.version,
        });
      }
    }
  }

  const matched = evidence.matchedProducts.length;
  return {
    name: 'cpe_match',
    result: matched > 0 ? 'pass' : 'fail',
    detail: matched > 0
      ? `${matched} CPE match(es): ${evidence.matchedProducts.map(m => `${m.vendor}:${m.product} ↔ ${m.matchedTech}`).join(', ')}`
      : `No CPE products match detected tech stack (${affectedProducts.length} CPEs checked)`,
    evidence,
    duration: Date.now() - startTime,
  };
}

// ─── Phase 2: Nuclei Detection ───────────────────────────

/**
 * Run Nuclei detection-only templates against in-scope targets.
 * Only runs if:
 *   1. Nuclei binary is available
 *   2. Target URL is in program's scope
 *   3. Program has safeHarbor: true
 *
 * Only uses templates tagged 'info' or 'detection' — never 'exploit' or 'high'.
 */
export async function runNucleiDetection(match, program, targetUrl) {
  const startTime = Date.now();

  // Safety checks
  if (!program.safeHarbor) {
    return {
      name: 'nuclei_detection',
      result: 'skip',
      detail: 'Program does not have safe harbor — skipping Nuclei',
      evidence: {},
      duration: Date.now() - startTime,
    };
  }

  if (!isInScope(targetUrl, program)) {
    return {
      name: 'nuclei_detection',
      result: 'skip',
      detail: `URL ${targetUrl} is not in program scope — skipping Nuclei`,
      evidence: {},
      duration: Date.now() - startTime,
    };
  }

  // Check if Nuclei is available
  try {
    await execFileAsync('nuclei', ['-version'], { timeout: 5000 });
  } catch {
    return {
      name: 'nuclei_detection',
      result: 'skip',
      detail: 'Nuclei binary not available (Phase 2 requires Docker build)',
      evidence: {},
      duration: Date.now() - startTime,
    };
  }

  try {
    // Run Nuclei with detection-only templates
    // -severity info — only info-level templates (detection, fingerprinting)
    // -rl 5 — max 5 requests per second
    // -timeout 30 — 30 second overall timeout
    // -silent — minimal output
    // -jsonl — JSON lines output for parsing
    const args = [
      '-u', targetUrl,
      '-severity', 'info',
      '-type', 'http',
      '-rl', '5',
      '-timeout', '30',
      '-silent',
      '-jsonl',
      '-no-interactsh',
    ];

    // If CVE ID is known, try to match specific templates
    if (match.cveId) {
      args.push('-tags', match.cveId.toLowerCase().replace(/-/g, ''));
    }

    const { stdout, stderr } = await execFileAsync('nuclei', args, {
      timeout: 60000,
      maxBuffer: 1024 * 1024,
    });

    const findings = stdout.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);

    return {
      name: 'nuclei_detection',
      result: findings.length > 0 ? 'pass' : 'fail',
      detail: findings.length > 0
        ? `${findings.length} detection(s): ${findings.map(f => f['template-id'] || f.templateID || 'unknown').join(', ')}`
        : 'No Nuclei detections matched',
      evidence: {
        findings: findings.slice(0, 10),
        templateCount: findings.length,
        target: targetUrl,
      },
      duration: Date.now() - startTime,
    };
  } catch (err) {
    return {
      name: 'nuclei_detection',
      result: 'error',
      detail: `Nuclei execution error: ${err.message}`,
      evidence: {},
      duration: Date.now() - startTime,
    };
  }
}

// ─── Confidence Scoring ──────────────────────────────────

/**
 * Calculate confidence score (0-100) from test results.
 *
 * | Signal                     | Points |
 * |----------------------------|--------|
 * | Version match (exact)      | +30    |
 * | Version match (partial)    | +15    |
 * | Endpoint exists            | +20    |
 * | Technology confirmed       | +15    |
 * | Shodan correlation         | +10    |
 * | CPE match                  | +10    |
 * | Nuclei detection (Phase 2) | +15    |
 */
function calculateConfidence(tests) {
  let score = 0;

  for (const test of tests) {
    switch (test.name) {
      case 'version_fingerprint':
        if (test.result === 'pass') score += 30;
        else if (test.result === 'partial') score += 15;
        break;
      case 'endpoint_existence':
        if (test.result === 'pass') score += 20;
        break;
      case 'technology_confirmation':
        if (test.result === 'pass') score += 15;
        break;
      case 'shodan_lookup':
        if (test.result === 'pass') score += 10;
        break;
      case 'cpe_match':
        if (test.result === 'pass') score += 10;
        break;
      case 'nuclei_detection':
        if (test.result === 'pass') score += 15;
        break;
    }
  }

  return Math.min(100, score);
}

function getConfidenceLabel(score) {
  if (score >= 90) return 'confirmed';
  if (score >= 70) return 'likely_vulnerable';
  if (score >= 50) return 'uncertain';
  return 'unlikely';
}

// ─── Query Functions ─────────────────────────────────────

export function getTestResults(limit = 50) {
  return testResultsStore.slice(-limit).reverse();
}

export function getTestResultByMatch(matchId) {
  return testResultsStore.filter(r => r.matchId === matchId).sort((a, b) =>
    new Date(b.completedAt) - new Date(a.completedAt)
  );
}

export function getTestResultByCVE(cveId) {
  return testResultsStore.filter(r => r.cveId === cveId).sort((a, b) =>
    new Date(b.completedAt) - new Date(a.completedAt)
  );
}

// ─── Helpers ─────────────────────────────────────────────

function buildResult(matchId, cveId, programId, tier, status, confidenceScore, tests, auditLog, startTime) {
  return {
    matchId,
    cveId,
    programId,
    tier,
    status,
    confidenceScore,
    confidenceLabel: getConfidenceLabel(confidenceScore),
    tests,
    auditLog,
    startedAt: new Date(startTime).toISOString(),
    completedAt: new Date().toISOString(),
    duration: Date.now() - startTime,
  };
}

function extractTargetUrls(program) {
  const urls = [];
  const scopeItems = program.scope?.inScope || [];
  for (const item of scopeItems) {
    if (item.match(/^https?:\/\//)) {
      urls.push(item);
    } else if (item.match(/^\*\./)) {
      // Wildcard domain — use base domain
      const base = item.replace(/^\*\./, '');
      if (base.includes('.')) urls.push(`https://${base}`);
    } else if (item.match(/^[\w-]+\.[\w-]+\.\w+$/) || item.match(/^[\w-]+\.\w{2,}$/)) {
      // Bare domain
      urls.push(`https://${item}`);
    }
  }
  return [...new Set(urls)];
}

function extractVulnerablePaths(description, references) {
  const paths = [];
  const lower = description.toLowerCase();

  // Extract paths from description
  const pathMatches = description.match(/\/[\w\-./]+/g) || [];
  for (const p of pathMatches) {
    // Filter out version-like patterns and common false positives
    if (!p.match(/^\/\d/) && p.length > 2 && p.length < 100) {
      paths.push(p);
    }
  }

  // Extract paths from reference URLs
  for (const ref of references) {
    const url = ref.url || ref;
    if (typeof url === 'string') {
      const pathMatch = url.match(/\/(?:api|v\d|admin|upload|login|auth|debug|console|graphql|webhook|actuator|server-status|\.env|\.git)[\w\-./]*/i);
      if (pathMatch) paths.push(pathMatch[0]);
    }
  }

  // Common vulnerable endpoints based on description keywords
  if (lower.includes('upload')) paths.push('/upload', '/api/upload', '/api/v1/upload');
  if (lower.includes('graphql')) paths.push('/graphql', '/__graphql');
  if (lower.includes('admin')) paths.push('/admin', '/admin/login');
  if (lower.includes('api')) paths.push('/api', '/api/v1', '/api/v2');
  if (lower.includes('webhook')) paths.push('/webhook', '/api/webhook');
  if (lower.includes('actuator')) paths.push('/actuator', '/actuator/health', '/actuator/env');

  return [...new Set(paths)].slice(0, 10);
}

function isVersionInRange(detected, affectedVersions) {
  if (affectedVersions.length === 0) return false;

  for (const range of affectedVersions) {
    // Parse range expressions like ">=2.4.49 <2.4.50" or "<=7.0.2"
    const parts = range.match(/(>=?|<=?)([\d.]+)/g);
    if (!parts) continue;

    let inRange = true;
    for (const part of parts) {
      const opMatch = part.match(/(>=?|<=?)([\d.]+)/);
      if (!opMatch) continue;

      const [, op, ver] = opMatch;
      const cmp = compareVersions(detected, ver);

      switch (op) {
        case '>=': if (cmp < 0) inRange = false; break;
        case '>': if (cmp <= 0) inRange = false; break;
        case '<=': if (cmp > 0) inRange = false; break;
        case '<': if (cmp >= 0) inRange = false; break;
      }
    }
    if (inRange) return true;
  }
  return false;
}

function compareVersions(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  const len = Math.max(pa.length, pb.length);

  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

function isInScope(url, program) {
  const scopeItems = (program.scope?.inScope || []).map(s => s.toLowerCase());
  const urlLower = url.toLowerCase();

  for (const item of scopeItems) {
    // Direct URL match
    if (urlLower.includes(item.replace(/^\*\./, ''))) return true;
    // Wildcard domain match
    if (item.startsWith('*.')) {
      const base = item.slice(2);
      if (urlLower.includes(base)) return true;
    }
    // Product name match (e.g., "Chrome", "Docker Engine")
    if (urlLower.includes(item)) return true;
  }
  return false;
}

// ─── Rate Limiter (Phase 2) ──────────────────────────────

const rateLimitBuckets = new Map();

/**
 * Token bucket rate limiter — max 5 requests/second per domain.
 * Returns true if request is allowed.
 */
export function checkRateLimit(domain) {
  const now = Date.now();
  const bucket = rateLimitBuckets.get(domain) || { tokens: 5, lastRefill: now };

  // Refill tokens (5 per second)
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(5, bucket.tokens + elapsed * 5);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    rateLimitBuckets.set(domain, bucket);
    return true;
  }

  rateLimitBuckets.set(domain, bucket);
  return false;
}
