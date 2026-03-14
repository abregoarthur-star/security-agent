/**
 * Domain Security Scanner — Comprehensive Analysis
 *
 * Replaces the basic quickScan with deep security assessment:
 * 1. SSL/TLS analysis
 * 2. Security headers (8 headers, detailed analysis)
 * 3. Technology detection (server, frameworks, common paths)
 * 4. DNS checks (A, AAAA, MX, TXT, NS, CAA + email security)
 * 5. Common exposure checks (14 sensitive paths)
 * 6. Scoring system (0-100, letter grade, categorized findings)
 *
 * All checks run in parallel with timeouts. Graceful failure handling.
 */

import dns from 'node:dns';
import { promisify } from 'node:util';

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveNs = promisify(dns.resolveNs);
const resolveCaa = promisify(dns.resolveCaa);

const FETCH_TIMEOUT = 8000;
const DNS_TIMEOUT = 5000;

// ─── Main Scanner ────────────────────────────────────────

/**
 * Run a comprehensive domain security scan.
 * All checks execute in parallel for speed.
 *
 * @param {string} domain - Domain to scan (e.g. "example.com")
 * @returns {object} Structured scan report with score, grade, and findings
 */
export async function runDomainScan(domain) {
  const startTime = Date.now();

  // Normalize domain — strip protocol and trailing slashes
  domain = domain.replace(/^https?:\/\//, '').replace(/\/+$/, '').split('/')[0];

  // Run all checks in parallel
  const [sslResult, headersResult, techResult, dnsResult, exposureResult] = await Promise.allSettled([
    checkSSL(domain),
    checkSecurityHeaders(domain),
    detectTechnology(domain),
    checkDNS(domain),
    checkExposures(domain),
  ]);

  const ssl = sslResult.status === 'fulfilled' ? sslResult.value : { valid: false, error: sslResult.reason?.message };
  const headers = headersResult.status === 'fulfilled' ? headersResult.value : { headers: {}, error: headersResult.reason?.message };
  const tech = techResult.status === 'fulfilled' ? techResult.value : { error: techResult.reason?.message };
  const dnsData = dnsResult.status === 'fulfilled' ? dnsResult.value : { error: dnsResult.reason?.message };
  const exposures = exposureResult.status === 'fulfilled' ? exposureResult.value : { paths: [], error: exposureResult.reason?.message };

  // Collect all findings
  const findings = [
    ...generateSSLFindings(ssl),
    ...generateHeaderFindings(headers),
    ...generateTechFindings(tech),
    ...generateDNSFindings(dnsData),
    ...generateExposureFindings(exposures),
  ];

  // Calculate score and grade
  const { score, grade } = calculateScore(findings);

  return {
    domain,
    scanTime: Date.now() - startTime,
    timestamp: new Date().toISOString(),
    score,
    grade,
    ssl,
    headers: headers.headers,
    technology: tech,
    dns: dnsData,
    exposures: exposures.paths,
    findings,
    summary: {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length,
    },
  };
}

// ─── 1. SSL/TLS Analysis ────────────────────────────────

async function checkSSL(domain) {
  const result = {
    valid: false,
    httpsAccessible: false,
    httpsRedirect: false,
    certIssuer: null,
    certExpiry: null,
    protocol: null,
  };

  // Try HTTPS
  try {
    const res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    result.valid = true;
    result.httpsAccessible = true;
    result.statusCode = res.status;
  } catch (err) {
    result.error = err.message;
  }

  // Check HTTP -> HTTPS redirect
  try {
    const httpRes = await fetch(`http://${domain}`, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    const location = httpRes.headers.get('location');
    result.httpsRedirect = !!(location && location.startsWith('https://'));
    result.httpStatusCode = httpRes.status;
  } catch {
    // HTTP not accessible is fine
  }

  return result;
}

// ─── 2. Security Headers ────────────────────────────────

async function checkSecurityHeaders(domain) {
  const headerChecks = {};

  let res;
  try {
    res = await fetch(`https://${domain}`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
  } catch {
    // Fall back to HTTP
    try {
      res = await fetch(`http://${domain}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
    } catch (err) {
      return { headers: headerChecks, error: err.message };
    }
  }

  const h = res.headers;

  // Strict-Transport-Security
  const hsts = h.get('strict-transport-security');
  headerChecks.hsts = {
    present: !!hsts,
    value: hsts,
    maxAge: hsts ? parseInt((hsts.match(/max-age=(\d+)/i) || [])[1] || '0') : 0,
    includeSubDomains: hsts ? /includeSubDomains/i.test(hsts) : false,
    preload: hsts ? /preload/i.test(hsts) : false,
  };

  // Content-Security-Policy
  const csp = h.get('content-security-policy');
  headerChecks.csp = {
    present: !!csp,
    value: csp?.slice(0, 500),
    hasDefaultSrc: csp ? /default-src/i.test(csp) : false,
    hasScriptSrc: csp ? /script-src/i.test(csp) : false,
    hasUnsafeInline: csp ? /unsafe-inline/i.test(csp) : false,
    hasUnsafeEval: csp ? /unsafe-eval/i.test(csp) : false,
  };

  // X-Frame-Options
  const xfo = h.get('x-frame-options');
  headerChecks.xFrameOptions = {
    present: !!xfo,
    value: xfo,
  };

  // X-Content-Type-Options
  const xcto = h.get('x-content-type-options');
  headerChecks.xContentTypeOptions = {
    present: !!xcto,
    value: xcto,
    correct: xcto?.toLowerCase() === 'nosniff',
  };

  // Referrer-Policy
  const rp = h.get('referrer-policy');
  headerChecks.referrerPolicy = {
    present: !!rp,
    value: rp,
  };

  // Permissions-Policy
  const pp = h.get('permissions-policy');
  headerChecks.permissionsPolicy = {
    present: !!pp,
    value: pp?.slice(0, 300),
  };

  // Cross-Origin-Opener-Policy
  const coop = h.get('cross-origin-opener-policy');
  headerChecks.crossOriginOpenerPolicy = {
    present: !!coop,
    value: coop,
  };

  // Cross-Origin-Resource-Policy
  const corp = h.get('cross-origin-resource-policy');
  headerChecks.crossOriginResourcePolicy = {
    present: !!corp,
    value: corp,
  };

  return { headers: headerChecks };
}

// ─── 3. Technology Detection ────────────────────────────

async function detectTechnology(domain) {
  const tech = {
    server: null,
    poweredBy: null,
    framework: null,
    detectedTech: [],
    paths: {},
  };

  // Fetch main page headers for tech detection
  let res;
  try {
    res = await fetch(`https://${domain}`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
  } catch {
    try {
      res = await fetch(`http://${domain}`, {
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
    } catch {
      return tech;
    }
  }

  tech.server = res.headers.get('server');
  tech.poweredBy = res.headers.get('x-powered-by');

  // Framework detection from headers
  const headerSignatures = {
    'x-aspnet-version': 'ASP.NET',
    'x-aspnetmvc-version': 'ASP.NET MVC',
    'x-drupal-cache': 'Drupal',
    'x-generator': res.headers.get('x-generator'),
    'x-shopify-stage': 'Shopify',
    'x-wix-request-id': 'Wix',
    'x-nextjs-page': 'Next.js',
    'x-vercel-id': 'Vercel',
    'cf-ray': 'Cloudflare',
    'x-amz-cf-id': 'AWS CloudFront',
    'x-cache': res.headers.get('x-cache'),
    'fly-request-id': 'Fly.io',
  };

  for (const [header, name] of Object.entries(headerSignatures)) {
    const val = res.headers.get(header);
    if (val) {
      tech.detectedTech.push(typeof name === 'string' ? name : `${header}: ${val}`);
    }
  }

  // Body-based detection (read first 10KB)
  try {
    const body = await res.text();
    const head = body.slice(0, 10000).toLowerCase();

    if (head.includes('wp-content') || head.includes('wp-includes')) tech.detectedTech.push('WordPress');
    if (head.includes('drupal.settings') || head.includes('drupal.js')) tech.detectedTech.push('Drupal');
    if (head.includes('joomla')) tech.detectedTech.push('Joomla');
    if (head.includes('__next')) tech.detectedTech.push('Next.js');
    if (head.includes('_nuxt')) tech.detectedTech.push('Nuxt.js');
    if (head.includes('react')) tech.detectedTech.push('React');
    if (head.includes('angular') || head.includes('ng-version')) tech.detectedTech.push('Angular');
    if (head.includes('vue')) tech.detectedTech.push('Vue.js');
    if (head.includes('shopify')) tech.detectedTech.push('Shopify');
    if (head.includes('squarespace')) tech.detectedTech.push('Squarespace');
  } catch {
    // Body read failure is non-critical
  }

  // Deduplicate
  tech.detectedTech = [...new Set(tech.detectedTech)];

  // Check common informational paths
  const pathChecks = [
    { path: '/robots.txt', name: 'robots.txt' },
    { path: '/.well-known/security.txt', name: 'security.txt' },
    { path: '/sitemap.xml', name: 'sitemap.xml' },
  ];

  const pathResults = await Promise.allSettled(
    pathChecks.map(async ({ path, name }) => {
      const r = await fetch(`https://${domain}${path}`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
      return { name, status: r.status, exists: r.status >= 200 && r.status < 400 };
    })
  );

  for (const pr of pathResults) {
    if (pr.status === 'fulfilled') {
      tech.paths[pr.value.name] = pr.value;
    }
  }

  return tech;
}

// ─── 4. DNS Checks ──────────────────────────────────────

async function checkDNS(domain) {
  const result = {
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    caa: [],
    spf: null,
    dmarc: null,
    dkim: null,
    emailSecurity: { spf: false, dmarc: false, dkim: false },
  };

  const dnsChecks = await Promise.allSettled([
    withTimeout(resolve4(domain), DNS_TIMEOUT),
    withTimeout(resolve6(domain), DNS_TIMEOUT),
    withTimeout(resolveMx(domain), DNS_TIMEOUT),
    withTimeout(resolveTxt(domain), DNS_TIMEOUT),
    withTimeout(resolveNs(domain), DNS_TIMEOUT),
    withTimeout(resolveCaa(domain), DNS_TIMEOUT),
    // DMARC lives at _dmarc.domain
    withTimeout(resolveTxt(`_dmarc.${domain}`), DNS_TIMEOUT),
  ]);

  if (dnsChecks[0].status === 'fulfilled') result.a = dnsChecks[0].value;
  if (dnsChecks[1].status === 'fulfilled') result.aaaa = dnsChecks[1].value;
  if (dnsChecks[2].status === 'fulfilled') result.mx = dnsChecks[2].value.sort((a, b) => a.priority - b.priority);
  if (dnsChecks[3].status === 'fulfilled') {
    result.txt = dnsChecks[3].value.map(r => r.join(''));

    // Check SPF
    const spfRecord = result.txt.find(t => t.startsWith('v=spf1'));
    if (spfRecord) {
      result.spf = spfRecord;
      result.emailSecurity.spf = true;
    }

    // Check for DKIM selector hints in TXT records
    const dkimHint = result.txt.find(t => t.includes('v=DKIM1') || t.includes('dkim'));
    if (dkimHint) {
      result.dkim = dkimHint;
      result.emailSecurity.dkim = true;
    }
  }
  if (dnsChecks[4].status === 'fulfilled') result.ns = dnsChecks[4].value;
  if (dnsChecks[5].status === 'fulfilled') result.caa = dnsChecks[5].value;

  // DMARC record from _dmarc.domain
  if (dnsChecks[6].status === 'fulfilled') {
    const dmarcRecords = dnsChecks[6].value.map(r => r.join(''));
    const dmarcRecord = dmarcRecords.find(t => t.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      result.dmarc = dmarcRecord;
      result.emailSecurity.dmarc = true;
    }
  }

  // Try common DKIM selectors if not found yet
  if (!result.emailSecurity.dkim) {
    const dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'mail'];
    const dkimChecks = await Promise.allSettled(
      dkimSelectors.map(sel =>
        withTimeout(resolveTxt(`${sel}._domainkey.${domain}`), DNS_TIMEOUT)
      )
    );

    for (let i = 0; i < dkimChecks.length; i++) {
      if (dkimChecks[i].status === 'fulfilled') {
        const records = dkimChecks[i].value.map(r => r.join(''));
        const dkimRec = records.find(t => t.includes('v=DKIM1'));
        if (dkimRec) {
          result.dkim = `${dkimSelectors[i]}._domainkey: ${dkimRec.slice(0, 100)}...`;
          result.emailSecurity.dkim = true;
          break;
        }
      }
    }
  }

  return result;
}

// ─── 5. Common Exposure Checks ──────────────────────────

async function checkExposures(domain) {
  const sensitivePaths = [
    { path: '/.env', name: '.env file', severity: 'CRITICAL', desc: 'Environment variables with secrets' },
    { path: '/.git/HEAD', name: 'Git repository', severity: 'CRITICAL', desc: 'Source code exposure via .git' },
    { path: '/wp-login.php', name: 'WordPress login', severity: 'INFO', desc: 'WordPress CMS detected' },
    { path: '/api/swagger', name: 'Swagger API docs', severity: 'MEDIUM', desc: 'API documentation exposed' },
    { path: '/swagger-ui.html', name: 'Swagger UI', severity: 'MEDIUM', desc: 'Swagger UI exposed' },
    { path: '/.DS_Store', name: '.DS_Store', severity: 'LOW', desc: 'macOS directory metadata exposed' },
    { path: '/server-status', name: 'Apache server-status', severity: 'HIGH', desc: 'Apache status page exposed' },
    { path: '/server-info', name: 'Apache server-info', severity: 'HIGH', desc: 'Apache server info exposed' },
    { path: '/phpinfo.php', name: 'phpinfo()', severity: 'HIGH', desc: 'PHP configuration exposed' },
    { path: '/actuator', name: 'Spring Boot Actuator', severity: 'HIGH', desc: 'Spring Boot management endpoints' },
    { path: '/debug', name: 'Debug endpoint', severity: 'MEDIUM', desc: 'Debug interface exposed' },
    { path: '/console', name: 'Console endpoint', severity: 'HIGH', desc: 'Console interface exposed' },
    { path: '/admin', name: 'Admin panel', severity: 'INFO', desc: 'Admin panel detected' },
    { path: '/graphql', name: 'GraphQL endpoint', severity: 'MEDIUM', desc: 'GraphQL endpoint (check introspection)' },
  ];

  const results = await Promise.allSettled(
    sensitivePaths.map(async ({ path, name, severity, desc }) => {
      try {
        const res = await fetch(`https://${domain}${path}`, {
          method: 'GET',
          redirect: 'follow',
          signal: AbortSignal.timeout(FETCH_TIMEOUT),
          headers: { 'User-Agent': 'SecurityScanner/1.0' },
        });

        const status = res.status;
        // Read a small chunk to verify content (not just a generic error page)
        let contentHint = '';
        try {
          const text = await res.text();
          contentHint = text.slice(0, 200);
        } catch {}

        const exposed = status >= 200 && status < 300;

        return {
          path,
          name,
          severity,
          desc,
          status,
          exposed,
          contentHint: exposed ? contentHint.slice(0, 100) : null,
        };
      } catch {
        return { path, name, severity, desc, status: null, exposed: false, error: 'timeout/unreachable' };
      }
    })
  );

  const paths = results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);

  return { paths };
}

// ─── Finding Generators ─────────────────────────────────

function generateSSLFindings(ssl) {
  const findings = [];

  if (ssl.valid) {
    findings.push({ category: 'SSL/TLS', check: 'HTTPS accessible', severity: 'INFO', status: 'PASS', detail: 'Site is accessible over HTTPS' });
  } else {
    findings.push({ category: 'SSL/TLS', check: 'HTTPS accessible', severity: 'CRITICAL', status: 'FAIL', detail: ssl.error || 'Site is not accessible over HTTPS' });
  }

  if (ssl.httpsRedirect) {
    findings.push({ category: 'SSL/TLS', check: 'HTTP to HTTPS redirect', severity: 'INFO', status: 'PASS', detail: 'HTTP redirects to HTTPS' });
  } else if (ssl.valid) {
    findings.push({ category: 'SSL/TLS', check: 'HTTP to HTTPS redirect', severity: 'MEDIUM', status: 'FAIL', detail: 'HTTP does not redirect to HTTPS' });
  }

  return findings;
}

function generateHeaderFindings(headerData) {
  const findings = [];
  const h = headerData.headers || {};

  // HSTS
  if (h.hsts?.present) {
    if (h.hsts.maxAge >= 31536000) {
      findings.push({ category: 'Headers', check: 'HSTS', severity: 'INFO', status: 'PASS', detail: `max-age=${h.hsts.maxAge}${h.hsts.includeSubDomains ? ', includeSubDomains' : ''}${h.hsts.preload ? ', preload' : ''}` });
    } else {
      findings.push({ category: 'Headers', check: 'HSTS', severity: 'LOW', status: 'WARN', detail: `max-age=${h.hsts.maxAge} is below recommended 31536000 (1 year)` });
    }
  } else {
    findings.push({ category: 'Headers', check: 'HSTS', severity: 'HIGH', status: 'FAIL', detail: 'Strict-Transport-Security header missing' });
  }

  // CSP
  if (h.csp?.present) {
    if (h.csp.hasUnsafeInline || h.csp.hasUnsafeEval) {
      const issues = [];
      if (h.csp.hasUnsafeInline) issues.push('unsafe-inline');
      if (h.csp.hasUnsafeEval) issues.push('unsafe-eval');
      findings.push({ category: 'Headers', check: 'CSP', severity: 'MEDIUM', status: 'WARN', detail: `CSP present but uses ${issues.join(', ')}` });
    } else {
      findings.push({ category: 'Headers', check: 'CSP', severity: 'INFO', status: 'PASS', detail: 'Content-Security-Policy is set and restrictive' });
    }
  } else {
    findings.push({ category: 'Headers', check: 'CSP', severity: 'HIGH', status: 'FAIL', detail: 'Content-Security-Policy header missing' });
  }

  // X-Frame-Options
  if (h.xFrameOptions?.present) {
    findings.push({ category: 'Headers', check: 'X-Frame-Options', severity: 'INFO', status: 'PASS', detail: `Value: ${h.xFrameOptions.value}` });
  } else {
    findings.push({ category: 'Headers', check: 'X-Frame-Options', severity: 'MEDIUM', status: 'FAIL', detail: 'X-Frame-Options header missing (clickjacking risk)' });
  }

  // X-Content-Type-Options
  if (h.xContentTypeOptions?.present) {
    findings.push({ category: 'Headers', check: 'X-Content-Type-Options', severity: 'INFO', status: 'PASS', detail: `Value: ${h.xContentTypeOptions.value}` });
  } else {
    findings.push({ category: 'Headers', check: 'X-Content-Type-Options', severity: 'MEDIUM', status: 'FAIL', detail: 'X-Content-Type-Options header missing (MIME sniffing risk)' });
  }

  // Referrer-Policy
  if (h.referrerPolicy?.present) {
    findings.push({ category: 'Headers', check: 'Referrer-Policy', severity: 'INFO', status: 'PASS', detail: `Value: ${h.referrerPolicy.value}` });
  } else {
    findings.push({ category: 'Headers', check: 'Referrer-Policy', severity: 'LOW', status: 'FAIL', detail: 'Referrer-Policy header missing' });
  }

  // Permissions-Policy
  if (h.permissionsPolicy?.present) {
    findings.push({ category: 'Headers', check: 'Permissions-Policy', severity: 'INFO', status: 'PASS', detail: 'Permissions-Policy is set' });
  } else {
    findings.push({ category: 'Headers', check: 'Permissions-Policy', severity: 'LOW', status: 'FAIL', detail: 'Permissions-Policy header missing' });
  }

  // COOP
  if (h.crossOriginOpenerPolicy?.present) {
    findings.push({ category: 'Headers', check: 'COOP', severity: 'INFO', status: 'PASS', detail: `Value: ${h.crossOriginOpenerPolicy.value}` });
  } else {
    findings.push({ category: 'Headers', check: 'COOP', severity: 'LOW', status: 'FAIL', detail: 'Cross-Origin-Opener-Policy header missing' });
  }

  // CORP
  if (h.crossOriginResourcePolicy?.present) {
    findings.push({ category: 'Headers', check: 'CORP', severity: 'INFO', status: 'PASS', detail: `Value: ${h.crossOriginResourcePolicy.value}` });
  } else {
    findings.push({ category: 'Headers', check: 'CORP', severity: 'LOW', status: 'FAIL', detail: 'Cross-Origin-Resource-Policy header missing' });
  }

  return findings;
}

function generateTechFindings(tech) {
  const findings = [];

  if (tech.poweredBy) {
    findings.push({
      category: 'Technology',
      check: 'X-Powered-By exposed',
      severity: 'MEDIUM',
      status: 'FAIL',
      detail: `X-Powered-By: ${tech.poweredBy} (information leak — remove this header)`,
    });
  }

  if (tech.server) {
    // Server header with version info is an info leak
    const hasVersion = /[\d.]+/.test(tech.server);
    findings.push({
      category: 'Technology',
      check: 'Server header',
      severity: hasVersion ? 'LOW' : 'INFO',
      status: hasVersion ? 'WARN' : 'INFO',
      detail: `Server: ${tech.server}${hasVersion ? ' (version exposed — consider removing)' : ''}`,
    });
  }

  if (tech.paths?.['security.txt']?.exists) {
    findings.push({ category: 'Technology', check: 'security.txt', severity: 'INFO', status: 'PASS', detail: 'security.txt is present (good practice)' });
  } else {
    findings.push({ category: 'Technology', check: 'security.txt', severity: 'INFO', status: 'INFO', detail: 'No security.txt found (recommended: /.well-known/security.txt)' });
  }

  if (tech.detectedTech?.length > 0) {
    findings.push({
      category: 'Technology',
      check: 'Stack detection',
      severity: 'INFO',
      status: 'INFO',
      detail: `Detected: ${tech.detectedTech.join(', ')}`,
    });
  }

  return findings;
}

function generateDNSFindings(dnsData) {
  const findings = [];

  if (dnsData.error) {
    findings.push({ category: 'DNS', check: 'DNS resolution', severity: 'HIGH', status: 'FAIL', detail: `DNS check failed: ${dnsData.error}` });
    return findings;
  }

  // A records
  if (dnsData.a?.length > 0) {
    findings.push({ category: 'DNS', check: 'A records', severity: 'INFO', status: 'INFO', detail: `${dnsData.a.length} A record(s): ${dnsData.a.slice(0, 3).join(', ')}` });
  }

  // AAAA records (IPv6)
  if (dnsData.aaaa?.length > 0) {
    findings.push({ category: 'DNS', check: 'IPv6 (AAAA)', severity: 'INFO', status: 'PASS', detail: `IPv6 enabled: ${dnsData.aaaa.length} AAAA record(s)` });
  }

  // SPF
  if (dnsData.emailSecurity?.spf) {
    findings.push({ category: 'DNS', check: 'SPF', severity: 'INFO', status: 'PASS', detail: `SPF record present: ${dnsData.spf?.slice(0, 80)}` });
  } else if (dnsData.mx?.length > 0) {
    findings.push({ category: 'DNS', check: 'SPF', severity: 'HIGH', status: 'FAIL', detail: 'No SPF record found (email spoofing risk)' });
  }

  // DMARC
  if (dnsData.emailSecurity?.dmarc) {
    findings.push({ category: 'DNS', check: 'DMARC', severity: 'INFO', status: 'PASS', detail: `DMARC record present: ${dnsData.dmarc?.slice(0, 80)}` });
  } else if (dnsData.mx?.length > 0) {
    findings.push({ category: 'DNS', check: 'DMARC', severity: 'HIGH', status: 'FAIL', detail: 'No DMARC record found (email spoofing risk)' });
  }

  // DKIM
  if (dnsData.emailSecurity?.dkim) {
    findings.push({ category: 'DNS', check: 'DKIM', severity: 'INFO', status: 'PASS', detail: 'DKIM record found' });
  } else if (dnsData.mx?.length > 0) {
    findings.push({ category: 'DNS', check: 'DKIM', severity: 'MEDIUM', status: 'WARN', detail: 'No DKIM record found on common selectors' });
  }

  // CAA records
  if (dnsData.caa?.length > 0) {
    findings.push({ category: 'DNS', check: 'CAA', severity: 'INFO', status: 'PASS', detail: `CAA records restrict certificate issuance: ${dnsData.caa.map(c => c.value).join(', ')}` });
  } else {
    findings.push({ category: 'DNS', check: 'CAA', severity: 'LOW', status: 'WARN', detail: 'No CAA records (any CA can issue certificates for this domain)' });
  }

  // MX records
  if (dnsData.mx?.length > 0) {
    findings.push({ category: 'DNS', check: 'MX records', severity: 'INFO', status: 'INFO', detail: `${dnsData.mx.length} MX record(s): ${dnsData.mx.slice(0, 3).map(m => m.exchange).join(', ')}` });
  }

  // NS records
  if (dnsData.ns?.length > 0) {
    findings.push({ category: 'DNS', check: 'NS records', severity: 'INFO', status: 'INFO', detail: `Nameservers: ${dnsData.ns.slice(0, 4).join(', ')}` });
  }

  return findings;
}

function generateExposureFindings(exposureData) {
  const findings = [];

  for (const path of (exposureData.paths || [])) {
    if (path.exposed) {
      // Verify it's not a generic error/redirect page masquerading as 200
      const isFalsePositive = path.contentHint &&
        (path.contentHint.toLowerCase().includes('not found') ||
         path.contentHint.toLowerCase().includes('404') ||
         path.contentHint.toLowerCase().includes('error'));

      if (!isFalsePositive) {
        findings.push({
          category: 'Exposure',
          check: path.name,
          severity: path.severity,
          status: 'FAIL',
          detail: `${path.path} returned HTTP ${path.status} — ${path.desc}`,
        });
      }
    }
  }

  return findings;
}

// ─── Scoring System ─────────────────────────────────────

function calculateScore(findings) {
  // Start at 100, deduct based on severity
  let score = 100;

  const deductions = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 8,
    LOW: 3,
  };

  for (const finding of findings) {
    if (finding.status === 'FAIL' || finding.status === 'WARN') {
      score -= deductions[finding.severity] || 0;
    }
  }

  // Floor at 0
  score = Math.max(0, score);

  // Letter grade
  let grade;
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'A-';
  else if (score >= 70) grade = 'B';
  else if (score >= 60) grade = 'B-';
  else if (score >= 50) grade = 'C';
  else if (score >= 40) grade = 'C-';
  else if (score >= 30) grade = 'D';
  else if (score >= 20) grade = 'D-';
  else grade = 'F';

  return { score, grade };
}

// ─── Helpers ────────────────────────────────────────────

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), ms)),
  ]);
}
