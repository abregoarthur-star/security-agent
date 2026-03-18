/**
 * Bounty Program Manager — Scalable CVE-to-Program Matching
 *
 * Adding a new bounty program = adding a data entry.
 * Incoming CVEs are automatically matched against all programs' tech stacks.
 * One CVE can match multiple programs — that's a feature (multiple payouts).
 *
 * First to find + first to report = first to get paid.
 */

import { getBountyRelevantCVEs } from './intel.js';
import { getNewPOCs, getExploitedInWild } from './underground.js';
import { readJSON, createDebouncedWriter } from './store.js';

// ─── Persistent Store ─────────────────────────────────────

const saved = readJSON('bounty-store.json', null);

let bountyStore = {
  programs: [],          // Program registry (rebuilt from BUILT_IN on boot)
  matches: saved?.matches || [],
  submissions: saved?.submissions || [],
  lastMatchRun: saved?.lastMatchRun || null,
};

const scheduleSave = createDebouncedWriter('bounty-store.json', 3000);

function saveBountyStore() {
  scheduleSave({
    matches: bountyStore.matches,
    submissions: bountyStore.submissions,
    lastMatchRun: bountyStore.lastMatchRun,
  });
}

if (saved) {
  console.log(`[BOUNTY] Loaded ${saved.matches?.length || 0} matches, ${saved.submissions?.length || 0} submissions from disk`);
}

// ─── Built-in Programs ────────────────────────────────────

const BUILT_IN_PROGRAMS = [
  // ─── Existing ─────────────────────────────────────────────
  {
    id: 'railway',
    name: 'Railway',
    platform: 'independent',
    url: 'https://railway.com/bug-bounty-program.pdf',
    submitTo: 'bugbounty@railway.com',
    techStack: [
      'node', 'docker', 'kubernetes', 'postgresql', 'redis', 'nginx',
      'graphql', 'rest', 'api', 'webhook', 'typescript', 'go', 'rust',
      'python', 'container', 'deploy', 'proxy', 'dns', 'ssl', 'tls',
    ],
    scope: {
      inScope: ['*.railway.app', 'railway.com', 'API endpoints', 'dashboard', 'CLI'],
      outOfScope: ['self-xss', 'rate-limiting', 'csv-injection', 'social-engineering', 'ddos'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-284',
      'CWE-502', 'CWE-78', 'CWE-22', 'CWE-862', 'CWE-863',
      'CWE-94', 'CWE-200',
    ],
    maxBounty: null,
    rewardsModel: 'cvss',
    safeHarbor: true,
    active: true,
    notes: 'CVSS 3.1 based rewards, paid within 30 days. Container escape / infra isolation bypass = highest value.',
    addedAt: '2026-03-14T00:00:00Z',
  },

  // ─── Tier 1 — Highest ROI ─────────────────────────────────

  {
    id: 'google-vrp',
    name: 'Google VRP',
    platform: 'independent',
    url: 'https://bughunters.google.com/',
    submitTo: 'https://bughunters.google.com/report',
    techStack: [
      'chrome', 'chromium', 'v8', 'skia', 'android', 'golang', 'grpc',
      'protobuf', 'kubernetes', 'gcp', 'cloud', 'firebase', 'angular',
      'tensorflow', 'webrtc', 'webassembly', 'wasm', 'pdfium', 'blink',
    ],
    scope: {
      inScope: ['*.google.com', 'Chrome', 'Android', 'GCP', 'Chromium', 'Google Cloud'],
      outOfScope: ['social-engineering', 'ddos', 'phishing', 'spam'],
    },
    cweHighValue: [
      'CWE-416', // Use After Free (Chrome)
      'CWE-787', // Out-of-bounds Write
      'CWE-125', // Out-of-bounds Read
      'CWE-94',  // Code Injection
      'CWE-843', // Type Confusion
      'CWE-79', 'CWE-352', 'CWE-918', 'CWE-287', 'CWE-862',
    ],
    maxBounty: 150000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Chrome zero-days dropping weekly. V8/Skia variant hunting = top payouts. $500-$150K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'microsoft-msrc',
    name: 'Microsoft MSRC',
    platform: 'independent',
    url: 'https://www.microsoft.com/en-us/msrc/bounty',
    submitTo: 'https://msrc.microsoft.com/report/vulnerability',
    techStack: [
      'windows', 'azure', 'active directory', 'exchange', '.net', 'dotnet',
      'asp.net', 'iis', 'sql server', 'office', 'outlook', 'sharepoint',
      'teams', 'hyper-v', 'edge', 'defender', 'entra', 'powershell',
      'ntlm', 'kerberos', 'ldap', 'smb', 'rdp', 'ad',
    ],
    scope: {
      inScope: ['Windows', 'Azure', 'Microsoft 365', 'Edge', 'Active Directory', 'Exchange', 'Hyper-V'],
      outOfScope: ['social-engineering', 'ddos', 'physical-access'],
    },
    cweHighValue: [
      'CWE-269', // Privilege Escalation
      'CWE-287', // Auth Bypass
      'CWE-78',  // Command Injection
      'CWE-94',  // Code Injection
      'CWE-416', // Use After Free
      'CWE-787', // OOB Write
      'CWE-918', 'CWE-89', 'CWE-22', 'CWE-502',
    ],
    maxBounty: 100000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: '84 CVEs per Patch Tuesday. AD/Exchange/Hyper-V = highest tier. AD SPN vuln already in PoC tracker.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'immunefi-top20',
    name: 'Immunefi Top 20',
    platform: 'immunefi',
    url: 'https://immunefi.com/explore/',
    submitTo: 'https://immunefi.com/',
    techStack: [
      'solidity', 'ethereum', 'smart contract', 'defi', 'evm', 'web3',
      'blockchain', 'bridge', 'lending', 'amm', 'oracle', 'token',
      'uniswap', 'aave', 'compound', 'chainlink', 'layer2', 'rollup',
      'rust', 'cosmwasm', 'solana', 'move', 'vyper',
    ],
    scope: {
      inScope: ['Smart contracts', 'DeFi protocols', 'Bridges', 'Oracles', 'Layer 2'],
      outOfScope: ['frontend-only', 'social-engineering', 'already-public'],
    },
    cweHighValue: [
      'CWE-682', // Incorrect Calculation (reentrancy, rounding)
      'CWE-863', // Incorrect Authorization
      'CWE-362', // Race Condition
      'CWE-190', // Integer Overflow
      'CWE-284', // Improper Access Control
      'CWE-94',  // Code Injection
      'CWE-502', 'CWE-287',
    ],
    maxBounty: 500000,
    rewardsModel: 'custom',
    safeHarbor: true,
    active: true,
    notes: 'Crypto pays the most. $50K-$500K regularly. DeFi protocols always in scope. Weight these HEAVILY in scoring.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'hackerone-top50',
    name: 'HackerOne Top 50',
    platform: 'hackerone',
    url: 'https://hackerone.com/directory/programs',
    submitTo: 'https://hackerone.com/',
    techStack: [
      'ruby', 'rails', 'node', 'python', 'java', 'php', 'go', 'react',
      'graphql', 'rest', 'api', 'aws', 'docker', 'kubernetes', 'nginx',
      'postgresql', 'mysql', 'redis', 'elasticsearch', 'oauth', 'saml',
      'jwt', 'webhook', 'mobile', 'ios', 'android',
    ],
    scope: {
      inScope: ['Shopify', 'GitLab', 'Uber', 'Yahoo', 'Coinbase', 'AT&T', 'Dropbox', 'PayPal'],
      outOfScope: ['self-xss', 'rate-limiting', 'social-engineering'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-862',
      'CWE-863', 'CWE-502', 'CWE-78', 'CWE-22', 'CWE-352',
      'CWE-434', 'CWE-601', 'CWE-94', 'CWE-200', 'CWE-269',
    ],
    maxBounty: 50000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Broadest coverage. One CVE can match many H1 programs. $150-$50K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'bugcrowd-top30',
    name: 'Bugcrowd Top 30',
    platform: 'bugcrowd',
    url: 'https://bugcrowd.com/programs',
    submitTo: 'https://bugcrowd.com/',
    techStack: [
      'node', 'python', 'java', 'php', 'ruby', 'go', 'react', 'angular',
      'vue', 'graphql', 'rest', 'api', 'aws', 'azure', 'docker',
      'kubernetes', 'nginx', 'apache', 'postgresql', 'mysql', 'mongodb',
      'oauth', 'saml', 'mobile', 'ios', 'android',
    ],
    scope: {
      inScope: ['Tesla', 'MasterCard', 'Atlassian', 'Veeam', 'Twilio', 'DigitalOcean', 'Netgear'],
      outOfScope: ['self-xss', 'rate-limiting', 'social-engineering'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-862',
      'CWE-863', 'CWE-502', 'CWE-78', 'CWE-22', 'CWE-352',
      'CWE-434', 'CWE-601', 'CWE-94', 'CWE-200',
    ],
    maxBounty: 40000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Veeam CVSS 9.9 RCE just dropped. Tesla, MasterCard, Atlassian. $150-$40K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },

  // ─── Tier 2 — Strong Match to Current Intel ───────────────

  {
    id: 'apple-security',
    name: 'Apple Security Bounty',
    platform: 'independent',
    url: 'https://security.apple.com/bounty/',
    submitTo: 'https://security.apple.com/bounty/',
    techStack: [
      'ios', 'macos', 'safari', 'webkit', 'xnu', 'iphone', 'ipad',
      'apple', 'swift', 'objective-c', 'icloud', 'siri', 'airdrop',
      'bluetooth', 'usb', 'kernel', 'sandbox', 'codesign', 'lockdown',
    ],
    scope: {
      inScope: ['iOS', 'macOS', 'Safari', 'iCloud', 'Apple hardware', 'Lockdown Mode'],
      outOfScope: ['social-engineering', 'ddos', 'physical-access-only'],
    },
    cweHighValue: [
      'CWE-416', 'CWE-787', 'CWE-125', 'CWE-843', 'CWE-269',
      'CWE-94', 'CWE-287', 'CWE-200', 'CWE-284',
    ],
    maxBounty: 1000000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Two iPhone zero-days just patched. iOS/macOS variant hunting. $5K-$1M. Lockdown Mode bypass = max.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'alibaba',
    name: 'Alibaba / Ant Group',
    platform: 'independent',
    url: 'https://security.alibaba.com/',
    submitTo: 'https://security.alibaba.com/',
    techStack: [
      'java', 'spring', 'android', 'ios', 'react', 'node', 'mysql',
      'postgresql', 'redis', 'nginx', 'api', 'rest', 'graphql', 'oauth',
      'alipay', 'deeplink', 'jsbridge', 'mobile', 'cloud', 'oss',
    ],
    scope: {
      inScope: ['Alibaba Cloud', 'Alipay', 'Taobao', 'Ant Group', 'DingTalk'],
      outOfScope: ['social-engineering', 'ddos', 'self-xss'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-862',
      'CWE-78', 'CWE-22', 'CWE-502', 'CWE-94', 'CWE-601',
    ],
    maxBounty: 50000,
    rewardsModel: 'custom',
    safeHarbor: true,
    active: true,
    notes: 'Alipay DeepLink+JSBridge CVSS 9.3, 17 vulns, 6 CVEs already in feed. Direct bounty target. $500-$50K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'veeam',
    name: 'Veeam',
    platform: 'bugcrowd',
    url: 'https://bugcrowd.com/veeam',
    submitTo: 'https://bugcrowd.com/veeam',
    techStack: [
      'windows', '.net', 'dotnet', 'sql server', 'powershell', 'rest',
      'api', 'backup', 'vmware', 'hyper-v', 'aws', 'azure', 'agent',
      'linux', 'ssh', 'smb', 'nfs', 'iscsi',
    ],
    scope: {
      inScope: ['Veeam Backup & Replication', 'Veeam ONE', 'Veeam Agent', 'Service Provider Console'],
      outOfScope: ['social-engineering', 'ddos', 'physical-access'],
    },
    cweHighValue: [
      'CWE-502', // Deserialization (their #1 issue)
      'CWE-78', 'CWE-89', 'CWE-287', 'CWE-269', 'CWE-22',
      'CWE-918', 'CWE-94', 'CWE-284',
    ],
    maxBounty: 25000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'CVE-2026-21666 CVSS 9.9 RCE just dropped. 7 critical RCEs. HOT target right now. $500-$25K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'fortinet',
    name: 'Fortinet PSIRT',
    platform: 'independent',
    url: 'https://www.fortiguard.com/psirt-policy',
    submitTo: 'psirt@fortinet.com',
    techStack: [
      'fortios', 'fortigate', 'fortiweb', 'fortianalyzer', 'fortimanager',
      'forticlient', 'ssl vpn', 'vpn', 'firewall', 'waf', 'proxy',
      'nginx', 'apache', 'linux', 'api', 'rest', 'ssh', 'snmp',
    ],
    scope: {
      inScope: ['FortiOS', 'FortiWeb', 'FortiGate', 'FortiAnalyzer', 'FortiManager', 'FortiClient'],
      outOfScope: ['social-engineering', 'ddos'],
    },
    cweHighValue: [
      'CWE-78', 'CWE-89', 'CWE-22', 'CWE-287', 'CWE-918',
      'CWE-269', 'CWE-79', 'CWE-502', 'CWE-306', 'CWE-863',
    ],
    maxBounty: 20000,
    rewardsModel: 'custom',
    safeHarbor: true,
    active: true,
    notes: 'FortiWeb actively exploited (CVE-2025-64446). They pay for variants. $500-$20K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'cisco',
    name: 'Cisco PSIRT',
    platform: 'independent',
    url: 'https://tools.cisco.com/security/center/resources/security_vulnerability_policy.html',
    submitTo: 'psirt@cisco.com',
    techStack: [
      'ios-xe', 'nxos', 'asa', 'firepower', 'webex', 'meraki', 'catalyst',
      'anyconnect', 'vpn', 'snmp', 'ssh', 'bgp', 'ospf', 'ldap',
      'radius', 'tacacs', 'rest', 'api', 'netconf', 'yang',
    ],
    scope: {
      inScope: ['IOS-XE', 'NX-OS', 'ASA', 'Firepower', 'Webex', 'Meraki', 'Catalyst'],
      outOfScope: ['social-engineering', 'ddos', 'eol-products'],
    },
    cweHighValue: [
      'CWE-78', 'CWE-287', 'CWE-269', 'CWE-22', 'CWE-120',
      'CWE-416', 'CWE-787', 'CWE-89', 'CWE-918', 'CWE-306',
    ],
    maxBounty: 25000,
    rewardsModel: 'custom',
    safeHarbor: true,
    active: true,
    notes: 'Emergency zero-day patched today. Massive deployed base. $500-$25K+.',
    addedAt: '2026-03-14T00:00:00Z',
  },

  // ─── Tier 3 — Coverage ────────────────────────────────────

  {
    id: 'gitlab',
    name: 'GitLab',
    platform: 'hackerone',
    url: 'https://hackerone.com/gitlab',
    submitTo: 'https://hackerone.com/gitlab',
    techStack: [
      'ruby', 'rails', 'go', 'vue', 'graphql', 'rest', 'api', 'git',
      'docker', 'kubernetes', 'nginx', 'postgresql', 'redis', 'sidekiq',
      'elasticsearch', 'prometheus', 'oauth', 'saml', 'ci', 'cd', 'runner',
    ],
    scope: {
      inScope: ['gitlab.com', 'GitLab CE/EE', 'GitLab Runner', 'GitLab Pages', 'Container Registry'],
      outOfScope: ['self-xss', 'rate-limiting', 'social-engineering'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-862',
      'CWE-863', 'CWE-22', 'CWE-78', 'CWE-502', 'CWE-94',
    ],
    maxBounty: 35000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Open source, huge scope, pays well. CI/CD pipeline exploits = high value.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'shopify',
    name: 'Shopify',
    platform: 'hackerone',
    url: 'https://hackerone.com/shopify',
    submitTo: 'https://hackerone.com/shopify',
    techStack: [
      'ruby', 'rails', 'react', 'graphql', 'rest', 'api', 'liquid',
      'node', 'mysql', 'redis', 'nginx', 'docker', 'kubernetes',
      'oauth', 'jwt', 'webhook', 'payment', 'checkout', 'storefront',
    ],
    scope: {
      inScope: ['*.shopify.com', '*.myshopify.com', 'Shopify API', 'Shopify Payments', 'Shop app'],
      outOfScope: ['self-xss', 'rate-limiting', 'social-engineering', 'clickjacking'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-287', 'CWE-862',
      'CWE-863', 'CWE-352', 'CWE-502', 'CWE-94', 'CWE-601',
    ],
    maxBounty: 50000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Consistent payouts, broad web scope. Payment/checkout vulns = highest tier.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'wordpress',
    name: 'WordPress (Automattic)',
    platform: 'hackerone',
    url: 'https://hackerone.com/automattic',
    submitTo: 'https://hackerone.com/automattic',
    techStack: [
      'php', 'wordpress', 'mysql', 'nginx', 'apache', 'rest', 'api',
      'plugin', 'theme', 'woocommerce', 'jetpack', 'wpcom', 'calypso',
      'react', 'node', 'elasticsearch', 'memcached', 'varnish',
    ],
    scope: {
      inScope: ['WordPress.com', 'WooCommerce', 'Jetpack', 'Tumblr', 'WordPress core'],
      outOfScope: ['self-xss', 'rate-limiting', 'wordpress.org plugins (third-party)'],
    },
    cweHighValue: [
      'CWE-79', 'CWE-89', 'CWE-918', 'CWE-22', 'CWE-434',
      'CWE-502', 'CWE-94', 'CWE-287', 'CWE-862', 'CWE-78',
    ],
    maxBounty: 25000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'WP Backup Migration RCE already in Exploit-DB feed. Massive attack surface via plugins.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'docker',
    name: 'Docker',
    platform: 'hackerone',
    url: 'https://hackerone.com/docker',
    submitTo: 'https://hackerone.com/docker',
    techStack: [
      'docker', 'container', 'containerd', 'runc', 'buildkit', 'compose',
      'swarm', 'registry', 'oci', 'linux', 'cgroup', 'namespace',
      'apparmor', 'seccomp', 'overlay', 'go', 'api', 'rest',
    ],
    scope: {
      inScope: ['Docker Engine', 'Docker Desktop', 'Docker Hub', 'containerd', 'BuildKit'],
      outOfScope: ['social-engineering', 'ddos', 'third-party-images'],
    },
    cweHighValue: [
      'CWE-269', // Container escape / privilege escalation
      'CWE-284', // Access control bypass
      'CWE-22',  // Path traversal (escape)
      'CWE-78', 'CWE-94', 'CWE-416', 'CWE-787', 'CWE-862',
    ],
    maxBounty: 20000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'CrackArmor AppArmor container escape = direct match. Container escape = top payout.',
    addedAt: '2026-03-14T00:00:00Z',
  },
  {
    id: 'redis',
    name: 'Redis',
    platform: 'hackerone',
    url: 'https://hackerone.com/redis',
    submitTo: 'https://hackerone.com/redis',
    techStack: [
      'redis', 'c', 'lua', 'module', 'cluster', 'sentinel', 'stream',
      'pubsub', 'acl', 'tls', 'ssl', 'replication', 'rdb', 'aof',
      'linux', 'tcp', 'api',
    ],
    scope: {
      inScope: ['Redis OSS', 'Redis Stack', 'Redis Modules', 'Redis Sentinel', 'Redis Cluster'],
      outOfScope: ['social-engineering', 'ddos', 'redis-cloud-only'],
    },
    cweHighValue: [
      'CWE-787', // OOB Write
      'CWE-125', // OOB Read
      'CWE-416', // Use After Free
      'CWE-78', 'CWE-94', 'CWE-287', 'CWE-120', 'CWE-190',
    ],
    maxBounty: 10000,
    rewardsModel: 'fixed-tier',
    safeHarbor: true,
    active: true,
    notes: 'Redis 8.0.2 RCE already in Exploit-DB feed. Memory corruption / Lua sandbox escape = high value.',
    addedAt: '2026-03-14T00:00:00Z',
  },
];

// ─── Initialize ───────────────────────────────────────────

export function loadPrograms() {
  if (bountyStore.programs.length === 0) {
    bountyStore.programs = [...BUILT_IN_PROGRAMS];
    console.log(`[BOUNTY] Loaded ${bountyStore.programs.length} built-in programs`);
  }
  return bountyStore.programs;
}

// ─── Program CRUD ─────────────────────────────────────────

export function getPrograms(activeOnly = false) {
  if (activeOnly) return bountyStore.programs.filter(p => p.active);
  return bountyStore.programs;
}

export function getProgram(id) {
  return bountyStore.programs.find(p => p.id === id) || null;
}

export function addProgram(program) {
  // Validate required fields
  const required = ['id', 'name', 'platform', 'techStack'];
  for (const field of required) {
    if (!program[field]) throw new Error(`Missing required field: ${field}`);
  }

  // Prevent duplicate IDs
  if (bountyStore.programs.find(p => p.id === program.id)) {
    throw new Error(`Program '${program.id}' already exists`);
  }

  const entry = {
    scope: { inScope: [], outOfScope: [] },
    cweHighValue: [],
    maxBounty: null,
    rewardsModel: 'unknown',
    safeHarbor: false,
    active: true,
    notes: '',
    addedAt: new Date().toISOString(),
    ...program,
  };

  bountyStore.programs.push(entry);
  console.log(`[BOUNTY] Added program: ${entry.name} (${entry.id})`);
  return entry;
}

export function upsertProgram(program) {
  const existing = bountyStore.programs.find(p => p.id === program.id);
  if (existing) {
    const { id, ...updates } = program;
    return updateProgram(id, updates);
  }
  return addProgram(program);
}

export function updateProgram(id, updates) {
  const program = bountyStore.programs.find(p => p.id === id);
  if (!program) throw new Error(`Program '${id}' not found`);

  // Don't allow changing the ID
  delete updates.id;
  Object.assign(program, updates);
  return program;
}

export function removeProgram(id) {
  const program = bountyStore.programs.find(p => p.id === id);
  if (!program) throw new Error(`Program '${id}' not found`);

  program.active = false;
  console.log(`[BOUNTY] Deactivated program: ${program.name}`);
  return program;
}

// ─── Matching Engine ──────────────────────────────────────

/**
 * Match bounty-relevant CVEs against all active programs.
 * One CVE can match multiple programs — multiple payouts.
 */
export function matchCVEsToPrograms() {
  const programs = getPrograms(true);
  if (programs.length === 0) return { newMatches: [], totalMatches: 0 };

  const cves = getBountyRelevantCVEs();
  const pocs = getNewPOCs();
  const wild = getExploitedInWild();

  // Build lookup sets for fast PoC/wild checks
  const pocCVEs = new Set(pocs.map(p => p.cveId).filter(Boolean));
  const wildCVEs = new Set(wild.map(w => w.cveId).filter(Boolean));

  // Existing match keys for dedup
  const existingKeys = new Set(bountyStore.matches.map(m => `${m.cveId}:${m.programId}`));

  const newMatches = [];

  for (const cve of cves) {
    for (const program of programs) {
      const key = `${cve.id}:${program.id}`;

      // Skip already-matched pairs
      if (existingKeys.has(key)) continue;

      // Skip if already submitted
      const alreadySubmitted = bountyStore.submissions.find(
        s => s.cveId === cve.id && s.programId === program.id
      );
      if (alreadySubmitted) continue;

      // Score the match
      const score = scoreCVEForProgram(cve, program, { pocCVEs, wildCVEs });

      // Only keep matches with meaningful relevance
      if (score.total >= 30) {
        const match = {
          id: `m_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          cveId: cve.id,
          programId: program.id,
          programName: program.name,
          score: score.total,
          breakdown: score,
          cve: {
            cvss: cve.cvss,
            severity: cve.severity,
            description: cve.description?.slice(0, 300),
            weaknesses: cve.weaknesses,
            exploitAvailable: cve.exploitAvailable,
            cisaKEV: cve.cisaKEV,
          },
          techOverlap: score.matchedKeywords,
          cweMatch: score.matchedCWEs,
          createdAt: new Date().toISOString(),
          analyzed: false,
        };

        newMatches.push(match);
        bountyStore.matches.push(match);
        existingKeys.add(key);
      }
    }
  }

  // Sort all matches by score (highest first)
  bountyStore.matches.sort((a, b) => b.score - a.score);

  // Prune old low-scoring matches (keep top 200)
  if (bountyStore.matches.length > 200) {
    bountyStore.matches = bountyStore.matches.slice(0, 200);
  }

  bountyStore.lastMatchRun = new Date().toISOString();

  // Sort new matches too for alerting
  newMatches.sort((a, b) => b.score - a.score);

  console.log(`[BOUNTY] Matching complete: ${newMatches.length} new matches, ${bountyStore.matches.length} total`);
  if (newMatches.length > 0) saveBountyStore();
  return { newMatches, totalMatches: bountyStore.matches.length };
}

// ─── Priority Scoring (0-100) ─────────────────────────────

/**
 * Score a CVE's relevance to a specific bounty program.
 *
 * | Factor            | Weight | Logic                                                |
 * |-------------------|--------|------------------------------------------------------|
 * | Tech stack match  | 30     | Count of matching keywords in description/CPE        |
 * | CWE relevance     | 20     | Is CWE in program's high-value list?                 |
 * | CVSS score        | 15     | Normalized: cvss / 10 * 15                           |
 * | Exploit available | 15     | Has PoC or in CISA KEV? +15                          |
 * | Freshness         | 10     | < 24h = 10, < 72h = 7, < 7d = 4, else 0             |
 * | Competition       | 10     | Independent = 10, HackerOne/Bugcrowd = 5             |
 */
function scoreCVEForProgram(cve, program, { pocCVEs, wildCVEs }) {
  const desc = (cve.description || '').toLowerCase();
  const products = (cve.affectedProducts || []).join(' ').toLowerCase();
  const searchText = `${desc} ${products}`;

  // ── Tech Stack Match (0-30) ──
  const matchedKeywords = [];
  for (const keyword of program.techStack) {
    if (searchText.includes(keyword.toLowerCase())) {
      matchedKeywords.push(keyword);
    }
  }
  // Scale: 1 match = 10, 2 = 18, 3+ = 24-30
  const techScore = Math.min(30, matchedKeywords.length * 8 + (matchedKeywords.length > 0 ? 2 : 0));

  // ── CWE Relevance (0-20) ──
  const cweList = cve.weaknesses || [];
  const matchedCWEs = cweList.filter(cwe => program.cweHighValue.includes(cwe));
  const cweScore = matchedCWEs.length > 0 ? 20 : 0;

  // ── CVSS Score (0-15) ──
  const cvssScore = cve.cvss ? Math.round((cve.cvss / 10) * 15) : 5;

  // ── Exploit Available (0-15) ──
  let exploitScore = 0;
  if (cve.exploitAvailable || pocCVEs.has(cve.id)) exploitScore = 15;
  else if (cve.cisaKEV || wildCVEs.has(cve.id)) exploitScore = 15;

  // ── Freshness (0-10) — first to report wins ──
  let freshnessScore = 0;
  const publishedTime = new Date(cve.published || 0).getTime();
  const ageMs = Date.now() - publishedTime;
  const ageHours = ageMs / (1000 * 60 * 60);
  if (ageHours < 24) freshnessScore = 10;
  else if (ageHours < 72) freshnessScore = 7;
  else if (ageHours < 168) freshnessScore = 4;

  // ── Competition Level (0-10) ──
  let competitionScore = 0;
  if (program.platform === 'independent') competitionScore = 10;
  else if (['hackerone', 'bugcrowd', 'intigriti'].includes(program.platform)) competitionScore = 5;
  else competitionScore = 7; // unknown platform = moderate competition

  // ── Out-of-scope filter ──
  const outOfScope = (program.scope?.outOfScope || []).map(s => s.toLowerCase());
  const isOutOfScope = outOfScope.some(item => desc.includes(item));
  if (isOutOfScope) {
    return {
      total: 0, techStack: 0, cwe: 0, cvss: 0,
      exploit: 0, freshness: 0, competition: 0,
      matchedKeywords: [], matchedCWEs: [],
      outOfScope: true,
    };
  }

  const total = techScore + cweScore + cvssScore + exploitScore + freshnessScore + competitionScore;

  return {
    total: Math.min(100, total),
    techStack: techScore,
    cwe: cweScore,
    cvss: cvssScore,
    exploit: exploitScore,
    freshness: freshnessScore,
    competition: competitionScore,
    matchedKeywords,
    matchedCWEs,
    outOfScope: false,
  };
}

// ─── Query Matches ────────────────────────────────────────

export function getTopMatches(limit = 20) {
  return bountyStore.matches.slice(0, limit);
}

export function getMatchesForProgram(programId, limit = 20) {
  return bountyStore.matches
    .filter(m => m.programId === programId)
    .slice(0, limit);
}

export function getMatchById(matchId) {
  return bountyStore.matches.find(m => m.id === matchId) || null;
}

// ─── Submission Tracker ───────────────────────────────────

/**
 * Track a submission to a bounty program.
 * Status flow: draft -> submitted -> acknowledged -> accepted -> paid | rejected
 */
export function addSubmission(programId, cveId, details = {}) {
  // Check for duplicate submission
  const existing = bountyStore.submissions.find(
    s => s.programId === programId && s.cveId === cveId
  );
  if (existing) {
    throw new Error(`Already submitted ${cveId} to ${programId} (status: ${existing.status})`);
  }

  const program = getProgram(programId);
  if (!program) throw new Error(`Program '${programId}' not found`);

  const submission = {
    id: `s_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    programId,
    programName: program.name,
    cveId,
    status: details.status || 'submitted',
    submittedAt: new Date().toISOString(),
    amount: details.amount || null,
    notes: details.notes || '',
    reportUrl: details.reportUrl || null,
    updatedAt: new Date().toISOString(),
  };

  bountyStore.submissions.push(submission);
  saveBountyStore();
  console.log(`[BOUNTY] Tracked submission: ${cveId} -> ${program.name} (${submission.status})`);
  return submission;
}

export function updateSubmission(id, updates) {
  const sub = bountyStore.submissions.find(s => s.id === id);
  if (!sub) throw new Error(`Submission '${id}' not found`);

  const allowed = ['status', 'amount', 'notes', 'reportUrl'];
  for (const key of allowed) {
    if (updates[key] !== undefined) sub[key] = updates[key];
  }
  sub.updatedAt = new Date().toISOString();
  saveBountyStore();
  return sub;
}

export function getSubmissions(filters = {}) {
  let results = bountyStore.submissions;
  if (filters.programId) results = results.filter(s => s.programId === filters.programId);
  if (filters.status) results = results.filter(s => s.status === filters.status);
  if (filters.cveId) results = results.filter(s => s.cveId === filters.cveId);
  return results;
}

// ─── Payout Analytics ─────────────────────────────────────

export function getPayoutStats() {
  const subs = bountyStore.submissions;

  const paid = subs.filter(s => s.status === 'paid');
  const pending = subs.filter(s => ['submitted', 'acknowledged', 'accepted'].includes(s.status));
  const rejected = subs.filter(s => s.status === 'rejected');

  const totalEarned = paid.reduce((sum, s) => sum + (s.amount || 0), 0);
  const totalPending = pending.reduce((sum, s) => sum + (s.amount || 0), 0);

  // Win rate
  const resolved = paid.length + rejected.length;
  const winRate = resolved > 0 ? Math.round((paid.length / resolved) * 100) : 0;

  // By program
  const byProgram = {};
  for (const sub of subs) {
    if (!byProgram[sub.programId]) {
      byProgram[sub.programId] = { name: sub.programName, submitted: 0, paid: 0, rejected: 0, earned: 0 };
    }
    byProgram[sub.programId].submitted++;
    if (sub.status === 'paid') {
      byProgram[sub.programId].paid++;
      byProgram[sub.programId].earned += sub.amount || 0;
    }
    if (sub.status === 'rejected') byProgram[sub.programId].rejected++;
  }

  // By CWE category (skill breakdown)
  const byCWE = {};
  for (const sub of subs) {
    const match = bountyStore.matches.find(m => m.cveId === sub.cveId && m.programId === sub.programId);
    const cwes = match?.cwe?.matchedCWEs || match?.cweMatch || ['Unknown'];
    for (const cwe of cwes) {
      if (!byCWE[cwe]) byCWE[cwe] = { count: 0, paid: 0 };
      byCWE[cwe].count++;
      if (sub.status === 'paid') byCWE[cwe].paid++;
    }
  }

  return {
    totalSubmissions: subs.length,
    totalEarned,
    totalPending,
    pendingCount: pending.length,
    rejectedCount: rejected.length,
    paidCount: paid.length,
    winRate,
    byProgram,
    byCWE,
    programs: bountyStore.programs.length,
    activePrograms: bountyStore.programs.filter(p => p.active).length,
    totalMatches: bountyStore.matches.length,
    lastMatchRun: bountyStore.lastMatchRun,
  };
}

// ─── Opus Analysis for High-Score Matches ─────────────────

/**
 * Analyze a high-scoring match with Opus 4.6.
 * Only called for matches scoring >= 70 to control API costs.
 */
export async function analyzeMatch(match) {
  // Dynamic import to avoid circular dependency
  const { default: _ } = await import('./exploit-analysis.js');

  const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  const program = getProgram(match.programId);
  if (!program) return null;

  const prompt = `You are a bug bounty strategist. Analyze this CVE match for the ${program.name} bounty program.

CVE: ${match.cveId}
CVSS: ${match.cve?.cvss || 'N/A'}
Description: ${match.cve?.description || 'N/A'}
Weaknesses: ${match.cve?.weaknesses?.join(', ') || 'N/A'}

Program: ${program.name}
Platform: ${program.platform}
Tech Stack: ${program.techStack.join(', ')}
In-Scope: ${program.scope?.inScope?.join(', ') || 'N/A'}
High-Value CWEs: ${program.cweHighValue.join(', ')}
Rewards: ${program.rewardsModel}
Max Bounty: ${program.maxBounty || 'Undisclosed'}

Match Score: ${match.score}/100
Tech Overlap: ${match.techOverlap?.join(', ') || 'None'}
CWE Match: ${match.cweMatch?.join(', ') || 'None'}

Respond in JSON:
{
  "attackStrategy": "specific steps to test for this vuln against ${program.name}",
  "estimatedBounty": "$X-$Y range",
  "duplicateRisk": "low|medium|high — have others likely found this?",
  "reportOutline": ["section 1", "section 2", "section 3"],
  "timeToTest": "estimated time to verify exploitability",
  "chainPotential": "can this be chained with other vulns for higher payout",
  "verdict": "submit|skip|investigate_further"
}`;

  try {
    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1024,
        system: 'You are an expert bug bounty hunter and security researcher. You analyze vulnerabilities for authorized bounty programs. Be direct, actionable, and strategic.',
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!res.ok) {
      console.error(`[BOUNTY] Opus analysis failed: ${res.status}`);
      return null;
    }

    const result = await res.json();
    const text = result.content?.[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const analysis = JSON.parse(jsonMatch[0]);

    // Update the match with analysis
    match.analyzed = true;
    match.analysis = analysis;
    match.analyzedAt = new Date().toISOString();

    return analysis;
  } catch (err) {
    console.error(`[BOUNTY] Opus analysis error: ${err.message}`);
    return null;
  }
}

// ─── Store Access ─────────────────────────────────────────

export function getBountyStore() {
  return bountyStore;
}
