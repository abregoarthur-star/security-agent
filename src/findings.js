/**
 * Findings Store
 *
 * Tracks vulnerability findings from scans and intelligence feeds.
 * In-memory for now, will persist to Railway volume later.
 */

let findings = [];

/**
 * Add a finding.
 */
export function addFinding(finding) {
  const id = `f_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const entry = {
    id,
    ...finding,
    status: 'new',
    createdAt: new Date().toISOString(),
  };
  findings.push(entry);
  return entry;
}

/**
 * Get all findings, optionally filtered.
 */
export function getFindings(filter = {}) {
  let result = [...findings];

  if (filter.status) {
    result = result.filter(f => f.status === filter.status);
  }
  if (filter.severity) {
    result = result.filter(f => f.severity === filter.severity);
  }

  return result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

/**
 * Update finding status.
 */
export function updateFinding(id, updates) {
  const finding = findings.find(f => f.id === id);
  if (!finding) return null;
  Object.assign(finding, updates, { updatedAt: new Date().toISOString() });
  return finding;
}

/**
 * Load findings (placeholder for disk persistence).
 */
export function loadFindings() {
  return findings;
}
