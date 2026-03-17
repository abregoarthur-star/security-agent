/**
 * Findings Store
 *
 * Tracks vulnerability findings from scans and intelligence feeds.
 * Persisted to Railway volume via store.js.
 */

import { readJSON, createDebouncedWriter } from './store.js';

let findings = readJSON('findings.json', []);
const scheduleSaveFindings = createDebouncedWriter('findings.json', 3000);

if (findings.length > 0) {
  console.log(`[FINDINGS] Loaded ${findings.length} findings from disk`);
}

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
  scheduleSaveFindings(findings);
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
  scheduleSaveFindings(findings);
  return finding;
}

/**
 * Load findings.
 */
export function loadFindings() {
  return findings;
}
