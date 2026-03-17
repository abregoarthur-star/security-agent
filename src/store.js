/**
 * Persistent JSON Store — Railway Volume
 *
 * Same pattern as the Brain's store.js:
 * - DATA_DIR env var points to Railway volume (/data in production)
 * - Falls back to ./data locally
 * - Read/write JSON with graceful fallback on missing files
 * - In-memory cache with write-through to disk
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const DATA_DIR = process.env.DATA_DIR || './data';

// Ensure data directory exists
if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

/**
 * Read a JSON file from the data directory.
 * Returns defaultValue if file doesn't exist or is corrupt.
 */
export function readJSON(filename, defaultValue = null) {
  const filepath = join(DATA_DIR, filename);
  try {
    const raw = readFileSync(filepath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return defaultValue;
  }
}

/**
 * Write a JSON file to the data directory.
 * Atomic-ish: writes synchronously to minimize partial write risk.
 */
export function writeJSON(filename, data) {
  const filepath = join(DATA_DIR, filename);
  try {
    writeFileSync(filepath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error(`[STORE] Failed to write ${filename}:`, err.message);
  }
}

/**
 * Debounced writer — batches rapid writes into one disk write.
 * Returns a function that schedules a write after `delay` ms of inactivity.
 */
export function createDebouncedWriter(filename, delay = 5000) {
  let timer = null;
  return function scheduleWrite(data) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      writeJSON(filename, data);
      timer = null;
    }, delay);
  };
}

console.log(`[STORE] Data directory: ${DATA_DIR}`);
