/**
 * Version information for wyscan CLI
 *
 * Single source of truth: reads from package.json at runtime
 */
import * as fs from 'fs';
import * as path from 'path';

interface PackageJson {
  version: string;
  name: string;
  author: string | { name: string };
}

function loadPackageJson(): PackageJson {
  // Handle both source (src/) and dist (dist/) paths
  const candidates = [
    path.join(__dirname, '../../package.json'),      // from dist/cli/
    path.join(__dirname, '../../../package.json'),   // deeper nesting
    path.join(process.cwd(), 'package.json'),        // fallback to cwd
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        return JSON.parse(fs.readFileSync(candidate, 'utf-8'));
      } catch {
        continue;
      }
    }
  }

  // Fallback if package.json not found
  return { version: 'unknown', name: 'wyscan', author: 'Plarix' };
}

const pkg = loadPackageJson();

export const VERSION = pkg.version;
export const NAME = pkg.name;
export const AUTHOR = typeof pkg.author === 'string' ? pkg.author : pkg.author?.name || 'Plarix';
export const REPO = 'github.com/plarix-security/wyscan';
