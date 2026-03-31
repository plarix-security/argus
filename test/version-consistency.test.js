const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const packageJson = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8')
);

describe('version consistency', () => {
  test('CLI version command matches package.json', () => {
    const cliPath = path.join(repoRoot, 'dist', 'cli', 'index.js');
    const output = execFileSync('node', [cliPath, 'version'], {
      cwd: repoRoot,
      encoding: 'utf8',
    }).trim();

    expect(output).toBe(`${packageJson.name} ${packageJson.version}`);
  });

  test('server banner does not hardcode a semver literal', () => {
    const appSource = fs.readFileSync(path.join(repoRoot, 'src', 'app.ts'), 'utf8');

    expect(appSource).toContain("import { NAME, VERSION } from './cli/version';");
    expect(appSource).not.toMatch(/v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?/);
  });
});
