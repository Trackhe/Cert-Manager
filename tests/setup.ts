/**
 * Läuft vor allen Tests (bun test --preload ./tests/setup.ts).
 * Setzt DATA_DIR und DB_PATH auf ein temporäres Verzeichnis, damit
 * index.ts eine frische DB und ein leeres data-Verzeichnis verwendet.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const testDir = mkdtempSync(join(tmpdir(), 'cert-manager-test-'));
process.env.DATA_DIR = testDir;
process.env.DB_PATH = join(testDir, 'test.db');
