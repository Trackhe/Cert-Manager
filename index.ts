import { mkdirSync } from 'node:fs';
import { serve } from 'bun';
import { getDataDir, getDbPath, getPort } from './src/config.js';
import { createPathHelpers } from './src/paths.js';
import { createDatabase, runMigrations } from './src/database.js';
import { createRequestHandler } from './src/server.js';
import { renderDashboard } from './src/dashboard.js';

const dataDir = getDataDir();
const dbPath = getDbPath();
const port = getPort();

mkdirSync(dataDir, { recursive: true });

const database = createDatabase(dbPath);
const paths = createPathHelpers(dataDir);
runMigrations(database, dataDir, paths);

const handleRequest = createRequestHandler(database, paths, port, renderDashboard);

if (import.meta.main) {
  serve({ port, fetch: handleRequest });
  console.log('🚀 Server läuft auf http://localhost:' + port);
}

export { handleRequest, database, paths };
