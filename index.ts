import { mkdirSync } from 'node:fs';
import { serve } from 'bun';
import { getDataDir, getDbPath, getHostname, getPort } from './src/config.js';
import { createPathHelpers } from './src/paths.js';
import { createDatabase, runMigrations } from './src/database.js';
import { createRequestHandler } from './src/server.js';
import { renderDashboard } from './src/dashboard.js';
import { startValidationPolling } from './src/acme.js';
import { initLogger, logger } from './src/logger.js';

const dataDir = getDataDir();
const dbPath = getDbPath();
const port = getPort();
const hostname = getHostname();

mkdirSync(dataDir, { recursive: true });

const database = createDatabase(dbPath);
const paths = createPathHelpers(dataDir);
runMigrations(database, dataDir, paths);
initLogger(database);

const handleRequest = createRequestHandler(database, paths, port, renderDashboard);
startValidationPolling(database);

if (import.meta.main) {
  serve({ port, hostname, fetch: handleRequest });
  const listenUrl = hostname === '0.0.0.0' ? `http://localhost:${port}` : `http://${hostname}:${port}`;
  logger.info('Server gestartet', { port, hostname, listenUrl });
  console.log('🚀 Server läuft auf ' + listenUrl);
}

export { handleRequest, database, paths };
