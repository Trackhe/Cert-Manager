import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { serve } from 'bun';
import { getDataDir, getDbPath, getHostname, getPort } from './src/config.js';
import { createPathHelpers } from './src/paths.js';
import { createDatabase, runMigrations } from './src/database.js';
import { createRequestHandler } from './src/server.js';
import { ensureServerHttpsCert } from './src/server-https-cert.js';
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
  (async () => {
    const httpsCertPath = paths.serverHttpsCertPath();
    const httpsKeyPath = paths.serverHttpsKeyPath();
    if (!existsSync(httpsCertPath) || !existsSync(httpsKeyPath)) {
      try {
        await ensureServerHttpsCert(database, paths);
      } catch (err) {
        logger.warn('HTTPS-Zertifikat konnte nicht automatisch erstellt werden', { error: String(err) });
      }
    }

    serve({ port, hostname, fetch: handleRequest });
    const listenUrl = hostname === '0.0.0.0' ? `http://localhost:${port}` : `http://${hostname}:${port}`;
    logger.info('Server gestartet', { port, hostname, listenUrl });
    console.log('🚀 Server läuft auf ' + listenUrl);

    if (existsSync(httpsCertPath) && existsSync(httpsKeyPath)) {
      const httpsPort = port + 1;
      try {
        serve({
          port: httpsPort,
          hostname,
          fetch: handleRequest,
          tls: {
            cert: readFileSync(httpsCertPath, 'utf8'),
            key: readFileSync(httpsKeyPath, 'utf8'),
          },
        });
        const httpsUrl = hostname === '0.0.0.0' ? `https://localhost:${httpsPort}` : `https://${hostname}:${httpsPort}`;
        logger.info('HTTPS-Server gestartet', { port: httpsPort, listenUrl: httpsUrl });
        console.log('🔒 HTTPS auf ' + httpsUrl + ' (ACME: ' + httpsUrl + '/acme/directory)');
      } catch (err) {
        logger.warn('HTTPS-Server konnte nicht gestartet werden', { error: String(err) });
        console.warn('⚠️ HTTPS nicht gestartet:', err instanceof Error ? err.message : err);
      }
    } else {
      console.log('💡 HTTPS: Keine aktive CA – unter „Eigene CA“ eine CA anlegen, dann Server neu starten (Port ' + (port + 1) + ')');
    }
  })();
}

export { handleRequest, database, paths };
