import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { Database } from 'bun:sqlite';
import { getActiveAcmeIntermediateId, getActiveCaId } from './ca.js';
import { createLeafCertificate } from './leaf-certificate.js';
import { logger } from './logger.js';
import type { PathHelpers } from './paths.js';

/**
 * Erstellt ein Leaf-Zertifikat für "localhost" und schreibt es (und den Schlüssel)
 * in die Server-HTTPS-Pfade, falls diese noch nicht existieren.
 * Nur wenn eine aktive CA existiert.
 * @returns true wenn die Dateien danach existieren, sonst false
 */
export async function ensureServerHttpsCert(
  database: Database,
  paths: PathHelpers
): Promise<boolean> {
  const certPath = paths.serverHttpsCertPath();
  const keyPath = paths.serverHttpsKeyPath();
  if (existsSync(certPath) && existsSync(keyPath)) {
    return true;
  }
  const activeCaId = getActiveCaId(database);
  if (!activeCaId) {
    return false;
  }
  const intermediateId = getActiveAcmeIntermediateId(database);
  const issuerId = intermediateId ?? activeCaId;
  const hostname = 'localhost';
  const certificateId = await createLeafCertificate(database, paths, issuerId, hostname, {
    sanDomains: [hostname],
    validityDays: 365,
  });
  const certRow = database.prepare('SELECT pem FROM certificates WHERE id = ?').get(certificateId) as { pem: string } | undefined;
  if (!certRow) {
    throw new Error('Zertifikat konnte nicht gelesen werden');
  }
  const leafKeyPath = paths.leafKeyPath(certificateId);
  if (!existsSync(leafKeyPath)) {
    throw new Error('Schlüsseldatei nicht gefunden');
  }
  const keyPem = readFileSync(leafKeyPath, 'utf8');
  writeFileSync(certPath, certRow.pem);
  writeFileSync(keyPath, keyPem);
  logger.info('HTTPS-Server-Zertifikat automatisch erstellt', { hostname });
  return true;
}
