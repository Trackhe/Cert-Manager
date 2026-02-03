import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
// @ts-expect-error no types
import * as forge from 'node-forge';
import { getDigestForSigning, buildSubjectAttributes } from './crypto.js';
import {
  CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID,
  CONFIG_KEY_ACTIVE_CA_ID,
  CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE,
  CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT,
  CONFIG_KEY_DEFAULT_HASH_ALGORITHM,
  CONFIG_KEY_DEFAULT_KEY_SIZE,
  CONFIG_KEY_DEFAULT_VALIDITY_YEARS,
  getConfigInt,
  getConfigValue,
} from './database.js';
import type { PathHelpers } from './paths.js';

export interface CaOptions {
  name: string;
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  locality?: string;
  stateOrProvince?: string;
  email?: string;
  validityYears?: number;
  keySize?: number;
  hashAlgorithm?: string;
}

export function getActiveCaId(database: Database): string | null {
  const row = database
    .prepare(`SELECT value FROM config WHERE key = ?`)
    .get(CONFIG_KEY_ACTIVE_CA_ID) as { value: string } | undefined;
  return row?.value ?? null;
}

/** Standard-Intermediate für ACME (wenn gesetzt); sonst null. */
export function getActiveAcmeIntermediateId(database: Database): string | null {
  const row = database
    .prepare(`SELECT value FROM config WHERE key = ?`)
    .get(CONFIG_KEY_ACTIVE_ACME_INTERMEDIATE_ID) as { value: string } | undefined;
  return row?.value ?? null;
}

export function getCa(
  database: Database,
  paths: PathHelpers
): { key: forge.pki.PrivateKey; cert: forge.pki.Certificate } | null {
  const activeCaId = getActiveCaId(database);
  if (!activeCaId) return null;
  const keyPath = paths.caKeyPath(activeCaId);
  const certPath = paths.caCertPath(activeCaId);
  if (!existsSync(keyPath) || !existsSync(certPath)) return null;
  return {
    key: forge.pki.privateKeyFromPem(readFileSync(keyPath, 'utf8')),
    cert: forge.pki.certificateFromPem(readFileSync(certPath, 'utf8')),
  };
}

export function getSignerCa(
  database: Database,
  paths: PathHelpers,
  issuerId: string
): { key: forge.pki.PrivateKey; cert: forge.pki.Certificate } {
  const isIntermediate = database
    .prepare('SELECT 1 FROM intermediate_cas WHERE id = ?')
    .get(issuerId);
  const keyPath = isIntermediate
    ? paths.intermediateKeyPath(issuerId)
    : paths.caKeyPath(issuerId);
  const certPath = isIntermediate
    ? paths.intermediateCertPath(issuerId)
    : paths.caCertPath(issuerId);
  if (!existsSync(keyPath) || !existsSync(certPath)) {
    throw new Error('Ausstellende CA nicht gefunden');
  }
  return {
    key: forge.pki.privateKeyFromPem(readFileSync(keyPath, 'utf8')),
    cert: forge.pki.certificateFromPem(readFileSync(certPath, 'utf8')),
  };
}

/**
 * Ermittelt die CA-ID (Root oder Intermediate) für eine ACME-Domain.
 * Exact-Match hat Vorrang; danach längster passender Wildcard (*.domain.tld).
 * @returns ca_id oder null (dann Standard-CA nutzen)
 */
export function getCaIdForAcmeDomain(database: Database, domain: string): string | null {
  const normalized = domain.toLowerCase().trim();
  const exact = database
    .prepare('SELECT ca_id FROM acme_ca_domain_assignments WHERE domain_pattern = ?')
    .get(normalized) as { ca_id: string } | undefined;
  if (exact) return exact.ca_id;

  const all = database
    .prepare('SELECT domain_pattern, ca_id FROM acme_ca_domain_assignments')
    .all() as Array<{ domain_pattern: string; ca_id: string }>;
  let best: { ca_id: string; suffixLen: number } | null = null;
  for (const row of all) {
    const p = row.domain_pattern;
    if (!p.startsWith('*.')) continue;
    const suffix = p.slice(2).toLowerCase();
    if (normalized === suffix || normalized.endsWith('.' + suffix)) {
      const suffixLen = suffix.length;
      if (!best || suffixLen > best.suffixLen) best = { ca_id: row.ca_id, suffixLen };
    }
  }
  return best ? best.ca_id : null;
}

export function createRootCa(
  database: Database,
  paths: PathHelpers,
  caId: string,
  options: CaOptions
): void {
  const keySize = options.keySize ?? getConfigInt(database, CONFIG_KEY_DEFAULT_KEY_SIZE);
  const validityYears = options.validityYears ?? getConfigInt(database, CONFIG_KEY_DEFAULT_VALIDITY_YEARS);
  const hashAlgorithm = options.hashAlgorithm ?? getConfigValue(database, CONFIG_KEY_DEFAULT_HASH_ALGORITHM) ?? 'sha256';

  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Date.now()).slice(-8);
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(
    certificate.validity.notAfter.getFullYear() + validityYears
  );

  const defaultCnRoot = getConfigValue(database, CONFIG_KEY_DEFAULT_COMMON_NAME_ROOT) ?? 'Meine CA';
  const subjectOptions = {
    commonName: options.commonName || defaultCnRoot,
    organization: options.organization,
    organizationalUnit: options.organizationalUnit,
    country: options.country,
    locality: options.locality,
    stateOrProvince: options.stateOrProvince,
    email: options.email,
  };
  const subjectAttributes = buildSubjectAttributes(subjectOptions);
  certificate.setSubject(subjectAttributes);
  certificate.setIssuer(subjectAttributes);

  const messageDigest = getDigestForSigning(hashAlgorithm);
  certificate.sign(keys.privateKey, messageDigest);

  writeFileSync(paths.caKeyPath(caId), forge.pki.privateKeyToPem(keys.privateKey));
  writeFileSync(paths.caCertPath(caId), forge.pki.certificateToPem(certificate));

  const notAfter = certificate.validity.notAfter.toISOString();
  const displayName = options.name || options.commonName || defaultCnRoot;
  database.prepare(
    'INSERT INTO cas (id, name, common_name, not_after, created_at) VALUES (?, ?, ?, ?, datetime("now"))'
  ).run(caId, displayName, options.commonName || defaultCnRoot, notAfter);

  if (!getActiveCaId(database)) {
    database
      .prepare(`INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)`)
      .run(CONFIG_KEY_ACTIVE_CA_ID, caId);
  }
}

export function createIntermediateCa(
  database: Database,
  paths: PathHelpers,
  parentCaId: string,
  intermediateId: string,
  options: CaOptions
): void {
  const parentKeyPath = paths.caKeyPath(parentCaId);
  const parentCertPath = paths.caCertPath(parentCaId);
  if (!existsSync(parentKeyPath) || !existsSync(parentCertPath)) {
    throw new Error('Parent-CA nicht gefunden');
  }

  const parentKey = forge.pki.privateKeyFromPem(readFileSync(parentKeyPath, 'utf8'));
  const parentCertificate = forge.pki.certificateFromPem(readFileSync(parentCertPath, 'utf8'));

  const keySize = options.keySize ?? getConfigInt(database, CONFIG_KEY_DEFAULT_KEY_SIZE);
  const validityYears = options.validityYears ?? getConfigInt(database, CONFIG_KEY_DEFAULT_VALIDITY_YEARS);
  const hashAlgorithm = options.hashAlgorithm ?? getConfigValue(database, CONFIG_KEY_DEFAULT_HASH_ALGORITHM) ?? 'sha256';

  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Date.now()).slice(-8);
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(
    certificate.validity.notAfter.getFullYear() + validityYears
  );

  const defaultCnInt = getConfigValue(database, CONFIG_KEY_DEFAULT_COMMON_NAME_INTERMEDIATE) ?? 'Intermediate CA';
  const subjectOptions = {
    commonName: options.commonName || defaultCnInt,
    organization: options.organization,
    organizationalUnit: options.organizationalUnit,
    country: options.country,
    locality: options.locality,
    stateOrProvince: options.stateOrProvince,
    email: options.email,
  };
  const subjectAttributes = buildSubjectAttributes(subjectOptions);
  certificate.setSubject(subjectAttributes);
  certificate.setIssuer(parentCertificate.subject.attributes);
  certificate.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
  ]);

  const messageDigest = getDigestForSigning(hashAlgorithm);
  certificate.sign(parentKey, messageDigest);

  writeFileSync(
    paths.intermediateKeyPath(intermediateId),
    forge.pki.privateKeyToPem(keys.privateKey)
  );
  writeFileSync(
    paths.intermediateCertPath(intermediateId),
    forge.pki.certificateToPem(certificate)
  );

  const notAfter = certificate.validity.notAfter.toISOString();
  const displayName = options.name || options.commonName || defaultCnInt;
  database.prepare(
    'INSERT INTO intermediate_cas (id, parent_ca_id, name, common_name, not_after, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))'
  ).run(intermediateId, parentCaId, displayName, options.commonName || defaultCnInt, notAfter);
}
