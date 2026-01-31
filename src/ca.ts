import type { Database } from 'bun:sqlite';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
// @ts-expect-error no types
import * as forge from 'node-forge';
import {
  CONFIG_KEY_ACTIVE_CA_ID,
  DEFAULT_COMMON_NAME_INTERMEDIATE,
  DEFAULT_COMMON_NAME_ROOT,
  DEFAULT_HASH_ALGORITHM,
  DEFAULT_KEY_SIZE,
  DEFAULT_VALIDITY_YEARS,
} from './constants.js';
import { getDigestForSigning, buildSubjectAttributes } from './crypto.js';
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

export function createRootCa(
  database: Database,
  paths: PathHelpers,
  caId: string,
  options: CaOptions
): void {
  const keySize = options.keySize ?? DEFAULT_KEY_SIZE;
  const validityYears = options.validityYears ?? DEFAULT_VALIDITY_YEARS;
  const hashAlgorithm = options.hashAlgorithm ?? DEFAULT_HASH_ALGORITHM;

  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Date.now()).slice(-8);
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(
    certificate.validity.notAfter.getFullYear() + validityYears
  );

  const subjectOptions = {
    commonName: options.commonName || DEFAULT_COMMON_NAME_ROOT,
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
  const displayName = options.name || options.commonName || DEFAULT_COMMON_NAME_ROOT;
  database.prepare(
    'INSERT INTO cas (id, name, common_name, not_after, created_at) VALUES (?, ?, ?, ?, datetime("now"))'
  ).run(caId, displayName, options.commonName || DEFAULT_COMMON_NAME_ROOT, notAfter);

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

  const keySize = options.keySize ?? DEFAULT_KEY_SIZE;
  const validityYears = options.validityYears ?? DEFAULT_VALIDITY_YEARS;
  const hashAlgorithm = options.hashAlgorithm ?? DEFAULT_HASH_ALGORITHM;

  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Date.now()).slice(-8);
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(
    certificate.validity.notAfter.getFullYear() + validityYears
  );

  const subjectOptions = {
    commonName: options.commonName || DEFAULT_COMMON_NAME_INTERMEDIATE,
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
  const displayName = options.name || options.commonName || DEFAULT_COMMON_NAME_INTERMEDIATE;
  database.prepare(
    'INSERT INTO intermediate_cas (id, parent_ca_id, name, common_name, not_after, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))'
  ).run(
    intermediateId,
    parentCaId,
    displayName,
    options.commonName || DEFAULT_COMMON_NAME_INTERMEDIATE,
    notAfter
  );
}
