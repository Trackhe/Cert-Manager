import type { Database } from 'bun:sqlite';
import { writeFileSync } from 'node:fs';
// @ts-expect-error no types
import * as forge from 'node-forge';
import { getSignerCa } from './ca.js';
import {
  DEFAULT_HASH_ALGORITHM,
  DEFAULT_KEY_SIZE,
  DEFAULT_VALIDITY_DAYS,
} from './constants.js';
import { getDigestForSigning } from './crypto.js';
import type { PathHelpers } from './paths.js';

export interface LeafCertificateOptions {
  sanDomains?: string[];
  validityDays?: number;
  keySize?: number;
  hashAlgorithm?: string;
}

export function createLeafCertificate(
  database: Database,
  paths: PathHelpers,
  issuerId: string,
  domain: string,
  options: LeafCertificateOptions = {}
): number {
  const signer = getSignerCa(database, paths, issuerId);

  const keySize = options.keySize ?? DEFAULT_KEY_SIZE;
  const validityDays = options.validityDays ?? DEFAULT_VALIDITY_DAYS;
  const hashAlgorithm = options.hashAlgorithm ?? DEFAULT_HASH_ALGORITHM;

  const keys = forge.pki.rsa.generateKeyPair(keySize);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Date.now()).slice(-8);
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setDate(
    certificate.validity.notAfter.getDate() + validityDays
  );

  const allDomains = [domain, ...(options.sanDomains ?? [])].filter(Boolean);
  const uniqueDomains = [...new Set(allDomains.map((d) => d.trim().toLowerCase()))].filter(Boolean);
  const primaryDomain = uniqueDomains[0] ?? domain;

  certificate.setSubject([{ name: 'commonName', value: primaryDomain }]);
  certificate.setIssuer(signer.cert.subject.attributes);
  certificate.setExtensions([
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    {
      name: 'subjectAltName',
      altNames: uniqueDomains.map((domainName) => ({ type: 2, value: domainName })),
    },
  ]);

  const messageDigest = getDigestForSigning(hashAlgorithm);
  certificate.sign(signer.key, messageDigest);

  const notAfter = certificate.validity.notAfter.toISOString();
  const certificatePem = forge.pki.certificateToPem(certificate);

  database.prepare(
    'INSERT INTO certificates (domain, not_after, created_at, pem) VALUES (?, ?, datetime("now"), ?)'
  ).run(primaryDomain, notAfter, certificatePem);

  const lastRow = database.prepare('SELECT last_insert_rowid() as id').get() as { id: number };
  const certificateId = lastRow.id;
  writeFileSync(
    paths.leafKeyPath(certificateId),
    forge.pki.privateKeyToPem(keys.privateKey)
  );

  return certificateId;
}
