import type { Database } from 'bun:sqlite';
import { writeFileSync } from 'node:fs';
// @ts-expect-error no types
import * as forge from 'node-forge';
import { getSignerCa } from './ca.js';
import { getDigestForSigning } from './crypto.js';
import {
  CONFIG_KEY_DEFAULT_HASH_ALGORITHM,
  CONFIG_KEY_DEFAULT_KEY_SIZE,
  CONFIG_KEY_DEFAULT_VALIDITY_DAYS,
  getConfigInt,
  getConfigValue,
} from './database.js';
import type { PathHelpers } from './paths.js';

export interface LeafCertificateOptions {
  sanDomains?: string[];
  validityDays?: number;
  keySize?: number;
  hashAlgorithm?: string;
  /** EV-Zertifikat mit PEN-OID und zusätzlichen Subject-Feldern */
  ev?: boolean;
  /** IANA Enterprise Number (PEN), z. B. 1.3.6.1.4.1.52357 */
  policyOidBase?: string;
  /** Sub-ID, z. B. .1.1 */
  policyOidSub?: string;
  /** EV: z. B. "Private Organization" */
  businessCategory?: string;
  /** EV: Jurisdiktion Land, z. B. "DE" */
  jurisdictionCountryName?: string;
  /** EV: Handelsregisternummer oder "N/A" */
  serialNumber?: string;
}

/** Baut die finale OID aus Basis (PEN) und Sub-ID. */
function buildPolicyOid(base: string, sub: string): string {
  const b = (base ?? '').trim();
  const s = (sub ?? '').trim();
  if (!b) return '';
  const subNorm = s.startsWith('.') ? s : s ? '.' + s : '';
  return (b + subNorm).replace(/\.+/g, '.').replace(/\.$/, '');
}

export function createLeafCertificate(
  database: Database,
  paths: PathHelpers,
  issuerId: string,
  domain: string,
  options: LeafCertificateOptions = {}
): number {
  const signer = getSignerCa(database, paths, issuerId);

  const keySize = options.keySize ?? getConfigInt(database, CONFIG_KEY_DEFAULT_KEY_SIZE);
  const validityDays = options.validityDays ?? getConfigInt(database, CONFIG_KEY_DEFAULT_VALIDITY_DAYS);
  const hashAlgorithm =
    options.hashAlgorithm ?? getConfigValue(database, CONFIG_KEY_DEFAULT_HASH_ALGORITHM) ?? 'sha256';

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

  const isEv = options.ev === true;
  const subjectAttrs: Array<{ name: string; value: string }> = [
    { name: 'commonName', value: primaryDomain },
  ];
  if (isEv) {
    if (options.businessCategory) subjectAttrs.push({ name: 'businessCategory', value: options.businessCategory });
    if (options.jurisdictionCountryName) subjectAttrs.push({ name: 'jurisdictionOfIncorporationCountryName', value: options.jurisdictionCountryName });
    if (options.serialNumber) subjectAttrs.push({ name: 'serialNumber', value: options.serialNumber });
  }
  certificate.setSubject(subjectAttrs);
  certificate.setIssuer(signer.cert.subject.attributes);

  const policyOid = buildPolicyOid(options.policyOidBase ?? '', options.policyOidSub ?? '');
  const extensions: forge.pki.CertificateExtension[] = [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
    {
      name: 'subjectAltName',
      altNames: uniqueDomains.map((domainName) => ({ type: 2, value: domainName })),
    },
  ];
  if (isEv && policyOid) {
    const asn1 = forge.asn1;
    const policyInfo = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(policyOid).getBytes()),
    ]);
    const certPoliciesValue = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [policyInfo]);
    extensions.push({
      id: '2.5.29.32',
      name: 'certificatePolicies',
      value: certPoliciesValue,
    });
  }
  certificate.setExtensions(extensions);

  const messageDigest = getDigestForSigning(hashAlgorithm);
  certificate.sign(signer.key, messageDigest);

  const notAfter = certificate.validity.notAfter.toISOString();
  const certificatePem = forge.pki.certificateToPem(certificate);

  database
    .prepare(
      'INSERT INTO certificates (domain, not_after, created_at, pem, issuer_id, is_ev, certificate_policy_oid) VALUES (?, ?, datetime("now"), ?, ?, ?, ?)'
    )
    .run(primaryDomain, notAfter, certificatePem, issuerId, isEv ? 1 : 0, policyOid || null);

  const lastRow = database.prepare('SELECT last_insert_rowid() as id').get() as { id: number };
  const certificateId = lastRow.id;
  writeFileSync(
    paths.leafKeyPath(certificateId),
    forge.pki.privateKeyToPem(keys.privateKey)
  );

  return certificateId;
}
