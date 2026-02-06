import type { Database } from 'bun:sqlite';
import { writeFileSync } from 'node:fs';
// @ts-expect-error no types
import * as forge from 'node-forge';
import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';
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

/** Erlaubte Schlüsselarten für Leaf-Zertifikate (RSA oder ECDSA). */
export type KeyAlgorithm = 'rsa-2048' | 'rsa-3072' | 'rsa-4096' | 'ec-p256' | 'ec-p384';

const EC_ALGORITHMS: KeyAlgorithm[] = ['ec-p256', 'ec-p384'];

function isEcAlgorithm(algo: KeyAlgorithm | undefined): algo is 'ec-p256' | 'ec-p384' {
  return algo !== undefined && EC_ALGORITHMS.includes(algo);
}

export interface LeafCertificateOptions {
  sanDomains?: string[];
  validityDays?: number;
  /** Schlüsselgröße in Bit (z. B. 2048). Wird ignoriert wenn keyAlgorithm gesetzt. */
  keySize?: number;
  /** Schlüsselart (z. B. rsa-2048). Hat Vorrang vor keySize. */
  keyAlgorithm?: KeyAlgorithm;
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
  /** Optionale Subject-DN-Felder (O, OU, C, L, ST, E-Mail) */
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  locality?: string;
  stateOrProvince?: string;
  email?: string;
}

const KEY_ALGORITHM_TO_SIZE: Record<string, number> = {
  'rsa-2048': 2048,
  'rsa-3072': 3072,
  'rsa-4096': 4096,
};

function resolveKeySize(
  database: Database,
  options: LeafCertificateOptions
): number {
  if (options.keyAlgorithm && KEY_ALGORITHM_TO_SIZE[options.keyAlgorithm] !== undefined) {
    return KEY_ALGORITHM_TO_SIZE[options.keyAlgorithm];
  }
  return options.keySize ?? getConfigInt(database, CONFIG_KEY_DEFAULT_KEY_SIZE);
}

/** CA-Signer (Forge RSA) als WebCrypto CryptoKey für @peculiar. PKCS#8 über Forge, ohne Node-API. */
async function signerToCryptoKey(signer: { key: forge.pki.PrivateKey }): Promise<CryptoKey> {
  const rsaAsn1 = forge.pki.privateKeyToAsn1(signer.key);
  const pkcs8Asn1 = forge.pki.wrapRsaPrivateKey(rsaAsn1);
  const derBytes = forge.asn1.toDer(pkcs8Asn1).getBytes();
  const derBuffer = new Uint8Array(derBytes.length);
  for (let i = 0; i < derBytes.length; i++) derBuffer[i] = derBytes.charCodeAt(i);
  return await crypto.subtle.importKey(
    'pkcs8',
    derBuffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

/** CryptoKey (privater Schlüssel) als PEM exportieren. */
async function exportPrivateKeyToPem(key: CryptoKey): Promise<string> {
  const der = await crypto.subtle.exportKey('pkcs8', key);
  const b64 = Buffer.from(der).toString('base64');
  const lines: string[] = ['-----BEGIN PRIVATE KEY-----'];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  lines.push('-----END PRIVATE KEY-----');
  return lines.join('\n') + '\n';
}

/** Hash-Algorithmus-String in WebCrypto-Name. */
function hashAlgoToSubtle(hash: string): 'SHA-256' | 'SHA-384' | 'SHA-512' {
  if (hash === 'sha384') return 'SHA-384';
  if (hash === 'sha512') return 'SHA-512';
  return 'SHA-256';
}

/** Baut die finale OID aus Basis (PEN) und Sub-ID. */
function buildPolicyOid(base: string, sub: string): string {
  const b = (base ?? '').trim();
  const s = (sub ?? '').trim();
  if (!b) return '';
  const subNorm = s.startsWith('.') ? s : s ? '.' + s : '';
  return (b + subNorm).replace(/\.+/g, '.').replace(/\.$/, '');
}

const EC_CURVES: Record<string, string> = {
  'ec-p256': 'P-256',
  'ec-p384': 'P-384',
};

/** ECDSA-Leaf-Zertifikat mit @peculiar/x509 erstellen (CA bleibt RSA). */
async function createLeafCertificateEc(
  database: Database,
  paths: PathHelpers,
  issuerId: string,
  domain: string,
  options: LeafCertificateOptions
): Promise<number> {
  const signer = getSignerCa(database, paths, issuerId);
  const validityDays = options.validityDays ?? getConfigInt(database, CONFIG_KEY_DEFAULT_VALIDITY_DAYS);
  const hashAlgorithm =
    options.hashAlgorithm ?? getConfigValue(database, CONFIG_KEY_DEFAULT_HASH_ALGORITHM) ?? 'sha256';
  const keyAlgo = options.keyAlgorithm as 'ec-p256' | 'ec-p384';
  const namedCurve = EC_CURVES[keyAlgo] ?? 'P-256';

  const allDomains = [domain, ...(options.sanDomains ?? [])].filter(Boolean);
  const uniqueDomains = [...new Set(allDomains.map((d) => d.trim().toLowerCase()))].filter(Boolean);
  const primaryDomain = uniqueDomains[0] ?? domain;

  const leafKeys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve },
    true,
    ['sign', 'verify']
  );

  const caCryptoKey = await signerToCryptoKey(signer);
  const caCertPem = forge.pki.certificateToPem(signer.cert);
  const caCert = new X509Certificate(caCertPem);
  const issuerName = caCert.issuer;

  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setDate(notAfter.getDate() + validityDays);

  const extensions = [
    new BasicConstraintsExtension(false, undefined, true),
    new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
    new ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
    new SubjectAlternativeNameExtension(
      uniqueDomains.map((d) => ({ type: 'dns' as const, value: d })),
      false
    ),
  ];

  const isEv = options.ev === true;
  const escapeRdn = (s: string) => s.replace(/=/g, '\\=').replace(/,/g, '\\,');
  const subjectParts = [`CN=${escapeRdn(primaryDomain)}`];
  if (options.organization) subjectParts.push(`O=${escapeRdn(options.organization)}`);
  if (options.organizationalUnit) subjectParts.push(`OU=${escapeRdn(options.organizationalUnit)}`);
  if (options.country) subjectParts.push(`C=${escapeRdn(options.country)}`);
  if (options.locality) subjectParts.push(`L=${escapeRdn(options.locality)}`);
  if (options.stateOrProvince) subjectParts.push(`ST=${escapeRdn(options.stateOrProvince)}`);
  if (options.email) subjectParts.push(`emailAddress=${escapeRdn(options.email)}`);
  if (isEv) {
    if (options.businessCategory) subjectParts.push(`businessCategory=${escapeRdn(options.businessCategory)}`);
    if (options.jurisdictionCountryName) subjectParts.push(`jurisdictionOfIncorporationCountryName=${escapeRdn(options.jurisdictionCountryName)}`);
    if (options.serialNumber) subjectParts.push(`serialNumber=${escapeRdn(options.serialNumber)}`);
  }
  const subjectDn = subjectParts.join(', ');

  const cert = await X509CertificateGenerator.create(
    {
      serialNumber: String(Date.now()).slice(-8),
      subject: subjectDn,
      issuer: issuerName,
      notBefore,
      notAfter,
      publicKey: leafKeys.publicKey,
      signingKey: caCryptoKey,
      signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: hashAlgoToSubtle(hashAlgorithm) },
      extensions,
    },
    crypto
  );

  const certificatePem = cert.toString('pem');
  const notAfterStr = notAfter.toISOString();
  const policyOid = buildPolicyOid(options.policyOidBase ?? '', options.policyOidSub ?? '');

  database
    .prepare(
      'INSERT INTO certificates (domain, not_after, created_at, pem, issuer_id, is_ev, certificate_policy_oid) VALUES (?, ?, datetime("now"), ?, ?, ?, ?)'
    )
    .run(primaryDomain, notAfterStr, certificatePem, issuerId, isEv ? 1 : 0, policyOid || null);

  const lastRow = database.prepare('SELECT last_insert_rowid() as id').get() as { id: number };
  const certificateId = lastRow.id;
  const keyPem = await exportPrivateKeyToPem(leafKeys.privateKey);
  writeFileSync(paths.leafKeyPath(certificateId), keyPem);

  return certificateId;
}

export async function createLeafCertificate(
  database: Database,
  paths: PathHelpers,
  issuerId: string,
  domain: string,
  options: LeafCertificateOptions = {}
): Promise<number> {
  if (isEcAlgorithm(options.keyAlgorithm as KeyAlgorithm | undefined)) {
    return createLeafCertificateEc(database, paths, issuerId, domain, options);
  }

  const signer = getSignerCa(database, paths, issuerId);

  const keySize = resolveKeySize(database, options);
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
  if (options.organization) subjectAttrs.push({ name: 'organizationName', value: options.organization });
  if (options.organizationalUnit) subjectAttrs.push({ name: 'organizationalUnitName', value: options.organizationalUnit });
  if (options.country) subjectAttrs.push({ name: 'countryName', value: options.country });
  if (options.locality) subjectAttrs.push({ name: 'localityName', value: options.locality });
  if (options.stateOrProvince) subjectAttrs.push({ name: 'stateOrProvinceName', value: options.stateOrProvince });
  if (options.email) subjectAttrs.push({ name: 'emailAddress', value: options.email });
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
