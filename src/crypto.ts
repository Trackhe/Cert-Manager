// @ts-expect-error no types
import * as forge from 'node-forge';

export type MessageDigest = ReturnType<typeof forge.md.sha256.create>;

export function getDigestForSigning(hashAlgorithm: string): MessageDigest {
  if (hashAlgorithm === 'sha512') return forge.md.sha512.create();
  if (hashAlgorithm === 'sha384') return forge.md.sha384.create();
  return forge.md.sha256.create();
}

export interface SubjectAttributesOptions {
  commonName: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  locality?: string;
  stateOrProvince?: string;
  email?: string;
}

export function buildSubjectAttributes(options: SubjectAttributesOptions): forge.pki.Attribute[] {
  const attributes: forge.pki.Attribute[] = [
    { name: 'commonName', value: options.commonName },
  ];
  if (options.organization) {
    attributes.push({ name: 'organizationName', value: options.organization });
  }
  if (options.organizationalUnit) {
    attributes.push({ name: 'organizationalUnitName', value: options.organizationalUnit });
  }
  if (options.country) {
    attributes.push({ name: 'countryName', value: options.country });
  }
  if (options.locality) {
    attributes.push({ name: 'localityName', value: options.locality });
  }
  if (options.stateOrProvince) {
    attributes.push({ name: 'stateOrProvinceName', value: options.stateOrProvince });
  }
  if (options.email) {
    attributes.push({ name: 'emailAddress', value: options.email });
  }
  return attributes;
}
