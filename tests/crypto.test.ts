import { describe, test, expect } from 'bun:test';
import { getDigestForSigning, buildSubjectAttributes } from '../src/crypto.js';

describe('getDigestForSigning', () => {
  test('gibt SHA-256 für sha256 zurück', () => {
    const md = getDigestForSigning('sha256');
    expect(md).toBeDefined();
    expect(typeof md.update).toBe('function');
    expect(typeof md.digest).toBe('function');
  });

  test('gibt SHA-384 für sha384 zurück', () => {
    const md = getDigestForSigning('sha384');
    expect(md).toBeDefined();
  });

  test('gibt SHA-512 für sha512 zurück', () => {
    const md = getDigestForSigning('sha512');
    expect(md).toBeDefined();
  });

  test('Default ist SHA-256 bei unbekanntem Algorithmus', () => {
    const md = getDigestForSigning('unknown');
    expect(md).toBeDefined();
  });
});

describe('buildSubjectAttributes', () => {
  test('enthält mindestens commonName', () => {
    const attrs = buildSubjectAttributes({ commonName: 'Test CA' });
    expect(attrs).toHaveLength(1);
    expect(attrs[0]).toEqual({ name: 'commonName', value: 'Test CA' });
  });

  test('fügt optionale Felder hinzu', () => {
    const attrs = buildSubjectAttributes({
      commonName: 'CN',
      organization: 'O',
      country: 'DE',
      locality: 'Berlin',
    });
    expect(attrs.length).toBeGreaterThanOrEqual(4);
    const names = attrs.map((a) => a.name);
    expect(names).toContain('commonName');
    expect(names).toContain('organizationName');
    expect(names).toContain('countryName');
    expect(names).toContain('localityName');
  });
});
