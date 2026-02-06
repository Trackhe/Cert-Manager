import { afterAll, beforeAll, describe, test, expect } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRootCa, createIntermediateCa } from '../src/ca.js';

let handleRequest: (req: Request) => Promise<Response>;
let database: Parameters<typeof createRootCa>[0];
let paths: Parameters<typeof createRootCa>[1];
let testDir: string;
let sharedCaId: string | null = null;

function req(method: string, path: string, body?: object): Request {
  const url = new URL(path, 'http://localhost');
  return new Request(url.toString(), {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}

beforeAll(async () => {
  testDir = mkdtempSync(join(tmpdir(), 'cert-manager-test-'));
  process.env.DATA_DIR = testDir;
  process.env.DB_PATH = join(testDir, 'test.db');
  const index = await import('../index');
  handleRequest = index.handleRequest;
  database = index.database;
  paths = index.paths;
  createRootCa(database, paths, 'shared-test-ca', {
    name: 'Shared Test CA',
    commonName: 'Shared Test CA',
    validityYears: 10,
    keySize: 2048,
    hashAlgorithm: 'sha256',
  });
  sharedCaId = 'shared-test-ca';
});

afterAll(() => {
  try {
    rmSync(testDir, { recursive: true, force: true });
  } catch {
    // ignorieren
  }
});

describe('Dashboard', () => {
  test('GET / liefert HTML', async () => {
    const res = await handleRequest(req('GET', '/'));
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/html');
    const text = await res.text();
    expect(text).toContain('Dashboard');
    expect(text).toContain('Zertifikate');
  });
});

describe('CA Cert Download', () => {
  test('GET /api/ca-cert ohne id nutzt aktive CA', async () => {
    const res = await handleRequest(req('GET', '/api/ca-cert'));
    if (res.status === 404) return;
    expect(res.status).toBe(200);
    const pem = await res.text();
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
  });

  test('GET /api/ca-cert?id=unknown liefert 404', async () => {
    const res = await handleRequest(req('GET', '/api/ca-cert?id=unknown-ca-id-xyz'));
    expect(res.status).toBe(404);
  });
});

describe('Intermediate CA', () => {
  test('POST /api/ca/intermediate erstellt Intermediate und Download', async () => {
    expect(sharedCaId).not.toBeNull();
    const parentId = sharedCaId!;

    const intRes = await handleRequest(
      req('POST', '/api/ca/intermediate', {
        parentCaId: parentId,
        name: 'Test Intermediate',
        commonName: 'Test Intermediate CA',
        validityYears: 2,
        keySize: 2048,
      })
    );
    expect(intRes.status).toBe(200);
    const { id: intId } = (await intRes.json()) as { id: string };
    expect(intId.length).toBeGreaterThan(0);

    const certRes = await handleRequest(req('GET', '/api/ca-cert?id=' + intId));
    expect(certRes.status).toBe(200);
    const pem = await certRes.text();
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
  });

  test('POST /api/ca/intermediate ohne parentCaId liefert 400', async () => {
    const res = await handleRequest(
      req('POST', '/api/ca/intermediate', {
        name: 'Int CA',
        commonName: 'Intermediate',
      })
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain('parentCaId');
  });

  test('POST /api/ca/intermediate mit unbekannter Parent liefert 404', async () => {
    const res = await handleRequest(
      req('POST', '/api/ca/intermediate', {
        parentCaId: 'nonexistent-parent',
        name: 'Int CA',
        commonName: 'Intermediate',
      })
    );
    expect(res.status).toBe(404);
  });
});

describe('Full flow: CA -> Leaf Cert -> Download', () => {
  test('CA erstellen, Zertifikat ausstellen, Download', async () => {
    expect(sharedCaId).not.toBeNull();
    const caId = sharedCaId!;

    const createRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: caId,
        domain: 'test.example.com',
        sanDomains: ['www.test.example.com'],
        validityDays: 90,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(createRes.status).toBe(200);
    const createData = (await createRes.json()) as { ok: boolean; id: number };
    expect(createData.ok).toBe(true);
    const certId = createData.id;
    expect(typeof certId).toBe('number');

    const certRes = await handleRequest(req('GET', '/api/cert/download?id=' + certId));
    expect(certRes.status).toBe(200);
    const certPem = await certRes.text();
    expect(certPem).toContain('-----BEGIN CERTIFICATE-----');
    expect(certPem).toContain('-----END CERTIFICATE-----');

    const keyRes = await handleRequest(req('GET', '/api/cert/key?id=' + certId));
    expect(keyRes.status).toBe(200);
    const keyPem = await keyRes.text();
    expect(keyPem).toMatch(/-----BEGIN (RSA )?PRIVATE KEY-----/);
    expect(keyPem).toMatch(/-----END (RSA )?PRIVATE KEY-----/);
  });
});

describe('Leaf Cert Create', () => {
  test('POST /api/cert/create ohne issuerId liefert 400', async () => {
    const res = await handleRequest(
      req('POST', '/api/cert/create', {
        domain: 'example.com',
      })
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBeDefined();
  });

  test('POST /api/cert/create ohne domain liefert 400', async () => {
    const res = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: 'test-ca',
        domain: '',
      })
    );
    expect(res.status).toBe(400);
  });

  test('POST /api/cert/create mit unbekannter CA liefert 400', async () => {
    const res = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: 'unknown-ca-xyz',
        domain: 'example.com',
      })
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toContain('nicht gefunden');
  });
});

describe('Cert Download', () => {
  test('GET /api/cert/download ohne id liefert 400', async () => {
    const res = await handleRequest(req('GET', '/api/cert/download'));
    expect(res.status).toBe(400);
  });

  test('GET /api/cert/download?id=999999 liefert 404', async () => {
    const res = await handleRequest(req('GET', '/api/cert/download?id=999999'));
    expect(res.status).toBe(404);
  });

  test('GET /api/cert/key?id=999999 liefert 404', async () => {
    const res = await handleRequest(req('GET', '/api/cert/key?id=999999'));
    expect(res.status).toBe(404);
  });
});

describe('Cert Delete', () => {
  test('DELETE /api/cert ohne id liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/cert', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/cert?id=abc liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/cert?id=abc', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/cert?id=999999 liefert 404', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/cert?id=999999', { method: 'DELETE' })
    );
    expect(res.status).toBe(404);
  });

  test('DELETE /api/cert löscht Leaf-Zertifikat', async () => {
    expect(sharedCaId).not.toBeNull();
    const createRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: sharedCaId!,
        domain: 'delete-test.example.com',
        validityDays: 365,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(createRes.status).toBe(200);
    const createData = (await createRes.json()) as { id: number };
    const certId = createData.id;
    const delRes = await handleRequest(
      new Request('http://localhost/api/cert?id=' + certId, { method: 'DELETE' })
    );
    expect(delRes.status).toBe(200);
    const delData = (await delRes.json()) as { ok: boolean };
    expect(delData.ok).toBe(true);
    const downloadAfter = await handleRequest(
      req('GET', '/api/cert/download?id=' + certId)
    );
    expect(downloadAfter.status).toBe(404);
  });
});

describe('CA Delete', () => {
  test('DELETE /api/ca ohne id liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/ca', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/ca?id=unknown liefert 404', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/ca?id=unknown-ca-xyz', { method: 'DELETE' })
    );
    expect(res.status).toBe(404);
  });

  test('DELETE /api/ca löscht Root-CA inkl. Intermediate und Zertifikate', async () => {
    const rootId = 'ca-delete-root';
    const intId = 'int-for-delete';
    createRootCa(database, paths, rootId, {
      name: 'CA Delete Root',
      commonName: 'CA Delete Root',
      validityYears: 2,
      keySize: 2048,
      hashAlgorithm: 'sha256',
    });
    createIntermediateCa(database, paths, rootId, intId, {
      name: 'Int for delete',
      commonName: 'Int for delete',
      validityYears: 5,
      keySize: 2048,
      hashAlgorithm: 'sha256',
    });
    const certRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: intId,
        domain: 'ca-delete-test.example.com',
        validityDays: 365,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(certRes.status).toBe(200);
    const delRes = await handleRequest(
      new Request('http://localhost/api/ca?id=' + rootId, { method: 'DELETE' })
    );
    expect(delRes.status).toBe(200);
    const delData = (await delRes.json()) as { ok: boolean };
    expect(delData.ok).toBe(true);
    const caCertAfter = await handleRequest(req('GET', '/api/ca-cert?id=' + rootId));
    expect(caCertAfter.status).toBe(404);
    const intCertAfter = await handleRequest(req('GET', '/api/ca-cert?id=' + intId));
    expect(intCertAfter.status).toBe(404);
  });
});

describe('CA Intermediate Delete', () => {
  test('DELETE /api/ca/intermediate ohne id liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/ca/intermediate', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/ca/intermediate?id=unknown liefert 404', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/ca/intermediate?id=unknown-int-xyz', { method: 'DELETE' })
    );
    expect(res.status).toBe(404);
  });

  test('DELETE /api/ca/intermediate löscht Intermediate-CA und zugehörige Zertifikate', async () => {
    const rootId = 'ca-int-delete-root';
    const intId = 'int-to-delete';
    createRootCa(database, paths, rootId, {
      name: 'CA Int Delete Root',
      commonName: 'CA Int Delete Root',
      validityYears: 2,
      keySize: 2048,
      hashAlgorithm: 'sha256',
    });
    createIntermediateCa(database, paths, rootId, intId, {
      name: 'Int to delete',
      commonName: 'Int to delete',
      validityYears: 5,
      keySize: 2048,
      hashAlgorithm: 'sha256',
    });
    const certRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: intId,
        domain: 'int-delete-test.example.com',
        validityDays: 365,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(certRes.status).toBe(200);
    const createData = (await certRes.json()) as { id: number };
    const delRes = await handleRequest(
      new Request('http://localhost/api/ca/intermediate?id=' + intId, { method: 'DELETE' })
    );
    expect(delRes.status).toBe(200);
    const delData = (await delRes.json()) as { ok: boolean };
    expect(delData.ok).toBe(true);
    const intCertAfter = await handleRequest(req('GET', '/api/ca-cert?id=' + intId));
    expect(intCertAfter.status).toBe(404);
    const leafAfter = await handleRequest(req('GET', '/api/cert/download?id=' + createData.id));
    expect(leafAfter.status).toBe(404);
  });
});

describe('CA Activate', () => {
  test('POST /api/ca/activate ohne id liefert 400', async () => {
    const res = await handleRequest(req('POST', '/api/ca/activate', {}));
    expect(res.status).toBe(400);
  });

  test('POST /api/ca/activate mit unbekannter id liefert 404', async () => {
    const res = await handleRequest(req('POST', '/api/ca/activate', { id: 'nonexistent-ca' }));
    expect(res.status).toBe(404);
  });
});

describe('SSE', () => {
  test('GET /api/events liefert EventStream', async () => {
    const res = await handleRequest(req('GET', '/api/events'));
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('text/event-stream');
  });
});

describe('404', () => {
  test('GET /unknown liefert 404', async () => {
    const res = await handleRequest(req('GET', '/unknown'));
    expect(res.status).toBe(404);
  });

  test('GET /api/unknown liefert 404', async () => {
    const res = await handleRequest(req('GET', '/api/unknown'));
    expect(res.status).toBe(404);
  });
});

describe('ACME (ohne JWS)', () => {
  test('GET /acme/directory liefert JSON mit newNonce, newAccount, newOrder', async () => {
    const res = await handleRequest(req('GET', '/acme/directory'));
    expect(res.status).toBe(200);
    const data = (await res.json()) as { newNonce: string; newAccount: string; newOrder: string };
    expect(data.newNonce).toContain('/acme/new-nonce');
    expect(data.newAccount).toContain('/acme/new-account');
    expect(data.newOrder).toContain('/acme/new-order');
  });

  test('HEAD /acme/new-nonce liefert 204 mit Replay-Nonce', async () => {
    const res = await handleRequest(req('HEAD', '/acme/new-nonce'));
    expect(res.status).toBe(204);
    const nonce = res.headers.get('Replay-Nonce');
    expect(nonce).toBeDefined();
    expect(typeof nonce).toBe('string');
    expect(nonce!.length).toBeGreaterThan(0);
  });
});

describe('ACME HTTP-01 Challenge', () => {
  test('GET /.well-known/acme-challenge/unknown liefert 404', async () => {
    const res = await handleRequest(req('GET', '/.well-known/acme-challenge/unknown-token-xyz'));
    expect(res.status).toBe(404);
  });

  test('GET /.well-known/acme-challenge/:token liefert key_authorization wenn Challenge existiert', async () => {
    const token = 'test-token-' + Date.now();
    const keyAuthorization = 'key-auth-value';
    database.prepare('INSERT INTO challenges (token, key_authorization, domain) VALUES (?, ?, ?)').run(token, keyAuthorization, 'example.com');

    const res = await handleRequest(req('GET', '/.well-known/acme-challenge/' + token));
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toContain('text/plain');
    expect(await res.text()).toBe(keyAuthorization);
  });
});

describe('Challenges Delete', () => {
  test('DELETE /api/challenges ohne id liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/challenges', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/challenges?id=abc liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/challenges?id=abc', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/challenges?id=999999 liefert 404', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/challenges?id=999999', { method: 'DELETE' })
    );
    expect(res.status).toBe(404);
  });

  test('DELETE /api/challenges löscht Challenge', async () => {
    const token = 'delete-challenge-' + Date.now();
    database.prepare('INSERT INTO challenges (token, key_authorization, domain) VALUES (?, ?, ?)').run(token, 'auth', 'example.com');
    const row = database.prepare('SELECT id FROM challenges WHERE token = ?').get(token) as { id: number };
    const id = row.id;
    const delRes = await handleRequest(
      new Request('http://localhost/api/challenges?id=' + id, { method: 'DELETE' })
    );
    expect(delRes.status).toBe(200);
    const getRes = await handleRequest(req('GET', '/.well-known/acme-challenge/' + token));
    expect(getRes.status).toBe(404);
  });
});

describe('ACME Whitelist', () => {
  test('POST /api/acme-whitelist fügt Domain hinzu', async () => {
    const domain = 'whitelist-test-' + Date.now() + '.example.com';
    const res = await handleRequest(req('POST', '/api/acme-whitelist', { domain }));
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok?: boolean };
    expect(data.ok).toBe(true);
    const row = database.prepare('SELECT id, domain FROM acme_whitelist_domains WHERE domain = ?').get(domain) as { id: number; domain: string } | undefined;
    expect(row).toBeDefined();
    expect(row!.domain).toBe(domain);
  });

  test('POST /api/acme-whitelist mit Wildcard-Domain', async () => {
    const domain = '*.wildcard-' + Date.now() + '.local';
    const res = await handleRequest(req('POST', '/api/acme-whitelist', { domain }));
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok?: boolean };
    expect(data.ok).toBe(true);
    const row = database.prepare('SELECT domain FROM acme_whitelist_domains WHERE domain = ?').get(domain) as { domain: string } | undefined;
    expect(row?.domain).toBe(domain);
  });

  test('POST /api/acme-whitelist gleiche Domain zweimal liefert 400', async () => {
    const domain = 'duplicate-whitelist-' + Date.now() + '.example.com';
    const first = await handleRequest(req('POST', '/api/acme-whitelist', { domain }));
    expect(first.status).toBe(200);
    const second = await handleRequest(req('POST', '/api/acme-whitelist', { domain }));
    expect(second.status).toBe(400);
    const data = (await second.json()) as { error: string };
    expect(data.error).toContain('bereits in der Whitelist');
  });

  test('POST /api/acme-whitelist ohne domain liefert 400', async () => {
    const res = await handleRequest(req('POST', '/api/acme-whitelist', {}));
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBeDefined();
  });

  test('POST /api/acme-whitelist mit leerem Body liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/acme-whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '',
      })
    );
    expect(res.status).toBe(400);
  });

  test('POST /api/acme-whitelist mit ungültigem JSON liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/acme-whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'not json',
      })
    );
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBeDefined();
  });

  test('DELETE /api/acme-whitelist ohne id liefert 400', async () => {
    const res = await handleRequest(new Request('http://localhost/api/acme-whitelist', { method: 'DELETE' }));
    expect(res.status).toBe(400);
  });

  test('DELETE /api/acme-whitelist?id=abc liefert 400', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/acme-whitelist?id=abc', { method: 'DELETE' })
    );
    expect(res.status).toBe(400);
  });

  test('DELETE /api/acme-whitelist?id=999999 liefert 404', async () => {
    const res = await handleRequest(
      new Request('http://localhost/api/acme-whitelist?id=999999', { method: 'DELETE' })
    );
    expect(res.status).toBe(404);
  });

  test('DELETE /api/acme-whitelist löscht Eintrag', async () => {
    const domain = 'delete-whitelist-' + Date.now() + '.example.com';
    database.prepare('INSERT INTO acme_whitelist_domains (domain) VALUES (?)').run(domain);
    const row = database.prepare('SELECT id FROM acme_whitelist_domains WHERE domain = ?').get(domain) as { id: number };
    const res = await handleRequest(
      new Request('http://localhost/api/acme-whitelist?id=' + row.id, { method: 'DELETE' })
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok?: boolean };
    expect(data.ok).toBe(true);
    const after = database.prepare('SELECT id FROM acme_whitelist_domains WHERE domain = ?').get(domain);
    expect(after == null).toBe(true);
  });

  test('Hinzufügen und Löschen Roundtrip', async () => {
    const domain = 'roundtrip-whitelist-' + Date.now() + '.local';
    const addRes = await handleRequest(req('POST', '/api/acme-whitelist', { domain }));
    expect(addRes.status).toBe(200);
    const row = database.prepare('SELECT id FROM acme_whitelist_domains WHERE domain = ?').get(domain) as { id: number };
    const delRes = await handleRequest(
      new Request('http://localhost/api/acme-whitelist?id=' + row.id, { method: 'DELETE' })
    );
    expect(delRes.status).toBe(200);
    const secondDel = await handleRequest(
      new Request('http://localhost/api/acme-whitelist?id=' + row.id, { method: 'DELETE' })
    );
    expect(secondDel.status).toBe(404);
  });
});

describe('CA Activate Erfolg', () => {
  test('nach Aktivierung liefert GET /api/ca-cert ohne id die aktivierte CA', async () => {
    expect(sharedCaId).not.toBeNull();
    const activateRes = await handleRequest(req('POST', '/api/ca/activate', { id: sharedCaId! }));
    expect(activateRes.status).toBe(200);

    const certRes = await handleRequest(req('GET', '/api/ca-cert'));
    expect(certRes.status).toBe(200);
    const pem = await certRes.text();
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
  });
});

describe('Leaf-Zertifikat von Intermediate-CA', () => {
  test('Zertifikat kann von Intermediate statt von Root ausgestellt werden', async () => {
    expect(sharedCaId).not.toBeNull();
    const intRes = await handleRequest(
      req('POST', '/api/ca/intermediate', {
        parentCaId: sharedCaId!,
        name: 'Int for Leaf',
        commonName: 'Int for Leaf CA',
        validityYears: 1,
        keySize: 2048,
      })
    );
    expect(intRes.status).toBe(200);
    const { id: intermediateId } = (await intRes.json()) as { id: string };

    const createRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: intermediateId,
        domain: 'leaf-from-int.example.com',
        validityDays: 30,
        keySize: 2048,
      })
    );
    expect(createRes.status).toBe(200);
    const createData = (await createRes.json()) as { ok: boolean; id: number };
    expect(createData.ok).toBe(true);

    const certRes = await handleRequest(req('GET', '/api/cert/download?id=' + createData.id));
    expect(certRes.status).toBe(200);
    const pem = await certRes.text();
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
  });
});

describe('Leaf-Zertifikat ECDSA', () => {
  test('Zertifikat mit ECDSA P-256 kann erstellt und heruntergeladen werden', async () => {
    expect(sharedCaId).not.toBeNull();
    const createRes = await handleRequest(
      req('POST', '/api/cert/create', {
        issuerId: sharedCaId!,
        domain: 'ec-leaf.example.com',
        validityDays: 90,
        keyAlgorithm: 'ec-p256',
        hashAlgo: 'sha256',
      })
    );
    expect(createRes.status).toBe(200);
    const createData = (await createRes.json()) as { ok: boolean; id: number };
    expect(createData.ok).toBe(true);
    expect(typeof createData.id).toBe('number');
    const certRes = await handleRequest(req('GET', '/api/cert/download?id=' + createData.id));
    expect(certRes.status).toBe(200);
    const pem = await certRes.text();
    expect(pem).toContain('-----BEGIN CERTIFICATE-----');
    expect(pem).toContain('-----END CERTIFICATE-----');
    const keyRes = await handleRequest(req('GET', '/api/cert/key?id=' + createData.id));
    expect(keyRes.status).toBe(200);
    const keyPem = await keyRes.text();
    expect(keyPem).toContain('-----BEGIN PRIVATE KEY-----');
  });
});

describe('Ungültige Parameter', () => {
  test('GET /api/cert/download?id=abc liefert 400', async () => {
    const res = await handleRequest(req('GET', '/api/cert/download?id=abc'));
    expect(res.status).toBe(400);
  });

  test('GET /api/cert/key?id=abc liefert 400', async () => {
    const res = await handleRequest(req('GET', '/api/cert/key?id=abc'));
    expect(res.status).toBe(400);
  });
});
