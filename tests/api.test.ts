import { describe, test, expect } from 'bun:test';
import { handleRequest, database } from '../index';

function req(method: string, path: string, body?: object): Request {
  const url = new URL(path, 'http://localhost');
  return new Request(url.toString(), {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
}

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

describe('CA Setup', () => {
  test('POST /api/ca/setup erstellt Root-CA', async () => {
    const res = await handleRequest(
      req('POST', '/api/ca/setup', {
        name: 'Test CA',
        commonName: 'Test CA Root',
        validityYears: 2,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok: boolean; id: string };
    expect(data.ok).toBe(true);
    expect(typeof data.id).toBe('string');
    expect(data.id.length).toBeGreaterThan(0);
  });

  test('POST /api/ca/setup mit minimalen Angaben nutzt Fallback', async () => {
    const res = await handleRequest(
      req('POST', '/api/ca/setup', {
        commonName: 'Cert Manager CA',
        name: 'Minimal CA',
      })
    );
    expect(res.status).toBe(200);
    const data = (await res.json()) as { ok: boolean; id: string };
    expect(data.ok).toBe(true);
    expect(data.id).toBeDefined();
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
    const parentName = 'Parent for Int ' + Date.now();
    const setupRes = await handleRequest(
      req('POST', '/api/ca/setup', {
        name: parentName,
        commonName: parentName,
        validityYears: 5,
        keySize: 2048,
      })
    );
    expect(setupRes.status).toBe(200);
    const { id: parentId } = (await setupRes.json()) as { id: string };

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
    const name = 'Flow CA ' + Date.now();
    const setupRes = await handleRequest(
      req('POST', '/api/ca/setup', {
        name,
        commonName: name,
        validityYears: 1,
        keySize: 2048,
        hashAlgo: 'sha256',
      })
    );
    expect(setupRes.status).toBe(200);
    const setupData = (await setupRes.json()) as { ok: boolean; id: string };
    expect(setupData.ok).toBe(true);
    const caId = setupData.id;

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

describe('CA Activate Erfolg', () => {
  test('nach Aktivierung liefert GET /api/ca-cert ohne id die aktivierte CA', async () => {
    const name = 'Activate CA ' + Date.now();
    const setupRes = await handleRequest(
      req('POST', '/api/ca/setup', {
        name,
        commonName: name,
        validityYears: 1,
        keySize: 2048,
      })
    );
    expect(setupRes.status).toBe(200);
    const { id: caId } = (await setupRes.json()) as { id: string };

    const activateRes = await handleRequest(req('POST', '/api/ca/activate', { id: caId }));
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
    const parentName = 'Parent IntFlow ' + Date.now();
    const setupRes = await handleRequest(
      req('POST', '/api/ca/setup', {
        name: parentName,
        commonName: parentName,
        validityYears: 2,
        keySize: 2048,
      })
    );
    expect(setupRes.status).toBe(200);
    const { id: parentId } = (await setupRes.json()) as { id: string };

    const intRes = await handleRequest(
      req('POST', '/api/ca/intermediate', {
        parentCaId: parentId,
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
